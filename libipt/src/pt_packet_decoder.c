/*
 * Copyright (c) 2014-2022, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "pt_packet_decoder.h"
#include "pt_packet.h"
#include "pt_sync.h"
#include "pt_config.h"
#include "pt_opcodes.h"

#include <string.h>
#include <stdlib.h>
#include <stddef.h>


int pt_pkt_decoder_init(struct pt_packet_decoder *decoder,
			const struct pt_config *config)
{
	int errcode;

	if (!decoder || !config)
		return -pte_invalid;

	memset(decoder, 0, sizeof(*decoder));

	errcode = pt_config_from_user(&decoder->config, config);
	if (errcode < 0)
		return errcode;

	return 0;
}

struct pt_packet_decoder *pt_pkt_alloc_decoder(const struct pt_config *config)
{
	struct pt_packet_decoder *decoder;
	int errcode;

	decoder = malloc(sizeof(*decoder));
	if (!decoder)
		return NULL;

	errcode = pt_pkt_decoder_init(decoder, config);
	if (errcode < 0) {
		free(decoder);
		return NULL;
	}

	return decoder;
}

void pt_pkt_decoder_fini(struct pt_packet_decoder *decoder)
{
	(void) decoder;

	/* Nothing to do. */
}

void pt_pkt_free_decoder(struct pt_packet_decoder *decoder)
{
	pt_pkt_decoder_fini(decoder);
	free(decoder);
}

int pt_pkt_sync_forward(struct pt_packet_decoder *decoder)
{
	const uint8_t *pos, *sync, *begin;
	ptrdiff_t space;
	int errcode;

	if (!decoder)
		return -pte_invalid;

	begin = decoder->config.begin;
	sync = decoder->sync;
	pos = decoder->pos;
	if (!pos)
		pos = begin;

	if (pos == sync)
		pos += ptps_psb;

	if (pos < begin)
		return -pte_internal;

	/* Start a bit earlier so we find PSB that have been partially consumed
	 * by a preceding packet.
	 */
	space = pos - begin;
	if (ptps_psb <= space)
		space = ptps_psb - 1;

	pos -= space;

	errcode = pt_sync_forward(&sync, pos, &decoder->config);
	if (errcode < 0)
		return errcode;

	decoder->sync = sync;
	decoder->pos = sync;

	return 0;
}

int pt_pkt_sync_backward(struct pt_packet_decoder *decoder)
{
	const uint8_t *pos, *sync;
	int errcode;

	if (!decoder)
		return -pte_invalid;

	pos = decoder->pos;
	if (!pos)
		pos = decoder->config.end;

	errcode = pt_sync_backward(&sync, pos, &decoder->config);
	if (errcode < 0)
		return errcode;

	decoder->sync = sync;
	decoder->pos = sync;

	return 0;
}

int pt_pkt_sync_set(struct pt_packet_decoder *decoder, uint64_t offset)
{
	const uint8_t *begin, *end, *pos;

	if (!decoder)
		return -pte_invalid;

	begin = decoder->config.begin;
	end = decoder->config.end;
	pos = begin + offset;

	if (end < pos || pos < begin)
		return -pte_eos;

	decoder->sync = pos;
	decoder->pos = pos;

	return 0;
}

int pt_pkt_get_offset(const struct pt_packet_decoder *decoder, uint64_t *offset)
{
	const uint8_t *begin, *pos;

	if (!decoder || !offset)
		return -pte_invalid;

	begin = decoder->config.begin;
	pos = decoder->pos;

	if (!pos)
		return -pte_nosync;

	*offset = (uint64_t) (int64_t) (pos - begin);
	return 0;
}

int pt_pkt_get_sync_offset(const struct pt_packet_decoder *decoder,
			   uint64_t *offset)
{
	const uint8_t *begin, *sync;

	if (!decoder || !offset)
		return -pte_invalid;

	begin = decoder->config.begin;
	sync = decoder->sync;

	if (!sync)
		return -pte_nosync;

	*offset = (uint64_t) (int64_t) (sync - begin);
	return 0;
}

const struct pt_config *
pt_pkt_get_config(const struct pt_packet_decoder *decoder)
{
	if (!decoder)
		return NULL;

	return &decoder->config;
}

static inline int pkt_to_user(struct pt_packet *upkt, size_t size,
			      const struct pt_packet *pkt)
{
	if (!upkt || !pkt)
		return -pte_internal;

	if (upkt == pkt)
		return 0;

	/* Zero out any unknown bytes. */
	if (sizeof(*pkt) < size) {
		memset(upkt + sizeof(*pkt), 0, size - sizeof(*pkt));

		size = sizeof(*pkt);
	}

	memcpy(upkt, pkt, size);

	return 0;
}

static int pt_pkt_decode_unknown(struct pt_packet_decoder *decoder,
				 struct pt_packet *packet)
{
	int size;

	if (!decoder)
		return -pte_internal;

	size = pt_pkt_read_unknown(packet, decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	return size;
}

static int pt_pkt_decode_pad(struct pt_packet_decoder *decoder,
			     struct pt_packet *packet)
{
	(void) decoder;

	if (!packet)
		return -pte_internal;

	packet->type = ppt_pad;
	packet->size = ptps_pad;

	return ptps_pad;
}

static int pt_pkt_decode_psb(struct pt_packet_decoder *decoder,
			     struct pt_packet *packet)
{
	int size;

	if (!decoder)
		return -pte_internal;

	size = pt_pkt_read_psb(decoder->pos, &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_psb;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_tip(struct pt_packet_decoder *decoder,
			     struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_ip(&packet->payload.ip, decoder->pos,
			      &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_tip;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_tnt_8(struct pt_packet_decoder *decoder,
			       struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_tnt_8(&packet->payload.tnt, decoder->pos,
				 &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_tnt_8;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_tnt_64(struct pt_packet_decoder *decoder,
				struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_tnt_64(&packet->payload.tnt, decoder->pos,
				  &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_tnt_64;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_tip_pge(struct pt_packet_decoder *decoder,
				 struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_ip(&packet->payload.ip, decoder->pos,
			      &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_tip_pge;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_tip_pgd(struct pt_packet_decoder *decoder,
				 struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_ip(&packet->payload.ip, decoder->pos,
			      &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_tip_pgd;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_fup(struct pt_packet_decoder *decoder,
			     struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_ip(&packet->payload.ip, decoder->pos,
			      &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_fup;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_pip(struct pt_packet_decoder *decoder,
			     struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_pip(&packet->payload.pip, decoder->pos,
			       &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_pip;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_ovf(struct pt_packet_decoder *decoder,
			     struct pt_packet *packet)
{
	(void) decoder;

	if (!packet)
		return -pte_internal;

	packet->type = ppt_ovf;
	packet->size = ptps_ovf;

	return ptps_ovf;
}

static int pt_pkt_decode_mode(struct pt_packet_decoder *decoder,
			      struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_mode(&packet->payload.mode, decoder->pos,
				&decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_mode;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_psbend(struct pt_packet_decoder *decoder,
				struct pt_packet *packet)
{
	(void) decoder;

	if (!packet)
		return -pte_internal;

	packet->type = ppt_psbend;
	packet->size = ptps_psbend;

	return ptps_psbend;
}

static int pt_pkt_decode_tsc(struct pt_packet_decoder *decoder,
			     struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_tsc(&packet->payload.tsc, decoder->pos,
			       &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_tsc;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_cbr(struct pt_packet_decoder *decoder,
			     struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_cbr(&packet->payload.cbr, decoder->pos,
			       &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_cbr;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_tma(struct pt_packet_decoder *decoder,
			     struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_tma(&packet->payload.tma, decoder->pos,
			       &decoder->config);
	if (size < 0) {
		/** SKZ84: Use of VMX TSC Scaling or TSC Offsetting Will Result
		 *         in Corrupted Intel PT Packets
		 *
		 * We cannot detect all kinds of corruption but we can detect
		 * reserved bits being set.
		 */
		if (decoder->config.errata.skz84
		    && (size == -pte_bad_packet)) {
			size = ptps_tma + 1;

			packet->type = ppt_invalid;
			packet->size = (uint8_t) size;
		}

		return size;
	}

	packet->type = ppt_tma;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_mtc(struct pt_packet_decoder *decoder,
			     struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_mtc(&packet->payload.mtc, decoder->pos,
			       &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_mtc;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_handle_skd007(struct pt_packet_decoder *decoder,
				struct pt_packet *packet)
{
	const uint8_t *pos;
	uint16_t payload;
	uint8_t size;

	if (!decoder || !packet)
		return -pte_internal;

	if (packet->type != ppt_cyc)
		return -pte_internal;

	/* It must be a 2-byte CYC. */
	size = packet->size;
	if (size != 2)
		return 0;

	payload = (uint16_t) packet->payload.cyc.value;

	/* The 2nd byte of the CYC payload must look like an ext opcode. */
	if ((payload & ~0x1f) != 0x20)
		return 0;

	/* Skip this CYC packet. */
	pos = decoder->pos + size;
	if (decoder->config.end <= pos)
		return 0;

	/* See if we got a second CYC that looks like an OVF ext opcode. */
	if (*pos != pt_ext_ovf)
		return 0;

	/* We shouldn't get back-to-back CYCs unless they are sent when the
	 * counter wraps around.  In this case, we'd expect a full payload.
	 *
	 * Since we got two non-full CYC packets, we assume the erratum hit.
	 * We ignore the CYC since we cannot provide its correct content,
	 * anyway, and report the OVF, instead.
	 */
	decoder->pos += 1;

	return pt_pkt_decode_ovf(decoder, packet);
}

static int pt_pkt_decode_cyc(struct pt_packet_decoder *decoder,
			     struct pt_packet *packet)
{
	int size, errcode;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_cyc(&packet->payload.cyc, decoder->pos,
			       &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_cyc;
	packet->size = (uint8_t) size;

	if (decoder->config.errata.skd007) {
		errcode = pt_pkt_handle_skd007(decoder, packet);
		if (errcode != 0)
			return errcode;
	}

	return size;
}

static int pt_pkt_decode_stop(struct pt_packet_decoder *decoder,
			      struct pt_packet *packet)
{
	(void) decoder;

	if (!packet)
		return -pte_internal;

	packet->type = ppt_stop;
	packet->size = ptps_stop;

	return ptps_stop;
}

static int pt_pkt_decode_vmcs(struct pt_packet_decoder *decoder,
			      struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_vmcs(&packet->payload.vmcs, decoder->pos,
			       &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_vmcs;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_mnt(struct pt_packet_decoder *decoder,
			     struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_mnt(&packet->payload.mnt, decoder->pos,
			       &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_mnt;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_exstop(struct pt_packet_decoder *decoder,
				struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_exstop(&packet->payload.exstop, decoder->pos,
				  &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_exstop;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_mwait(struct pt_packet_decoder *decoder,
			       struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_mwait(&packet->payload.mwait, decoder->pos,
				 &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_mwait;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_pwre(struct pt_packet_decoder *decoder,
			      struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_pwre(&packet->payload.pwre, decoder->pos,
				&decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_pwre;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_pwrx(struct pt_packet_decoder *decoder,
			      struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_pwrx(&packet->payload.pwrx, decoder->pos,
				&decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_pwrx;
	packet->size = (uint8_t) size;

	return size;
}

static int pt_pkt_decode_ptw(struct pt_packet_decoder *decoder,
			     struct pt_packet *packet)
{
	int size;

	if (!decoder || !packet)
		return -pte_internal;

	size = pt_pkt_read_ptw(&packet->payload.ptw, decoder->pos,
			       &decoder->config);
	if (size < 0)
		return size;

	packet->type = ppt_ptw;
	packet->size = (uint8_t) size;

	return size;
}

#define USE_DISPATCH

static int pt_pkt_decode(struct pt_packet_decoder *decoder,
			 struct pt_packet *packet)
{
#ifdef USE_DISPATCH
static void *pt_dispatch_level_1[256] = {
		&&handle_pt_opc_pad,			// 00000000
		&&handle_pt_opc_tip_pgd,	// 00000001
		&&handle_pt_opc_ext,			// 00000010
		&&handle_pt_opc_cyc,			// 00000011
		&&handle_pt_opc_tnt_8,		// 00000100
		&&handle_pt_opc_bad,			// 00000101
		&&handle_pt_opc_tnt_8,		// 00000110
		&&handle_pt_opc_cyc,			// 00000111
		&&handle_pt_opc_tnt_8,		// 00001000
		&&handle_pt_opc_bad,			// 00001001
		&&handle_pt_opc_tnt_8,		// 00001010
		&&handle_pt_opc_cyc,			// 00001011
		&&handle_pt_opc_tnt_8,		// 00001100
		&&handle_pt_opc_tip,			// 00001101
		&&handle_pt_opc_tnt_8,		// 00001110
		&&handle_pt_opc_cyc,			// 00001111
		&&handle_pt_opc_tnt_8,		// 00010000
		&&handle_pt_opc_tip_pge,	// 00010001
		&&handle_pt_opc_tnt_8,		// 00010010
		&&handle_pt_opc_cyc,			// 00010011
		&&handle_pt_opc_tnt_8,		// 00010100
		&&handle_pt_opc_bad,			// 00010101
		&&handle_pt_opc_tnt_8,		// 00010110
		&&handle_pt_opc_cyc,			// 00010111
		&&handle_pt_opc_tnt_8,		// 00011000
		&&handle_pt_opc_tsc,			// 00011001
		&&handle_pt_opc_tnt_8,		// 00011010
		&&handle_pt_opc_cyc,			// 00011011
		&&handle_pt_opc_tnt_8,		// 00011100
		&&handle_pt_opc_fup,			// 00011101
		&&handle_pt_opc_tnt_8,		// 00011110
		&&handle_pt_opc_cyc,			// 00011111
		&&handle_pt_opc_tnt_8,		// 00100000
		&&handle_pt_opc_tip_pgd,	// 00100001
		&&handle_pt_opc_tnt_8,		// 00100010
		&&handle_pt_opc_cyc,			// 00100011
		&&handle_pt_opc_tnt_8,		// 00100100
		&&handle_pt_opc_bad,			// 00100101
		&&handle_pt_opc_tnt_8,		// 00100110
		&&handle_pt_opc_cyc,			// 00100111
		&&handle_pt_opc_tnt_8,		// 00101000
		&&handle_pt_opc_bad,			// 00101001
		&&handle_pt_opc_tnt_8,		// 00101010
		&&handle_pt_opc_cyc,			// 00101011
		&&handle_pt_opc_tnt_8,		// 00101100
		&&handle_pt_opc_tip,			// 00101101
		&&handle_pt_opc_tnt_8,		// 00101110
		&&handle_pt_opc_cyc,			// 00101111
		&&handle_pt_opc_tnt_8,		// 00110000
		&&handle_pt_opc_tip_pge,	// 00110001
		&&handle_pt_opc_tnt_8,		// 00110010
		&&handle_pt_opc_cyc,			// 00110011
		&&handle_pt_opc_tnt_8,		// 00110100
		&&handle_pt_opc_bad,			// 00110101
		&&handle_pt_opc_tnt_8,		// 00110110
		&&handle_pt_opc_cyc,			// 00110111
		&&handle_pt_opc_tnt_8,		// 00111000
		&&handle_pt_opc_bad,			// 00111001
		&&handle_pt_opc_tnt_8,		// 00111010
		&&handle_pt_opc_cyc,			// 00111011
		&&handle_pt_opc_tnt_8,		// 00111100
		&&handle_pt_opc_fup,			// 00111101
		&&handle_pt_opc_tnt_8,		// 00111110
		&&handle_pt_opc_cyc,			// 00111111
		&&handle_pt_opc_tnt_8,		// 01000000
		&&handle_pt_opc_tip_pgd,	// 01000001
		&&handle_pt_opc_tnt_8,		// 01000010
		&&handle_pt_opc_cyc,			// 01000011
		&&handle_pt_opc_tnt_8,		// 01000100
		&&handle_pt_opc_bad,			// 01000101
		&&handle_pt_opc_tnt_8,		// 01000110
		&&handle_pt_opc_cyc,			// 01000111
		&&handle_pt_opc_tnt_8,		// 01001000
		&&handle_pt_opc_bad,			// 01001001
		&&handle_pt_opc_tnt_8,		// 01001010
		&&handle_pt_opc_cyc,			// 01001011
		&&handle_pt_opc_tnt_8,		// 01001100
		&&handle_pt_opc_tip,			// 01001101
		&&handle_pt_opc_tnt_8,		// 01001110
		&&handle_pt_opc_cyc,			// 01001111
		&&handle_pt_opc_tnt_8,		// 01010000
		&&handle_pt_opc_tip_pge,	// 01010001
		&&handle_pt_opc_tnt_8,		// 01010010
		&&handle_pt_opc_cyc,			// 01010011
		&&handle_pt_opc_tnt_8,		// 01010100
		&&handle_pt_opc_bad,			// 01010101
		&&handle_pt_opc_tnt_8,		// 01010110
		&&handle_pt_opc_cyc,			// 01010111
		&&handle_pt_opc_tnt_8,		// 01011000
		&&handle_pt_opc_mtc,			// 01011001
		&&handle_pt_opc_tnt_8,		// 01011010
		&&handle_pt_opc_cyc,			// 01011011
		&&handle_pt_opc_tnt_8,		// 01011100
		&&handle_pt_opc_fup,			// 01011101
		&&handle_pt_opc_tnt_8,		// 01011110
		&&handle_pt_opc_cyc,			// 01011111
		&&handle_pt_opc_tnt_8,		// 01100000
		&&handle_pt_opc_tip_pgd,	// 01100001
		&&handle_pt_opc_tnt_8,		// 01100010
		&&handle_pt_opc_cyc,			// 01100011
		&&handle_pt_opc_tnt_8,		// 01100100
		&&handle_pt_opc_bad,			// 01100101
		&&handle_pt_opc_tnt_8,		// 01100110
		&&handle_pt_opc_cyc,			// 01100111
		&&handle_pt_opc_tnt_8,		// 01101000
		&&handle_pt_opc_bad,			// 01101001
		&&handle_pt_opc_tnt_8,		// 01101010
		&&handle_pt_opc_cyc,			// 01101011
		&&handle_pt_opc_tnt_8,		// 01101100
		&&handle_pt_opc_tip,			// 01101101
		&&handle_pt_opc_tnt_8,		// 01101110
		&&handle_pt_opc_cyc,			// 01101111
		&&handle_pt_opc_tnt_8,		// 01110000
		&&handle_pt_opc_tip_pge,	// 01110001
		&&handle_pt_opc_tnt_8,		// 01110010
		&&handle_pt_opc_cyc,			// 01110011
		&&handle_pt_opc_tnt_8,		// 01110100
		&&handle_pt_opc_bad,			// 01110101
		&&handle_pt_opc_tnt_8,		// 01110110
		&&handle_pt_opc_cyc,			// 01110111
		&&handle_pt_opc_tnt_8,		// 01111000
		&&handle_pt_opc_bad,			// 01111001
		&&handle_pt_opc_tnt_8,		// 01111010
		&&handle_pt_opc_cyc,			// 01111011
		&&handle_pt_opc_tnt_8,		// 01111100
		&&handle_pt_opc_fup,			// 01111101
		&&handle_pt_opc_tnt_8,		// 01111110
		&&handle_pt_opc_cyc,			// 01111111
		&&handle_pt_opc_tnt_8,		// 10000000
		&&handle_pt_opc_tip_pgd,	// 10000001
		&&handle_pt_opc_tnt_8,		// 10000010
		&&handle_pt_opc_cyc,			// 10000011
		&&handle_pt_opc_tnt_8,		// 10000100
		&&handle_pt_opc_bad,			// 10000101
		&&handle_pt_opc_tnt_8,		// 10000110
		&&handle_pt_opc_cyc,			// 10000111
		&&handle_pt_opc_tnt_8,		// 10001000
		&&handle_pt_opc_bad,			// 10001001
		&&handle_pt_opc_tnt_8,		// 10001010
		&&handle_pt_opc_cyc,			// 10001011
		&&handle_pt_opc_tnt_8,		// 10001100
		&&handle_pt_opc_tip,			// 10001101
		&&handle_pt_opc_tnt_8,		// 10001110
		&&handle_pt_opc_cyc,			// 10001111
		&&handle_pt_opc_tnt_8,		// 10010000
		&&handle_pt_opc_tip_pge,	// 10010001
		&&handle_pt_opc_tnt_8,		// 10010010
		&&handle_pt_opc_cyc,			// 10010011
		&&handle_pt_opc_tnt_8,		// 10010100
		&&handle_pt_opc_bad,			// 10010101
		&&handle_pt_opc_tnt_8,		// 10010110
		&&handle_pt_opc_cyc,			// 10010111
		&&handle_pt_opc_tnt_8,		// 10011000
		&&handle_pt_opc_mode,		// 10011001
		&&handle_pt_opc_tnt_8,		// 10011010
		&&handle_pt_opc_cyc,			// 10011011
		&&handle_pt_opc_tnt_8,		// 10011100
		&&handle_pt_opc_fup,			// 10011101
		&&handle_pt_opc_tnt_8,		// 10011110
		&&handle_pt_opc_cyc,			// 10011111
		&&handle_pt_opc_tnt_8,		// 10100000
		&&handle_pt_opc_tip_pgd,	// 10100001
		&&handle_pt_opc_tnt_8,		// 10100010
		&&handle_pt_opc_cyc,			// 10100011
		&&handle_pt_opc_tnt_8,		// 10100100
		&&handle_pt_opc_bad,			// 10100101
		&&handle_pt_opc_tnt_8,		// 10100110
		&&handle_pt_opc_cyc,			// 10100111
		&&handle_pt_opc_tnt_8,		// 10101000
		&&handle_pt_opc_bad,			// 10101001
		&&handle_pt_opc_tnt_8,		// 10101010
		&&handle_pt_opc_cyc,			// 10101011
		&&handle_pt_opc_tnt_8,		// 10101100
		&&handle_pt_opc_tip,			// 10101101
		&&handle_pt_opc_tnt_8,		// 10101110
		&&handle_pt_opc_cyc,			// 10101111
		&&handle_pt_opc_tnt_8,		// 10110000
		&&handle_pt_opc_tip_pge,	// 10110001
		&&handle_pt_opc_tnt_8,		// 10110010
		&&handle_pt_opc_cyc,			// 10110011
		&&handle_pt_opc_tnt_8,		// 10110100
		&&handle_pt_opc_bad,			// 10110101
		&&handle_pt_opc_tnt_8,		// 10110110
		&&handle_pt_opc_cyc,			// 10110111
		&&handle_pt_opc_tnt_8,		// 10111000
		&&handle_pt_opc_bad,			// 10111001
		&&handle_pt_opc_tnt_8,		// 10111010
		&&handle_pt_opc_cyc,			// 10111011
		&&handle_pt_opc_tnt_8,		// 10111100
		&&handle_pt_opc_fup,			// 10111101
		&&handle_pt_opc_tnt_8,		// 10111110
		&&handle_pt_opc_cyc,			// 10111111
		&&handle_pt_opc_tnt_8,		// 11000000
		&&handle_pt_opc_tip_pgd,	// 11000001
		&&handle_pt_opc_tnt_8,		// 11000010
		&&handle_pt_opc_cyc,			// 11000011
		&&handle_pt_opc_tnt_8,		// 11000100
		&&handle_pt_opc_bad,			// 11000101
		&&handle_pt_opc_tnt_8,		// 11000110
		&&handle_pt_opc_cyc,			// 11000111
		&&handle_pt_opc_tnt_8,		// 11001000
		&&handle_pt_opc_bad,			// 11001001
		&&handle_pt_opc_tnt_8,		// 11001010
		&&handle_pt_opc_cyc,			// 11001011
		&&handle_pt_opc_tnt_8,		// 11001100
		&&handle_pt_opc_tip,			// 11001101
		&&handle_pt_opc_tnt_8,		// 11001110
		&&handle_pt_opc_cyc,			// 11001111
		&&handle_pt_opc_tnt_8,		// 11010000
		&&handle_pt_opc_tip_pge,	// 11010001
		&&handle_pt_opc_tnt_8,		// 11010010
		&&handle_pt_opc_cyc,			// 11010011
		&&handle_pt_opc_tnt_8,		// 11010100
		&&handle_pt_opc_bad,			// 11010101
		&&handle_pt_opc_tnt_8,		// 11010110
		&&handle_pt_opc_cyc,			// 11010111
		&&handle_pt_opc_tnt_8,		// 11011000
		&&handle_pt_opc_bad,			// 11011001
		&&handle_pt_opc_tnt_8,		// 11011010
		&&handle_pt_opc_cyc,			// 11011011
		&&handle_pt_opc_tnt_8,		// 11011100
		&&handle_pt_opc_fup,			// 11011101
		&&handle_pt_opc_tnt_8,		// 11011110
		&&handle_pt_opc_cyc,			// 11011111
		&&handle_pt_opc_tnt_8,		// 11100000
		&&handle_pt_opc_tip_pgd,	// 11100001
		&&handle_pt_opc_tnt_8,		// 11100010
		&&handle_pt_opc_cyc,			// 11100011
		&&handle_pt_opc_tnt_8,		// 11100100
		&&handle_pt_opc_bad,			// 11100101
		&&handle_pt_opc_tnt_8,		// 11100110
		&&handle_pt_opc_cyc,			// 11100111
		&&handle_pt_opc_tnt_8,		// 11101000
		&&handle_pt_opc_bad,			// 11101001
		&&handle_pt_opc_tnt_8,		// 11101010
		&&handle_pt_opc_cyc,			// 11101011
		&&handle_pt_opc_tnt_8,		// 11101100
		&&handle_pt_opc_tip,			// 11101101
		&&handle_pt_opc_tnt_8,		// 11101110
		&&handle_pt_opc_cyc,			// 11101111
		&&handle_pt_opc_tnt_8,		// 11110000
		&&handle_pt_opc_tip_pge,	// 11110001
		&&handle_pt_opc_tnt_8,		// 11110010
		&&handle_pt_opc_cyc,			// 11110011
		&&handle_pt_opc_tnt_8,		// 11110100
		&&handle_pt_opc_bad,			// 11110101
		&&handle_pt_opc_tnt_8,		// 11110110
		&&handle_pt_opc_cyc,			// 11110111
		&&handle_pt_opc_tnt_8,		// 11111000
		&&handle_pt_opc_bad,			// 11111001
		&&handle_pt_opc_tnt_8,		// 11111010
		&&handle_pt_opc_cyc,			// 11111011
		&&handle_pt_opc_tnt_8,		// 11111100
		&&handle_pt_opc_fup,			// 11111101
		&&handle_pt_opc_tnt_8,		// 11111110
		&&handle_pt_opc_cyc,			// 11111111
};

static void *pt_dispatch_level_2[256] = {
		&&handle_pt_ext_bad,			// 00000000
		&&handle_pt_ext_bad,	// 00000001
		&&handle_pt_ext_bad,			// 00000010
		&&handle_pt_ext_cbr,			// 00000011
		&&handle_pt_ext_bad,		// 00000100
		&&handle_pt_ext_bad,		// 00000101
		&&handle_pt_ext_bad,		// 00000110
		&&handle_pt_ext_bad,			// 00000111
		&&handle_pt_ext_bad,		// 00001000
		&&handle_pt_ext_bad,		// 00001001
		&&handle_pt_ext_bad,		// 00001010
		&&handle_pt_ext_bad,			// 00001011
		&&handle_pt_ext_bad,		// 00001100
		&&handle_pt_ext_bad,			// 00001101
		&&handle_pt_ext_bad,		// 00001110
		&&handle_pt_ext_bad,			// 00001111
		&&handle_pt_ext_bad,		// 00010000
		&&handle_pt_ext_bad,	// 00010001
		&&handle_pt_ext_ptw,		// 00010010
		&&handle_pt_ext_bad,			// 00010011
		&&handle_pt_ext_bad,		// 00010100
		&&handle_pt_ext_bad,		// 00010101
		&&handle_pt_ext_bad,		// 00010110
		&&handle_pt_ext_bad,			// 00010111
		&&handle_pt_ext_bad,		// 00011000
		&&handle_pt_ext_bad,			// 00011001
		&&handle_pt_ext_bad,		// 00011010
		&&handle_pt_ext_bad,			// 00011011
		&&handle_pt_ext_bad,		// 00011100
		&&handle_pt_ext_bad,	// 00011101
		&&handle_pt_ext_bad,		// 00011110
		&&handle_pt_ext_bad,			// 00011111
		&&handle_pt_ext_bad,		// 00100000
		&&handle_pt_ext_bad,	// 00100001
		&&handle_pt_ext_pwre,		// 00100010
		&&handle_pt_ext_psbend,			// 00100011
		&&handle_pt_ext_bad,		// 00100100
		&&handle_pt_ext_bad,		// 00100101
		&&handle_pt_ext_bad,		// 00100110
		&&handle_pt_ext_bad,			// 00100111
		&&handle_pt_ext_bad,		// 00101000
		&&handle_pt_ext_bad,		// 00101001
		&&handle_pt_ext_bad,		// 00101010
		&&handle_pt_ext_bad,			// 00101011
		&&handle_pt_ext_bad,		// 00101100
		&&handle_pt_ext_bad,			// 00101101
		&&handle_pt_ext_bad,		// 00101110
		&&handle_pt_ext_bad,			// 00101111
		&&handle_pt_ext_bad,		// 00110000
		&&handle_pt_ext_bad,	// 00110001
		&&handle_pt_ext_ptw,		// 00110010
		&&handle_pt_ext_bad,			// 00110011
		&&handle_pt_ext_bad,		// 00110100
		&&handle_pt_ext_bad,		// 00110101
		&&handle_pt_ext_bad,		// 00110110
		&&handle_pt_ext_bad,			// 00110111
		&&handle_pt_ext_bad,		// 00111000
		&&handle_pt_ext_bad,		// 00111001
		&&handle_pt_ext_bad,		// 00111010
		&&handle_pt_ext_bad,			// 00111011
		&&handle_pt_ext_bad,		// 00111100
		&&handle_pt_ext_bad,	// 00111101
		&&handle_pt_ext_bad,		// 00111110
		&&handle_pt_ext_bad,			// 00111111
		&&handle_pt_ext_bad,		// 01000000
		&&handle_pt_ext_bad,	// 01000001
		&&handle_pt_ext_bad,		// 01000010
		&&handle_pt_ext_pip,			// 01000011
		&&handle_pt_ext_bad,		// 01000100
		&&handle_pt_ext_bad,		// 01000101
		&&handle_pt_ext_bad,		// 01000110
		&&handle_pt_ext_bad,			// 01000111
		&&handle_pt_ext_bad,		// 01001000
		&&handle_pt_ext_bad,		// 01001001
		&&handle_pt_ext_bad,		// 01001010
		&&handle_pt_ext_bad,			// 01001011
		&&handle_pt_ext_bad,		// 01001100
		&&handle_pt_ext_bad,			// 01001101
		&&handle_pt_ext_bad,		// 01001110
		&&handle_pt_ext_bad,			// 01001111
		&&handle_pt_ext_bad,		// 01010000
		&&handle_pt_ext_bad,	// 01010001
		&&handle_pt_ext_ptw,		// 01010010
		&&handle_pt_ext_bad,			// 01010011
		&&handle_pt_ext_bad,		// 01010100
		&&handle_pt_ext_bad,		// 01010101
		&&handle_pt_ext_bad,		// 01010110
		&&handle_pt_ext_bad,			// 01010111
		&&handle_pt_ext_bad,		// 01011000
		&&handle_pt_ext_bad,			// 01011001
		&&handle_pt_ext_bad,		// 01011010
		&&handle_pt_ext_bad,			// 01011011
		&&handle_pt_ext_bad,		// 01011100
		&&handle_pt_ext_bad,	// 01011101
		&&handle_pt_ext_bad,		// 01011110
		&&handle_pt_ext_bad,			// 01011111
		&&handle_pt_ext_bad,		// 01100000
		&&handle_pt_ext_bad,	// 01100001
		&&handle_pt_ext_exstop,		// 01100010
		&&handle_pt_ext_bad,			// 01100011
		&&handle_pt_ext_bad,		// 01100100
		&&handle_pt_ext_bad,		// 01100101
		&&handle_pt_ext_bad,		// 01100110
		&&handle_pt_ext_bad,			// 01100111
		&&handle_pt_ext_bad,		// 01101000
		&&handle_pt_ext_bad,		// 01101001
		&&handle_pt_ext_bad,		// 01101010
		&&handle_pt_ext_bad,			// 01101011
		&&handle_pt_ext_bad,		// 01101100
		&&handle_pt_ext_bad,			// 01101101
		&&handle_pt_ext_bad,		// 01101110
		&&handle_pt_ext_bad,			// 01101111
		&&handle_pt_ext_bad,		// 01110000
		&&handle_pt_ext_bad,	// 01110001
		&&handle_pt_ext_ptw,		// 01110010
		&&handle_pt_ext_tma,			// 01110011
		&&handle_pt_ext_bad,		// 01110100
		&&handle_pt_ext_bad,		// 01110101
		&&handle_pt_ext_bad,		// 01110110
		&&handle_pt_ext_bad,			// 01110111
		&&handle_pt_ext_bad,		// 01111000
		&&handle_pt_ext_bad,		// 01111001
		&&handle_pt_ext_bad,		// 01111010
		&&handle_pt_ext_bad,			// 01111011
		&&handle_pt_ext_bad,		// 01111100
		&&handle_pt_ext_bad,	// 01111101
		&&handle_pt_ext_bad,		// 01111110
		&&handle_pt_ext_bad,			// 01111111
		&&handle_pt_ext_bad,		// 10000000
		&&handle_pt_ext_bad,	// 10000001
		&&handle_pt_ext_psb,		// 10000010
		&&handle_pt_ext_stop,			// 10000011
		&&handle_pt_ext_bad,		// 10000100
		&&handle_pt_ext_bad,		// 10000101
		&&handle_pt_ext_bad,		// 10000110
		&&handle_pt_ext_bad,			// 10000111
		&&handle_pt_ext_bad,		// 10001000
		&&handle_pt_ext_bad,		// 10001001
		&&handle_pt_ext_bad,		// 10001010
		&&handle_pt_ext_bad,			// 10001011
		&&handle_pt_ext_bad,		// 10001100
		&&handle_pt_ext_bad,			// 10001101
		&&handle_pt_ext_bad,		// 10001110
		&&handle_pt_ext_bad,			// 10001111
		&&handle_pt_ext_bad,		// 10010000
		&&handle_pt_ext_bad,	// 10010001
		&&handle_pt_ext_ptw,		// 10010010
		&&handle_pt_ext_bad,			// 10010011
		&&handle_pt_ext_bad,		// 10010100
		&&handle_pt_ext_bad,		// 10010101
		&&handle_pt_ext_bad,		// 10010110
		&&handle_pt_ext_bad,			// 10010111
		&&handle_pt_ext_bad,		// 10011000
		&&handle_pt_ext_bad,		// 10011001
		&&handle_pt_ext_bad,		// 10011010
		&&handle_pt_ext_bad,			// 10011011
		&&handle_pt_ext_bad,		// 10011100
		&&handle_pt_ext_bad,	// 10011101
		&&handle_pt_ext_bad,		// 10011110
		&&handle_pt_ext_bad,			// 10011111
		&&handle_pt_ext_bad,		// 10100000
		&&handle_pt_ext_bad,	// 10100001
		&&handle_pt_ext_pwrx,		// 10100010
		&&handle_pt_ext_tnt_64,			// 10100011
		&&handle_pt_ext_bad,		// 10100100
		&&handle_pt_ext_bad,		// 10100101
		&&handle_pt_ext_bad,		// 10100110
		&&handle_pt_ext_bad,			// 10100111
		&&handle_pt_ext_bad,		// 10101000
		&&handle_pt_ext_bad,		// 10101001
		&&handle_pt_ext_bad,		// 10101010
		&&handle_pt_ext_bad,			// 10101011
		&&handle_pt_ext_bad,		// 10101100
		&&handle_pt_ext_bad,			// 10101101
		&&handle_pt_ext_bad,		// 10101110
		&&handle_pt_ext_bad,			// 10101111
		&&handle_pt_ext_bad,		// 10110000
		&&handle_pt_ext_bad,	// 10110001
		&&handle_pt_ext_ptw,		// 10110010
		&&handle_pt_ext_bad,			// 10110011
		&&handle_pt_ext_bad,		// 10110100
		&&handle_pt_ext_bad,		// 10110101
		&&handle_pt_ext_bad,		// 10110110
		&&handle_pt_ext_bad,			// 10110111
		&&handle_pt_ext_bad,		// 10111000
		&&handle_pt_ext_bad,		// 10111001
		&&handle_pt_ext_bad,		// 10111010
		&&handle_pt_ext_bad,			// 10111011
		&&handle_pt_ext_bad,		// 10111100
		&&handle_pt_ext_bad,	// 10111101
		&&handle_pt_ext_bad,		// 10111110
		&&handle_pt_ext_bad,			// 10111111
		&&handle_pt_ext_bad,		// 11000000
		&&handle_pt_ext_bad,	// 11000001
		&&handle_pt_ext_mwait,		// 11000010
		&&handle_pt_ext_ext2,			// 11000011
		&&handle_pt_ext_bad,		// 11000100
		&&handle_pt_ext_bad,		// 11000101
		&&handle_pt_ext_bad,		// 11000110
		&&handle_pt_ext_bad,			// 11000111
		&&handle_pt_ext_vmcs,		// 11001000
		&&handle_pt_ext_bad,		// 11001001
		&&handle_pt_ext_bad,		// 11001010
		&&handle_pt_ext_bad,			// 11001011
		&&handle_pt_ext_bad,		// 11001100
		&&handle_pt_ext_bad,			// 11001101
		&&handle_pt_ext_bad,		// 11001110
		&&handle_pt_ext_bad,			// 11001111
		&&handle_pt_ext_bad,		// 11010000
		&&handle_pt_ext_bad,	// 11010001
		&&handle_pt_ext_ptw,		// 11010010
		&&handle_pt_ext_bad,			// 11010011
		&&handle_pt_ext_bad,		// 11010100
		&&handle_pt_ext_bad,		// 11010101
		&&handle_pt_ext_bad,		// 11010110
		&&handle_pt_ext_bad,			// 11010111
		&&handle_pt_ext_bad,		// 11011000
		&&handle_pt_ext_bad,		// 11011001
		&&handle_pt_ext_bad,		// 11011010
		&&handle_pt_ext_bad,			// 11011011
		&&handle_pt_ext_bad,		// 11011100
		&&handle_pt_ext_bad,	// 11011101
		&&handle_pt_ext_bad,		// 11011110
		&&handle_pt_ext_bad,			// 11011111
		&&handle_pt_ext_bad,		// 11100000
		&&handle_pt_ext_bad,	// 11100001
		&&handle_pt_ext_exstop_ip,		// 11100010
		&&handle_pt_ext_bad,			// 11100011
		&&handle_pt_ext_bad,		// 11100100
		&&handle_pt_ext_bad,		// 11100101
		&&handle_pt_ext_bad,		// 11100110
		&&handle_pt_ext_bad,			// 11100111
		&&handle_pt_ext_bad,		// 11101000
		&&handle_pt_ext_bad,		// 11101001
		&&handle_pt_ext_bad,		// 11101010
		&&handle_pt_ext_bad,			// 11101011
		&&handle_pt_ext_bad,		// 11101100
		&&handle_pt_ext_bad,			// 11101101
		&&handle_pt_ext_bad,		// 11101110
		&&handle_pt_ext_bad,			// 11101111
		&&handle_pt_ext_bad,		// 11110000
		&&handle_pt_ext_bad,	// 11110001
		&&handle_pt_ext_ptw,		// 11110010
		&&handle_pt_ext_ovf,			// 11110011
		&&handle_pt_ext_bad,		// 11110100
		&&handle_pt_ext_bad,		// 11110101
		&&handle_pt_ext_bad,		// 11110110
		&&handle_pt_ext_bad,			// 11110111
		&&handle_pt_ext_bad,		// 11111000
		&&handle_pt_ext_bad,		// 11111001
		&&handle_pt_ext_bad,		// 11111010
		&&handle_pt_ext_bad,			// 11111011
		&&handle_pt_ext_bad,		// 11111100
		&&handle_pt_ext_bad,	// 11111101
		&&handle_pt_ext_bad,		// 11111110
		&&handle_pt_ext_bad,		// 11111111
};
#endif

	const struct pt_config *config;
	const uint8_t *pos, *begin, *end;
	uint8_t opc, ext, ext2;

	config = pt_pkt_config(decoder);
	if (!config)
		return -pte_internal;

	begin = config->begin;
	pos = pt_pkt_pos(decoder);
	if (pos < begin)
		return -pte_nosync;

	end = config->end;
	if (end <= pos)
		return -pte_eos;

	opc = *pos++;

	//printf("level_1: %x\n", opc);
#ifdef USE_DISPATCH
	goto *pt_dispatch_level_1[opc];
#endif
	switch (opc) {
	default:
		/* Check opcodes that require masking. */
		if ((opc & pt_opm_cyc) == pt_opc_cyc)
			handle_pt_opc_cyc:
			return pt_pkt_decode_cyc(decoder, packet);

		if ((opc & pt_opm_tnt_8) == pt_opc_tnt_8)
			handle_pt_opc_tnt_8:
			return pt_pkt_decode_tnt_8(decoder, packet);

		if ((opc & pt_opm_fup) == pt_opc_fup)
			handle_pt_opc_fup:
			return pt_pkt_decode_fup(decoder, packet);

		if ((opc & pt_opm_tip) == pt_opc_tip)
			handle_pt_opc_tip:
			return pt_pkt_decode_tip(decoder, packet);

		if ((opc & pt_opm_tip) == pt_opc_tip_pge)
			handle_pt_opc_tip_pge:
			return pt_pkt_decode_tip_pge(decoder, packet);

		if ((opc & pt_opm_tip) == pt_opc_tip_pgd)
			handle_pt_opc_tip_pgd:
			return pt_pkt_decode_tip_pgd(decoder, packet);

		handle_pt_opc_bad:
		return pt_pkt_decode_unknown(decoder, packet);

	case pt_opc_mode:
		handle_pt_opc_mode:
		return pt_pkt_decode_mode(decoder, packet);

	case pt_opc_mtc:
		handle_pt_opc_mtc:
		return pt_pkt_decode_mtc(decoder, packet);

	case pt_opc_tsc:
		handle_pt_opc_tsc:
		return pt_pkt_decode_tsc(decoder, packet);

	case pt_opc_pad:
		handle_pt_opc_pad:
		return pt_pkt_decode_pad(decoder, packet);

	case pt_opc_ext:
		handle_pt_opc_ext:
		if (end <= pos)
			return -pte_eos;

		ext = *pos++;

		//printf("level_2: %x\n", ext);
#ifdef USE_DISPATCH
		goto *pt_dispatch_level_2[ext];
#endif
		switch (ext) {
		default:
			/* Check opcodes that require masking. */
			if ((ext & pt_opm_ptw) == pt_ext_ptw)
				handle_pt_ext_ptw:
				return pt_pkt_decode_ptw(decoder, packet);

			handle_pt_ext_bad:
			return pt_pkt_decode_unknown(decoder, packet);

		case pt_ext_psb:
			handle_pt_ext_psb:
			return pt_pkt_decode_psb(decoder, packet);

		case pt_ext_ovf:
			handle_pt_ext_ovf:
			return pt_pkt_decode_ovf(decoder, packet);

		case pt_ext_psbend:
			handle_pt_ext_psbend:
			return pt_pkt_decode_psbend(decoder, packet);

		case pt_ext_cbr:
			handle_pt_ext_cbr:
			return pt_pkt_decode_cbr(decoder, packet);

		case pt_ext_tma:
			handle_pt_ext_tma:
			return pt_pkt_decode_tma(decoder, packet);

		case pt_ext_pip:
			handle_pt_ext_pip:
			return pt_pkt_decode_pip(decoder, packet);

		case pt_ext_vmcs:
			handle_pt_ext_vmcs:
			return pt_pkt_decode_vmcs(decoder, packet);

		case pt_ext_exstop:
			handle_pt_ext_exstop:
		case pt_ext_exstop_ip:
			handle_pt_ext_exstop_ip:
			return pt_pkt_decode_exstop(decoder, packet);

		case pt_ext_mwait:
			handle_pt_ext_mwait:
			return pt_pkt_decode_mwait(decoder, packet);

		case pt_ext_pwre:
			handle_pt_ext_pwre:
			return pt_pkt_decode_pwre(decoder, packet);

		case pt_ext_pwrx:
			handle_pt_ext_pwrx:
			return pt_pkt_decode_pwrx(decoder, packet);

		case pt_ext_stop:
			handle_pt_ext_stop:
			return pt_pkt_decode_stop(decoder, packet);

		case pt_ext_tnt_64:
			handle_pt_ext_tnt_64:
			return pt_pkt_decode_tnt_64(decoder, packet);

		case pt_ext_ext2:
			handle_pt_ext_ext2:
			if (end <= pos)
				return -pte_eos;

			ext2 = *pos++;
			switch (ext2) {
			default:
				return pt_pkt_decode_unknown(decoder, packet);

			case pt_ext2_mnt:
				return pt_pkt_decode_mnt(decoder, packet);
			}
		}
	}
}

int pt_pkt_next(struct pt_packet_decoder *decoder, struct pt_packet *packet,
		size_t psize)
{
	struct pt_packet pkt, *ppkt;
	int errcode, size;

	if (!packet || !decoder)
		return -pte_invalid;

	ppkt = psize == sizeof(pkt) ? packet : &pkt;

	size = pt_pkt_decode(decoder, ppkt);
	if (size < 0)
		return size;

	errcode = pkt_to_user(packet, psize, ppkt);
	if (errcode < 0)
		return errcode;

	decoder->pos += size;

	return size;
}
