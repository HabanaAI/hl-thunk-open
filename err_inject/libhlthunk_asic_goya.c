// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

#include "hlthunk.h"
#include "libhlthunk_supp.h"
#include "goya/goya_packets.h"


static uint32_t goya_add_fence_pkt(void *buffer, uint32_t buf_off,
					struct hlthunk_pkt_info *pkt_info)
{
	struct packet_fence packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_FENCE;
	packet.dec_val = pkt_info->fence.dec_val;
	packet.gate_val = pkt_info->fence.gate_val;
	packet.id = pkt_info->fence.fence_id;
	packet.eng_barrier = pkt_info->eb ? 1 : 0;
	packet.msg_barrier = pkt_info->mb ? 1 : 0;
	packet.reg_barrier = 1;

	packet.ctl = htole32(packet.ctl);
	packet.cfg = htole32(packet.cfg);

	return hlthunk_add_packet_to_cb(buffer, buf_off,
					&packet, sizeof(packet));
}

static uint32_t goya_get_dma_down_qid(
			enum hlthunk_dcore_separation_mode dcore_sep_mode,
			enum hlthunk_stream_id stream)
{
	return GOYA_QUEUE_ID_DMA_1;
}

static struct hlthunk_asic_funcs asic_goya = {
	.add_fence_pkt = goya_add_fence_pkt,
	.get_dma_down_qid = goya_get_dma_down_qid,
};

struct hlthunk_asic_funcs *get_asic_funcs_goya(void)
{
	return &asic_goya;
}

