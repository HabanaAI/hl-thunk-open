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
#include "goya/goya.h"
#include "goya/asic_reg/goya_regs.h"

#define GOYA_ASYNC_EVENT_ID_TPC0_ECC 36 /* Non Fatal event */
#define GOYA_ASYNC_EVENT_ID_TPC0_DEC 117 /* Fatal event */

#define GOYA_EVENT_GEN_REG \
		((CFG_BASE) + (mmGIC_DISTRIBUTOR__5_GICD_SETSPI_NSR))
#define GOYA_CPU_CA53_CFG_ARM_RST_CONTROL \
		((CFG_BASE) + mmCPU_CA53_CFG_ARM_RST_CONTROL)

#define mmPSOC_GLOBAL_CONF_KMD_MSG_TO_CPU 0xC4B304
#define GOYA_PSOC_GLOBAL_CONF_KMD_MSG_TO_CPU \
		((CFG_BASE) + (mmPSOC_GLOBAL_CONF_KMD_MSG_TO_CPU))

enum kmd_msg {
	KMD_MSG_NA = 0,
	KMD_MSG_GOTO_WFE,
	KMD_MSG_FIT_RDY,
	KMD_MSG_SKIP_BMC,
};

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

static int goya_generate_non_fatal_event(int fd, int *event_num)
{
	struct hlthunk_debugfs debugfs;
	int rc;

	rc = hlthunk_debugfs_open(fd, &debugfs);
	if (rc)
		return -ENOTSUP;

	*event_num = GOYA_ASYNC_EVENT_ID_TPC0_DEC;
	rc = hlthunk_debugfs_write(&debugfs, GOYA_EVENT_GEN_REG, *event_num);
	hlthunk_debugfs_close(&debugfs);

	return rc;
}

static int goya_generate_fatal_event(struct hlthunk_debugfs *debugfs,
					int *event_num)
{
	*event_num = GOYA_ASYNC_EVENT_ID_TPC0_ECC;
	return hlthunk_debugfs_write(debugfs, GOYA_EVENT_GEN_REG, *event_num);
}

static int goya_halt_cpu(struct hlthunk_debugfs *debugfs)
{
	hlthunk_debugfs_write(debugfs, GOYA_PSOC_GLOBAL_CONF_KMD_MSG_TO_CPU,
				KMD_MSG_GOTO_WFE);
	usleep(2);
	/* Put all CPUs in reset */
	hlthunk_debugfs_write(debugfs, GOYA_CPU_CA53_CFG_ARM_RST_CONTROL, 0);

	return 0;
}

static struct hlthunk_asic_funcs asic_goya = {
	.add_fence_pkt = goya_add_fence_pkt,
	.get_dma_down_qid = goya_get_dma_down_qid,
	.generate_non_fatal_event = goya_generate_non_fatal_event,
	.generate_fatal_event = goya_generate_fatal_event,
	.halt_cpu = goya_halt_cpu,
};

struct hlthunk_asic_funcs *get_asic_funcs_goya(void)
{
	return &asic_goya;
}

