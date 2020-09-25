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

#include "uapi/hlthunk.h"
#include "libhlthunk_supp.h"
#include "gaudi/gaudi_packets.h"
#include "gaudi/gaudi.h"
#include "gaudi/asic_reg/gaudi_regs.h"

#define GAUDI_EVENT_TPC0_DERR 46 /* Fatal event */
#define GAUDI_EVENT_TPC0_SERR 38 /* Non Fatal event */

#define GAUDI_CPU_CA53_CFG_ARM_RST_CONTROL \
		((CFG_BASE) + mmCPU_CA53_CFG_ARM_RST_CONTROL)
#define GAUDI_EVENT_GEN_REG \
		((CFG_BASE) + (mmGIC_DISTRIBUTOR__5_GICD_SETSPI_NSR))
#define GAUDI_PSOC_GLOBAL_CONF_KMD_MSG_TO_CPU \
		((CFG_BASE) + (mmPSOC_GLOBAL_CONF_KMD_MSG_TO_CPU))

enum kmd_msg {
	KMD_MSG_NA = 0,
	KMD_MSG_GOTO_WFE,
	KMD_MSG_FIT_RDY,
	KMD_MSG_SKIP_BMC,
};

static uint32_t gaudi_add_fence_pkt(void *buffer, uint32_t buf_off,
					struct hlthunk_pkt_info *pkt_info)
{
	struct packet_fence packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_FENCE;
	packet.dec_val = pkt_info->fence.dec_val;
	packet.target_val = pkt_info->fence.gate_val;
	packet.id = pkt_info->fence.fence_id;
	packet.pred = 0;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;

	packet.ctl = htole32(packet.ctl);
	packet.cfg = htole32(packet.cfg);

	return hlthunk_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi_get_dma_down_qid(
			enum hlthunk_dcore_separation_mode dcore_sep_mode,
			enum hlthunk_stream_id stream)
{
	return GAUDI_QUEUE_ID_DMA_0_0 + stream;
}

static int gaudi_generate_non_fatal_event(int fd, int *event_num)
{
	struct hlthunk_debugfs debugfs;
	int rc;

	rc = hlthunk_debugfs_open(fd, &debugfs);
	if (rc)
		return -ENOTSUP;

	*event_num = GAUDI_EVENT_TPC0_SERR;
	rc = hlthunk_debugfs_write(&debugfs, GAUDI_EVENT_GEN_REG, *event_num);
	hlthunk_debugfs_close(&debugfs);

	return rc;
}

static int gaudi_generate_fatal_event(struct hlthunk_debugfs *debugfs,
					int *event_num)
{
	*event_num = GAUDI_EVENT_TPC0_DERR;
	return hlthunk_debugfs_write(debugfs, GAUDI_EVENT_GEN_REG, *event_num);
}

static int gaudi_halt_cpu(struct hlthunk_debugfs *debugfs)
{
	hlthunk_debugfs_write(debugfs, GAUDI_PSOC_GLOBAL_CONF_KMD_MSG_TO_CPU,
				KMD_MSG_GOTO_WFE);
	usleep(2);
	/* Put all CPUs in reset */
	hlthunk_debugfs_write(debugfs, GAUDI_CPU_CA53_CFG_ARM_RST_CONTROL, 0);

	return 0;
}

static struct hlthunk_asic_funcs asic_gaudi = {
	.add_fence_pkt = gaudi_add_fence_pkt,
	.get_dma_down_qid = gaudi_get_dma_down_qid,
	.generate_non_fatal_event = gaudi_generate_non_fatal_event,
	.generate_fatal_event = gaudi_generate_fatal_event,
	.halt_cpu = gaudi_halt_cpu,
};

struct hlthunk_asic_funcs *get_asic_funcs_gaudi(void)
{
	return &asic_gaudi;
}

