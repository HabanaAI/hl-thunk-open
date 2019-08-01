// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "uapi/misc/habanalabs.h"
#include "goya/goya.h"
#include "goya/goya_packets.h"
#include "goya/asic_reg/goya_regs.h"

#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

static uint32_t goya_add_nop_pkt(void *buffer, uint32_t buf_off, bool eb,
					bool mb)
{
	struct packet_nop packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_NOP;
	packet.eng_barrier = eb;
	packet.msg_barrier = mb;
	packet.reg_barrier = 1;

	packet.ctl = htole32(packet.ctl);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t goya_add_msg_long_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_long packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_MSG_LONG;
	packet.addr = pkt_info->msg_long.address;
	packet.value = pkt_info->msg_long.value;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);
	packet.addr = htole64(packet.addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t goya_add_msg_short_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_short packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_MSG_SHORT;
	packet.value = pkt_info->msg_short.value;
	packet.base = pkt_info->msg_short.base;
	packet.msg_addr_offset = pkt_info->msg_short.address;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t goya_add_arm_monitor_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_short packet;
	uint8_t base = 0; /* monitor base address */

	memset(&packet, 0, sizeof(packet));
	packet.mon_arm_register.sync_id = pkt_info->arm_monitor.sob_id;
	packet.mon_arm_register.mode = pkt_info->arm_monitor.mon_mode;
	packet.mon_arm_register.sync_value = pkt_info->arm_monitor.sob_val;
	packet.opcode = PACKET_MSG_SHORT;
	packet.base = base;
	packet.msg_addr_offset = pkt_info->arm_monitor.address;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
							sizeof(packet));
}

static uint32_t goya_add_write_to_sob_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_short packet;
	uint16_t address = pkt_info->write_to_sob.sob_id * 4;
	uint8_t base = 1; /* syn object base address */

	memset(&packet, 0, sizeof(packet.value));
	packet.opcode = PACKET_MSG_SHORT;
	packet.value = pkt_info->write_to_sob.value;
	packet.base  = base;
	packet.msg_addr_offset = address;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;
	packet.so_upd.sync_value = pkt_info->write_to_sob.value;
	packet.so_upd.mode = pkt_info->write_to_sob.mode;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
							sizeof(packet));
}

static uint32_t goya_add_fence_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_fence packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_FENCE;
	packet.dec_val = pkt_info->fence.dec_val;
	packet.gate_val = pkt_info->fence.gate_val;
	packet.id = pkt_info->fence.fence_id;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;

	packet.ctl = htole32(packet.ctl);
	packet.cfg = htole32(packet.cfg);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t goya_add_dma_pkt(void *buffer, uint32_t buf_off,
				struct hltests_pkt_info *pkt_info)
{
	struct packet_lin_dma packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_LIN_DMA;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;
	packet.weakly_ordered = 1;
	packet.src_addr = pkt_info->dma.src_addr;
	packet.dst_addr = pkt_info->dma.dst_addr;
	packet.tsize = pkt_info->dma.size;
	packet.dma_dir = pkt_info->dma.dma_dir;

	packet.ctl = htole32(packet.ctl);
	packet.tsize = htole32(packet.tsize);
	packet.src_addr = htole64(packet.src_addr);
	packet.dst_addr = htole64(packet.dst_addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t goya_add_cp_dma_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_cp_dma packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_CP_DMA;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;
	packet.src_addr = pkt_info->cp_dma.src_addr;
	packet.tsize = pkt_info->cp_dma.size;

	packet.ctl = htole32(packet.ctl);
	packet.tsize = htole32(packet.tsize);
	packet.src_addr = htole64(packet.src_addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t goya_add_monitor_and_fence(void *buffer, uint32_t buf_off,
			struct hltests_monitor_and_fence *mon_and_fence_info)
{
	uint64_t address, monitor_base;
	uint32_t fence_addr = 0;
	uint16_t msg_addr_offset;
	struct hltests_pkt_info pkt_info;
	bool cmdq_fence = mon_and_fence_info->cmdq_fence;
	uint8_t base = 0; /* monitor base address */

	switch (mon_and_fence_info->queue_id) {
	case GOYA_QUEUE_ID_DMA_0:
		fence_addr = mmDMA_QM_0_CP_FENCE0_RDATA;
		break;
	case GOYA_QUEUE_ID_DMA_1:
		fence_addr = mmDMA_QM_1_CP_FENCE0_RDATA;
		break;
	case GOYA_QUEUE_ID_DMA_2:
		fence_addr = mmDMA_QM_2_CP_FENCE0_RDATA;
		break;
	case GOYA_QUEUE_ID_DMA_3:
		fence_addr = mmDMA_QM_3_CP_FENCE0_RDATA;
		break;
	case GOYA_QUEUE_ID_DMA_4:
		fence_addr = mmDMA_QM_4_CP_FENCE0_RDATA;
		break;
	case GOYA_QUEUE_ID_MME:
		if (cmdq_fence)
			fence_addr = mmMME_CMDQ_CP_FENCE0_RDATA;
		else
			fence_addr = mmMME_QM_CP_FENCE0_RDATA;
		break;
	case GOYA_QUEUE_ID_TPC0:
		if (cmdq_fence)
			fence_addr = mmTPC0_CMDQ_CP_FENCE0_RDATA;
		else
			fence_addr = mmTPC0_QM_CP_FENCE0_RDATA;
		break;
	case GOYA_QUEUE_ID_TPC1:
		if (cmdq_fence)
			fence_addr = mmTPC1_CMDQ_CP_FENCE0_RDATA;
		else
			fence_addr = mmTPC1_QM_CP_FENCE0_RDATA;
		break;
	case GOYA_QUEUE_ID_TPC2:
		if (cmdq_fence)
			fence_addr = mmTPC2_CMDQ_CP_FENCE0_RDATA;
		else
			fence_addr = mmTPC2_QM_CP_FENCE0_RDATA;
		break;
	case GOYA_QUEUE_ID_TPC3:
		if (cmdq_fence)
			fence_addr = mmTPC3_CMDQ_CP_FENCE0_RDATA;
		else
			fence_addr = mmTPC3_QM_CP_FENCE0_RDATA;
		break;
	case GOYA_QUEUE_ID_TPC4:
		if (cmdq_fence)
			fence_addr = mmTPC4_CMDQ_CP_FENCE0_RDATA;
		else
			fence_addr = mmTPC4_QM_CP_FENCE0_RDATA;
		break;
	case GOYA_QUEUE_ID_TPC5:
		if (cmdq_fence)
			fence_addr = mmTPC5_CMDQ_CP_FENCE0_RDATA;
		else
			fence_addr = mmTPC5_QM_CP_FENCE0_RDATA;
		break;
	case GOYA_QUEUE_ID_TPC6:
		if (cmdq_fence)
			fence_addr = mmTPC6_CMDQ_CP_FENCE0_RDATA;
		else
			fence_addr = mmTPC6_QM_CP_FENCE0_RDATA;
		break;
	case GOYA_QUEUE_ID_TPC7:
		if (cmdq_fence)
			fence_addr = mmTPC7_CMDQ_CP_FENCE0_RDATA;
		else
			fence_addr = mmTPC7_QM_CP_FENCE0_RDATA;
		break;
	default:
		printf("Failed to configure fence - invalid queue ID %d\n",
				mon_and_fence_info->queue_id);
	}

	if (mon_and_fence_info->mon_address)
		address = mon_and_fence_info->mon_address;
	else
		address = CFG_BASE + fence_addr;

	/* monitor_base should be the content of the base0 address registers,
	 * so it will be added to the msg short offsets
	 */
	monitor_base = mmSYNC_MNGR_MON_PAY_ADDRL_0;

	/* First monitor config packet: low address of the sync */
	msg_addr_offset = (mmSYNC_MNGR_MON_PAY_ADDRL_0 +
			mon_and_fence_info->mon_id * 4) - monitor_base;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_short.base = base;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = (uint32_t) address;
	buf_off = goya_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	/* Second config packet: high address of the sync */
	msg_addr_offset = (mmSYNC_MNGR_MON_PAY_ADDRH_0 +
				mon_and_fence_info->mon_id * 4) - monitor_base;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_short.base = base;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = (uint32_t) (address >> 32);
	buf_off = goya_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	/* Third config packet: the payload, i.e. what to write when the sync
	 * triggers
	 */
	msg_addr_offset = (mmSYNC_MNGR_MON_PAY_DATA_0 +
				mon_and_fence_info->mon_id * 4) - monitor_base;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_short.base = base;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = 1;
	buf_off = goya_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	/* Fourth config packet: bind the monitor to a sync object */
	msg_addr_offset = (mmSYNC_MNGR_MON_ARM_0 +
				mon_and_fence_info->mon_id * 4) - monitor_base;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.arm_monitor.address = msg_addr_offset;
	pkt_info.arm_monitor.mon_mode = EQUAL;
	pkt_info.arm_monitor.sob_val = 1;
	pkt_info.arm_monitor.sob_id = mon_and_fence_info->sob_id;
	buf_off = goya_add_arm_monitor_pkt(buffer, buf_off, &pkt_info);

	/* Fence packet */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.fence.dec_val = mon_and_fence_info->dec_val;
	pkt_info.fence.gate_val = mon_and_fence_info->target_val;
	pkt_info.fence.fence_id = 0;
	buf_off = goya_add_fence_pkt(buffer, buf_off, &pkt_info);

	return buf_off;
}

static uint32_t goya_get_dma_down_qid(enum hltests_dcore_id dcore_id,
						enum hltests_stream_id stream)
{
	return GOYA_QUEUE_ID_DMA_1;
}

static uint32_t goya_get_dma_up_qid(enum hltests_dcore_id dcore_id,
						enum hltests_stream_id stream)
{
	return GOYA_QUEUE_ID_DMA_2;
}

static uint32_t goya_get_dma_dram_to_sram_qid(enum hltests_dcore_id dcore_id,
						enum hltests_stream_id stream)
{
	return GOYA_QUEUE_ID_DMA_3;
}

static uint32_t goya_get_dma_sram_to_dram_qid(enum hltests_dcore_id dcore_id,
						enum hltests_stream_id stream)
{
	return GOYA_QUEUE_ID_DMA_4;
}

static uint32_t goya_get_tpc_qid(enum hltests_dcore_id decore_id,
				uint8_t tpc_id,	enum hltests_stream_id stream)
{
	return GOYA_QUEUE_ID_TPC0 + tpc_id;
}

static uint32_t goya_get_mme_qid(enum hltests_dcore_id decore_id,
				uint8_t mme_id, enum hltests_stream_id stream)
{
	return GOYA_QUEUE_ID_MME;
}

static uint8_t goya_get_tpc_cnt(uint8_t dcore_id)
{
	return TPC_MAX_NUM;
}

static void goya_dram_pool_init(struct hltests_device *hdev)
{

}

static void goya_dram_pool_fini(struct hltests_device *hdev)
{

}

static int goya_dram_pool_alloc(struct hltests_device *hdev, uint64_t size,
				uint64_t *return_addr)
{
	return -EFAULT;
}

static void goya_dram_pool_free(struct hltests_device *hdev, uint64_t addr,
					uint64_t size)
{

}

static const struct hltests_asic_funcs goya_funcs = {
	.add_monitor_and_fence = goya_add_monitor_and_fence,
	.add_nop_pkt = goya_add_nop_pkt,
	.add_msg_long_pkt = goya_add_msg_long_pkt,
	.add_msg_short_pkt = goya_add_msg_short_pkt,
	.add_arm_monitor_pkt = goya_add_arm_monitor_pkt,
	.add_write_to_sob_pkt = goya_add_write_to_sob_pkt,
	.add_fence_pkt = goya_add_fence_pkt,
	.add_dma_pkt = goya_add_dma_pkt,
	.add_cp_dma_pkt = goya_add_cp_dma_pkt,
	.get_dma_down_qid = goya_get_dma_down_qid,
	.get_dma_up_qid = goya_get_dma_up_qid,
	.get_dma_dram_to_sram_qid = goya_get_dma_dram_to_sram_qid,
	.get_dma_sram_to_dram_qid = goya_get_dma_sram_to_dram_qid,
	.get_tpc_qid = goya_get_tpc_qid,
	.get_mme_qid = goya_get_mme_qid,
	.get_tpc_cnt = goya_get_tpc_cnt,
	.dram_pool_init = goya_dram_pool_init,
	.dram_pool_fini = goya_dram_pool_fini,
	.dram_pool_alloc = goya_dram_pool_alloc,
	.dram_pool_free = goya_dram_pool_free
};

void goya_tests_set_asic_funcs(struct hltests_device *hdev)
{
	hdev->asic_funcs = &goya_funcs;
}
