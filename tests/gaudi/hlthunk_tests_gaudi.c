// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "common/hlthunk_tests.h"
#include "uapi/hlthunk.h"
#include "gaudi/gaudi.h"
#include "gaudi/gaudi_packets.h"
#include "gaudi/asic_reg/gaudi_regs.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <cmocka.h>
#include <pthread.h>

static uint32_t gaudi_add_nop_pkt(void *buffer, uint32_t buf_off, bool eb,
					bool mb)
{
	struct packet_nop packet = {0};

	packet.opcode = PACKET_NOP;
	packet.eng_barrier = eb;
	packet.msg_barrier = mb;
	packet.reg_barrier = 1;

	packet.ctl = htole32(packet.ctl);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi_add_wreg32_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_wreg32 packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_WREG_32;
	packet.reg_offset = pkt_info->wreg32.reg_addr;
	packet.value = pkt_info->wreg32.value;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;
	packet.pred = pkt_info->pred;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi_add_arb_point_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_arb_point packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_ARB_POINT;
	packet.priority = pkt_info->arb_point.priority;
	packet.rls = pkt_info->arb_point.release;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;
	packet.pred = pkt_info->pred;

	packet.ctl = htole32(packet.ctl);
	packet.cfg = htole32(packet.cfg);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi_add_msg_long_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_long packet = {0};

	packet.opcode = PACKET_MSG_LONG;
	packet.addr = pkt_info->msg_long.address;
	packet.value = pkt_info->msg_long.value;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;
	packet.pred = pkt_info->pred;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);
	packet.addr = htole64(packet.addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi_add_msg_short_pkt(void *buffer, uint32_t buf_off,
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

static uint32_t gaudi_add_arm_monitor_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_short packet;
	uint8_t mask_val;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_MSG_SHORT;
	packet.op = 0;
	packet.base = 0;
	packet.msg_addr_offset = pkt_info->arm_monitor.address;
	packet.value = 0;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;
	packet.mon_arm_register.mode = pkt_info->arm_monitor.mon_mode;
	packet.mon_arm_register.sync_value = pkt_info->arm_monitor.sob_val;
	packet.mon_arm_register.sync_group_id =
					pkt_info->arm_monitor.sob_id / 8;
	mask_val = ~(1 << (pkt_info->arm_monitor.sob_id & 0x7));
	packet.mon_arm_register.mask = mask_val;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi_add_write_to_sob_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_short packet;

	memset(&packet, 0, sizeof(packet));
	packet.eng_barrier = pkt_info->eb;
	packet.reg_barrier = 1;
	packet.msg_barrier = pkt_info->mb;
	packet.opcode = PACKET_MSG_SHORT;
	packet.op = 0; /* Write the value */
	packet.base = 1; /* Sync object base */
	packet.so_upd.mode = pkt_info->write_to_sob.mode;
	packet.msg_addr_offset = pkt_info->write_to_sob.sob_id * 4;
	packet.so_upd.sync_value = pkt_info->write_to_sob.value;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi_add_fence_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_fence packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_FENCE;
	packet.dec_val = pkt_info->fence.dec_val;
	packet.target_val = pkt_info->fence.gate_val;
	packet.id = pkt_info->fence.fence_id;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;
	packet.pred = pkt_info->pred;

	packet.ctl = htole32(packet.ctl);
	packet.cfg = htole32(packet.cfg);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi_add_dma_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_lin_dma packet = {0};

	packet.opcode = PACKET_LIN_DMA;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;
	packet.lin = 1;
	packet.src_addr = pkt_info->dma.src_addr;
	packet.dst_addr = pkt_info->dma.dst_addr;
	packet.tsize = pkt_info->dma.size;
	packet.mem_set = pkt_info->dma.memset;

	packet.ctl = htole32(packet.ctl);
	packet.tsize = htole32(packet.tsize);
	packet.src_addr = htole64(packet.src_addr);
	packet.dst_addr = htole64(packet.dst_addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi_add_cp_dma_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_cp_dma packet = {0};

	packet.opcode = PACKET_CP_DMA;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;
	packet.pred = pkt_info->pred;
	packet.src_addr = pkt_info->cp_dma.src_addr;
	packet.tsize = pkt_info->cp_dma.size;

	packet.ctl = htole32(packet.ctl);
	packet.tsize = htole32(packet.tsize);
	packet.src_addr = htole64(packet.src_addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi_add_cb_list_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	return 0;
}

static uint32_t gaudi_add_load_and_exe_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_load_and_exe packet;

	memset(&packet, 0, sizeof(packet));

	packet.opcode = PACKET_LOAD_AND_EXE;
	packet.eng_barrier = pkt_info->eb;
	packet.reg_barrier = 1;
	packet.msg_barrier = pkt_info->mb;
	packet.pred = pkt_info->pred;
	packet.src_addr = pkt_info->load_and_exe.src_addr;
	packet.load = pkt_info->load_and_exe.load;
	packet.exe = pkt_info->load_and_exe.exe;
	packet.dst = pkt_info->load_and_exe.load_dst;
	packet.etype = pkt_info->load_and_exe.exe_type;

	packet.cfg = htole32(packet.cfg);
	packet.ctl = htole32(packet.ctl);
	packet.src_addr = htole64(packet.src_addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi_add_monitor_and_fence(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			void *buffer, uint32_t buf_off,
			struct hltests_monitor_and_fence *mon_and_fence_info)
{
	uint64_t address, monitor_base;
	uint32_t fence_addr = 0;
	uint16_t msg_addr_offset;
	bool cmdq_fence = mon_and_fence_info->cmdq_fence;
	struct hltests_pkt_info pkt_info;
	uint8_t fence_gate_val = mon_and_fence_info->mon_payload;

	switch (mon_and_fence_info->queue_id) {
	case GAUDI_QUEUE_ID_DMA_0_0:
		fence_addr = mmDMA0_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI_QUEUE_ID_DMA_0_1:
		fence_addr = mmDMA0_QM_CP_FENCE0_RDATA_1;
		break;
	case GAUDI_QUEUE_ID_DMA_0_2:
		fence_addr = mmDMA0_QM_CP_FENCE0_RDATA_2;
		break;
	case GAUDI_QUEUE_ID_DMA_0_3:
		fence_addr = mmDMA0_QM_CP_FENCE0_RDATA_3;
		break;
	case GAUDI_QUEUE_ID_DMA_1_0:
		fence_addr = mmDMA1_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI_QUEUE_ID_DMA_1_1:
		fence_addr = mmDMA1_QM_CP_FENCE0_RDATA_1;
		break;
	case GAUDI_QUEUE_ID_DMA_1_2:
		fence_addr = mmDMA1_QM_CP_FENCE0_RDATA_2;
		break;
	case GAUDI_QUEUE_ID_DMA_1_3:
		fence_addr = mmDMA1_QM_CP_FENCE0_RDATA_3;
		break;
	case GAUDI_QUEUE_ID_DMA_2_0:
		if (!cmdq_fence)
			fence_addr = mmDMA2_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmDMA2_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_DMA_3_0:
		if (!cmdq_fence)
			fence_addr = mmDMA3_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmDMA3_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_DMA_4_0:
		if (!cmdq_fence)
			fence_addr = mmDMA4_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmDMA4_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_DMA_5_0:
		if (!cmdq_fence)
			fence_addr = mmDMA5_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmDMA5_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_DMA_6_0:
		if (!cmdq_fence)
			fence_addr = mmDMA6_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmDMA6_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_DMA_7_0:
		if (!cmdq_fence)
			fence_addr = mmDMA7_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmDMA7_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_MME_0_0:
		if (!cmdq_fence)
			fence_addr = mmMME2_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmMME2_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_MME_1_0:
		if (!cmdq_fence)
			fence_addr = mmMME0_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmMME0_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_TPC_0_0:
		if (!cmdq_fence)
			fence_addr = mmTPC0_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmTPC0_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_TPC_1_0:
		if (!cmdq_fence)
			fence_addr = mmTPC1_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmTPC1_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_TPC_2_0:
		if (!cmdq_fence)
			fence_addr = mmTPC2_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmTPC2_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_TPC_3_0:
		if (!cmdq_fence)
			fence_addr = mmTPC3_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmTPC3_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_TPC_4_0:
		if (!cmdq_fence)
			fence_addr = mmTPC4_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmTPC4_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_TPC_5_0:
		if (!cmdq_fence)
			fence_addr = mmTPC5_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmTPC5_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_TPC_6_0:
		if (!cmdq_fence)
			fence_addr = mmTPC6_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmTPC6_QM_CP_FENCE0_RDATA_4;
		break;
	case GAUDI_QUEUE_ID_TPC_7_0:
		if (!cmdq_fence)
			fence_addr = mmTPC7_QM_CP_FENCE0_RDATA_0;
		else
			fence_addr = mmTPC7_QM_CP_FENCE0_RDATA_4;
		break;
	default:
		printf("Failed to configure fence - invalid QID %d\n",
			mon_and_fence_info->queue_id);
	}

	if (mon_and_fence_info->mon_address)
		address = mon_and_fence_info->mon_address;
	else
		address = CFG_BASE + fence_addr;

	/* monitor_base should be the content of the base0 address registers,
	 * so it will be added to the msg short offsets
	 */
	monitor_base = mmSYNC_MNGR_E_N_SYNC_MNGR_OBJS_MON_PAY_ADDRL_0;

	/* First monitor config packet: low address of the sync */
	msg_addr_offset =
		(mmSYNC_MNGR_E_N_SYNC_MNGR_OBJS_MON_PAY_ADDRL_0 +
				mon_and_fence_info->mon_id * 4) - monitor_base;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_short.base = 0;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = (uint32_t) address;
	buf_off = gaudi_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	/* Second config packet: high address of the sync */
	msg_addr_offset =
		(mmSYNC_MNGR_E_N_SYNC_MNGR_OBJS_MON_PAY_ADDRH_0 +
				mon_and_fence_info->mon_id * 4) - monitor_base;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_short.base = 0;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = (uint32_t) (address >> 32);
	buf_off = gaudi_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	/* Third config packet: the payload, i.e. what to write when the sync
	 * triggers
	 */
	msg_addr_offset =
		(mmSYNC_MNGR_E_N_SYNC_MNGR_OBJS_MON_PAY_DATA_0 +
				mon_and_fence_info->mon_id * 4) - monitor_base;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_short.base = 0;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = fence_gate_val;
	buf_off = gaudi_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	/* Fourth config packet: bind the monitor to a sync object */
	msg_addr_offset =
		(mmSYNC_MNGR_E_N_SYNC_MNGR_OBJS_MON_ARM_0 +
				mon_and_fence_info->mon_id * 4) - monitor_base;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.arm_monitor.address = msg_addr_offset;
	pkt_info.arm_monitor.mon_mode = EQUAL;
	pkt_info.arm_monitor.sob_val = mon_and_fence_info->sob_val;
	pkt_info.arm_monitor.sob_id = mon_and_fence_info->sob_id;
	buf_off = gaudi_add_arm_monitor_pkt(buffer, buf_off, &pkt_info);

	/* Fence packet */
	if (!(mon_and_fence_info->no_fence)) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.fence.dec_val =
			mon_and_fence_info->dec_fence ? fence_gate_val : 0;

		pkt_info.fence.gate_val = fence_gate_val;
		pkt_info.fence.fence_id = 0;
		buf_off = gaudi_add_fence_pkt(buffer, buf_off, &pkt_info);
	}

	return buf_off;
}

static int gaudi_get_arb_cfg_reg_off(uint32_t queue_id, uint32_t *cfg_offset,
		uint32_t *wrr_cfg_offset, uint32_t *arb_mst_quiet)
{
	switch (queue_id) {
	case GAUDI_QUEUE_ID_DMA_0_0:
	case GAUDI_QUEUE_ID_DMA_0_1:
	case GAUDI_QUEUE_ID_DMA_0_2:
	case GAUDI_QUEUE_ID_DMA_0_3:
		*cfg_offset = mmDMA0_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmDMA0_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmDMA0_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_DMA_1_0:
	case GAUDI_QUEUE_ID_DMA_1_1:
	case GAUDI_QUEUE_ID_DMA_1_2:
	case GAUDI_QUEUE_ID_DMA_1_3:
		*cfg_offset = mmDMA1_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmDMA1_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmDMA1_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_DMA_2_0:
	case GAUDI_QUEUE_ID_DMA_2_1:
	case GAUDI_QUEUE_ID_DMA_2_2:
	case GAUDI_QUEUE_ID_DMA_2_3:
		*cfg_offset = mmDMA2_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmDMA2_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmDMA2_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_DMA_3_0:
	case GAUDI_QUEUE_ID_DMA_3_1:
	case GAUDI_QUEUE_ID_DMA_3_2:
	case GAUDI_QUEUE_ID_DMA_3_3:
		*cfg_offset = mmDMA3_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmDMA3_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmDMA3_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_DMA_4_0:
	case GAUDI_QUEUE_ID_DMA_4_1:
	case GAUDI_QUEUE_ID_DMA_4_2:
	case GAUDI_QUEUE_ID_DMA_4_3:
		*cfg_offset = mmDMA4_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmDMA4_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmDMA4_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_DMA_5_0:
	case GAUDI_QUEUE_ID_DMA_5_1:
	case GAUDI_QUEUE_ID_DMA_5_2:
	case GAUDI_QUEUE_ID_DMA_5_3:
		*cfg_offset = mmDMA5_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmDMA5_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmDMA5_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_DMA_6_0:
	case GAUDI_QUEUE_ID_DMA_6_1:
	case GAUDI_QUEUE_ID_DMA_6_2:
	case GAUDI_QUEUE_ID_DMA_6_3:
		*cfg_offset = mmDMA6_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmDMA6_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmDMA6_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_DMA_7_0:
	case GAUDI_QUEUE_ID_DMA_7_1:
	case GAUDI_QUEUE_ID_DMA_7_2:
	case GAUDI_QUEUE_ID_DMA_7_3:
		*cfg_offset = mmDMA7_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmDMA7_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmDMA7_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_MME_0_0:
	case GAUDI_QUEUE_ID_MME_0_1:
	case GAUDI_QUEUE_ID_MME_0_2:
	case GAUDI_QUEUE_ID_MME_0_3:
		*cfg_offset = mmMME0_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmMME0_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmMME0_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_MME_1_0:
	case GAUDI_QUEUE_ID_MME_1_1:
	case GAUDI_QUEUE_ID_MME_1_2:
	case GAUDI_QUEUE_ID_MME_1_3:
		*cfg_offset = mmMME2_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmMME2_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmMME2_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_TPC_0_0:
	case GAUDI_QUEUE_ID_TPC_0_1:
	case GAUDI_QUEUE_ID_TPC_0_2:
	case GAUDI_QUEUE_ID_TPC_0_3:
		*cfg_offset = mmTPC0_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmTPC0_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmTPC0_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_TPC_1_0:
	case GAUDI_QUEUE_ID_TPC_1_1:
	case GAUDI_QUEUE_ID_TPC_1_2:
	case GAUDI_QUEUE_ID_TPC_1_3:
		*cfg_offset = mmTPC1_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmTPC1_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmTPC1_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_TPC_2_0:
	case GAUDI_QUEUE_ID_TPC_2_1:
	case GAUDI_QUEUE_ID_TPC_2_2:
	case GAUDI_QUEUE_ID_TPC_2_3:
		*cfg_offset = mmTPC2_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmTPC2_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmTPC2_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_TPC_3_0:
	case GAUDI_QUEUE_ID_TPC_3_1:
	case GAUDI_QUEUE_ID_TPC_3_2:
	case GAUDI_QUEUE_ID_TPC_3_3:
		*cfg_offset = mmTPC3_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmTPC3_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmTPC3_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_TPC_4_0:
	case GAUDI_QUEUE_ID_TPC_4_1:
	case GAUDI_QUEUE_ID_TPC_4_2:
	case GAUDI_QUEUE_ID_TPC_4_3:
		*cfg_offset = mmTPC4_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmTPC4_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmTPC4_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_TPC_5_0:
	case GAUDI_QUEUE_ID_TPC_5_1:
	case GAUDI_QUEUE_ID_TPC_5_2:
	case GAUDI_QUEUE_ID_TPC_5_3:
		*cfg_offset = mmTPC5_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmTPC5_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmTPC5_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_TPC_6_0:
	case GAUDI_QUEUE_ID_TPC_6_1:
	case GAUDI_QUEUE_ID_TPC_6_2:
	case GAUDI_QUEUE_ID_TPC_6_3:
		*cfg_offset = mmTPC6_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmTPC6_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmTPC6_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI_QUEUE_ID_TPC_7_0:
	case GAUDI_QUEUE_ID_TPC_7_1:
	case GAUDI_QUEUE_ID_TPC_7_2:
	case GAUDI_QUEUE_ID_TPC_7_3:
		*cfg_offset = mmTPC7_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmTPC7_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmTPC7_QM_ARB_MST_QUIET_PER;
		break;
	default:
		printf("QMAN id %u does not support arbitration\n", queue_id);
		return -EINVAL;
	}

	return 0;
}

static uint32_t gaudi_add_arb_en_pkt(void *buffer, uint32_t buf_off,
				     struct hltests_pkt_info *pkt_info,
				     struct hltests_arb_info *arb_info,
				     uint32_t queue_id, bool enable)
{
	uint32_t i, arb_reg_off, arb_wrr_reg_off, arb_mst_quiet_off;
	int rc;

	rc = gaudi_get_arb_cfg_reg_off(queue_id, &arb_reg_off,
			&arb_wrr_reg_off, &arb_mst_quiet_off);
	if (rc)
		return buf_off;

	/* Set all QMAN Arbiter arb/master/enable */
	pkt_info->msg_long.value = !!arb_info->arb << 0 | 1 << 4 | enable << 8;
	pkt_info->msg_long.address = CFG_BASE + arb_reg_off;

	buf_off = gaudi_add_msg_long_pkt(buffer, buf_off, pkt_info);

	/* Set QMAN quiet period Between Grants */
	pkt_info->msg_long.value = arb_info->arb_mst_quiet_val;
	pkt_info->msg_long.address = CFG_BASE + arb_mst_quiet_off;

	buf_off = gaudi_add_msg_long_pkt(buffer, buf_off, pkt_info);

	if (arb_info->arb == ARB_PRIORITY)
		return buf_off;

	/* Configure weight for each stream */
	for (i = 0 ; i < NUM_OF_STREAMS ; i++) {
		pkt_info->msg_long.value = arb_info->weight[i];
		pkt_info->msg_long.address =
				CFG_BASE + arb_wrr_reg_off + (4 * i);

		buf_off = gaudi_add_msg_long_pkt(buffer, buf_off, pkt_info);
	}

	return buf_off;
}

static uint32_t gaudi_get_dma_down_qid(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			enum hltests_stream_id stream)
{
	return GAUDI_QUEUE_ID_DMA_0_0 + stream;
}

static uint32_t gaudi_get_dma_up_qid(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			enum hltests_stream_id stream)
{
	return GAUDI_QUEUE_ID_DMA_1_0 + stream;
}

static uint8_t gaudi_get_ddma_cnt(
			enum hltests_dcore_separation_mode dcore_sep_mode)
{
	return DMA_NUMBER_OF_CHANNELS - 2;
}

static uint32_t gaudi_get_ddma_qid(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			int dma_ch,
			enum hltests_stream_id stream)
{
	assert_in_range(dma_ch, 0, gaudi_get_ddma_cnt(dcore_sep_mode) - 1);

	return GAUDI_QUEUE_ID_DMA_2_0 + dma_ch * NUM_OF_STREAMS + stream;
}

static uint32_t gaudi_get_tpc_qid(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			uint8_t tpc_id,	enum hltests_stream_id stream)
{
	return GAUDI_QUEUE_ID_TPC_0_0 + tpc_id * 4 + stream;
}

static uint32_t gaudi_get_mme_qid(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			uint8_t mme_id, enum hltests_stream_id stream)
{
	return GAUDI_QUEUE_ID_MME_0_0 + mme_id * 4 + stream;
}

static uint8_t gaudi_get_tpc_cnt(
			enum hltests_dcore_separation_mode dcore_sep_mode)
{
	return TPC_NUMBER_OF_ENGINES;
}

static uint8_t gaudi_get_mme_cnt(
			enum hltests_dcore_separation_mode dcore_sep_mode)
{
	return MME_NUMBER_OF_MASTER_ENGINES;
}

static uint16_t gaudi_get_first_avail_sob(
			enum hltests_dcore_separation_mode dcore_sep_mode)
{
	return 0;
}

static uint16_t gaudi_get_first_avail_mon(
			enum hltests_dcore_separation_mode dcore_sep_mode)
{
	return 0;
}

static int gaudi_dram_pool_alloc(struct hltests_device *hdev, uint64_t size,
					uint64_t *return_addr)
{
	uint64_t addr;
	int rc;

	rc = hltests_mem_pool_alloc(hdev->priv, size, &addr);
	if (rc)
		return rc;

	*return_addr = addr;

	return 0;
}

static void gaudi_dram_pool_free(struct hltests_device *hdev, uint64_t addr,
					uint64_t size)
{
	hltests_mem_pool_free(hdev->priv, addr, size);
}

int gaudi_submit_cs(int fd, struct hltests_cs_chunk *restore_arr,
		uint32_t restore_arr_size, struct hltests_cs_chunk *execute_arr,
		uint32_t execute_arr_size, uint32_t flags, uint64_t *seq)
{
	return hltests_submit_legacy_cs(fd, restore_arr, restore_arr_size,
				execute_arr, execute_arr_size, flags, seq);
}

int gaudi_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us)
{
	return hltests_wait_for_legacy_cs(fd, seq, timeout_us);
}

static void gaudi_dram_pool_init(struct hltests_device *hdev)
{
	struct hlthunk_hw_ip_info hw_ip;
	int rc;

	rc = hlthunk_get_hw_ip_info(hdev->fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled)
		return;

	hdev->priv = hltests_mem_pool_init(hw_ip.dram_base_address,
						hw_ip.dram_size,
						PAGE_SHIFT_2MB);
	assert_non_null(hdev->priv);
}

static void gaudi_dram_pool_fini(struct hltests_device *hdev)
{
	if (hdev->priv)
		hltests_mem_pool_fini(hdev->priv);
	hdev->priv = NULL;
}

static int gaudi_get_max_pll_idx(void)
{
	return HL_GAUDI_PLL_MAX;
}

static const char *gaudi_stringify_pll_idx(uint32_t pll_idx)
{
	switch (pll_idx) {
	case HL_GAUDI_CPU_PLL: return "HL_GAUDI_CPU_PLL";
	case HL_GAUDI_PCI_PLL: return "HL_GAUDI_PCI_PLL";
	case HL_GAUDI_SRAM_PLL: return "HL_GAUDI_SRAM_PLL";
	case HL_GAUDI_HBM_PLL: return "HL_GAUDI_HBM_PLL";
	case HL_GAUDI_NIC_PLL: return "HL_GAUDI_NIC_PLL";
	case HL_GAUDI_DMA_PLL: return "HL_GAUDI_DMA_PLL";
	case HL_GAUDI_MESH_PLL: return "HL_GAUDI_MESH_PLL";
	case HL_GAUDI_MME_PLL: return "HL_GAUDI_MME_PLL";
	case HL_GAUDI_TPC_PLL: return "HL_GAUDI_TPC_PLL";
	case HL_GAUDI_IF_PLL: return "HL_GAUDI_IF_PLL";
	default: return "INVALID_PLL_INDEX";
	}
}

static const char *gaudi_stringify_pll_type(uint32_t pll_idx, uint8_t type_idx)
{
	switch (pll_idx) {
	case HL_GAUDI_CPU_PLL:
		switch (type_idx) {
		case 0: return "HBW_CLK";
		case 1: return "LBW_CLK";
		case 2: return "TS_CLK";
		case 3: return "NA";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI_PCI_PLL:
		switch (type_idx) {
		case 0: return "PCI_LBW_CLK|PSOC_LBW_CLK";
		case 1: return "PCI_TRACE_CLK|PSOC_TRACE";
		case 2: return "PCI_DBG_CLK|PCI_AUX_CLK|PSOC_CFG_CLK|PSOC_DBG_CLK";
		case 3: return "PCI_PHY_CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI_SRAM_PLL:
		switch (type_idx) {
		case 0: return "HBW_CLK";
		case 1 ... 3: return "NA";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI_HBM_PLL:
		switch (type_idx) {
		case 0: return "HBM_CLK";
		case 1: return "NIC_CLK";
		case 2 ... 3: return "NA";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI_NIC_PLL:
		switch (type_idx) {
		case 0: return "PRT_CLK";
		case 1: return "PRT_ANIT_CLK";
		case 2: return "PRT_CFG_CLK|HBM_CFG_CLK";
		case 3: return "NA";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI_DMA_PLL:
		switch (type_idx) {
		case 0: return "HBW_CLK";
		case 1: return "LBW_CLK";
		case 2 ... 3: return "NA";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI_MESH_PLL:
		switch (type_idx) {
		case 0: return "MESH_HBW_CLK|DMA_IF_HBW_CLK";
		case 1: return "MESH_LBW_CLK|DMA_IF_LBW_CLK";
		case 2: return "MESH_TRACE_CLK|DMA_IF_TRACE_CLK";
		case 3: return "MESH_DBG_CLK|DMA_IF_DBG_CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI_MME_PLL:
	case HL_GAUDI_TPC_PLL:
	case HL_GAUDI_IF_PLL:
		switch (type_idx) {
		case 0: return "HBW_CLK";
		case 1: return "LBW_CLK";
		case 2: return "TRACE_CLK";
		case 3: return "DBG_CLK";
		default: return "INVALID_REQ";
		}
	default: return "INVALID_PLL_INDEX";
	}
}

static const struct hltests_asic_funcs gaudi_funcs = {
	.add_arb_en_pkt = gaudi_add_arb_en_pkt,
	.add_monitor_and_fence = gaudi_add_monitor_and_fence,
	.add_nop_pkt = gaudi_add_nop_pkt,
	.add_wreg32_pkt = gaudi_add_wreg32_pkt,
	.add_arb_point_pkt = gaudi_add_arb_point_pkt,
	.add_msg_long_pkt = gaudi_add_msg_long_pkt,
	.add_msg_short_pkt = gaudi_add_msg_short_pkt,
	.add_arm_monitor_pkt = gaudi_add_arm_monitor_pkt,
	.add_write_to_sob_pkt = gaudi_add_write_to_sob_pkt,
	.add_fence_pkt = gaudi_add_fence_pkt,
	.add_dma_pkt = gaudi_add_dma_pkt,
	.add_cp_dma_pkt = gaudi_add_cp_dma_pkt,
	.add_load_and_exe_pkt = gaudi_add_load_and_exe_pkt,
	.get_dma_down_qid = gaudi_get_dma_down_qid,
	.get_dma_up_qid = gaudi_get_dma_up_qid,
	.get_ddma_qid = gaudi_get_ddma_qid,
	.get_ddma_cnt = gaudi_get_ddma_cnt,
	.get_tpc_qid = gaudi_get_tpc_qid,
	.get_mme_qid = gaudi_get_mme_qid,
	.get_tpc_cnt = gaudi_get_tpc_cnt,
	.get_mme_cnt = gaudi_get_mme_cnt,
	.get_first_avail_sob = gaudi_get_first_avail_sob,
	.get_first_avail_mon = gaudi_get_first_avail_mon,
	.dram_pool_init = gaudi_dram_pool_init,
	.dram_pool_fini = gaudi_dram_pool_fini,
	.dram_pool_alloc = gaudi_dram_pool_alloc,
	.dram_pool_free = gaudi_dram_pool_free,
	.submit_cs = gaudi_submit_cs,
	.wait_for_cs = gaudi_wait_for_cs,
	.get_max_pll_idx = gaudi_get_max_pll_idx,
	.stringify_pll_idx = gaudi_stringify_pll_idx,
	.stringify_pll_type = gaudi_stringify_pll_type
};

void gaudi_tests_set_asic_funcs(struct hltests_device *hdev)
{
	hdev->asic_funcs = &gaudi_funcs;
}

static void *gaudi_mmap(int fd, size_t size, off_t offset)
{
	return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
}

static int gaudi_munmap(void *addr, size_t size)
{
	return munmap(addr, size);
}
