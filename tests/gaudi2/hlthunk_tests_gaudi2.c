// SPDX-License-Identifier: MIT

/*
 * Copyright 2019-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "gaudi2/gaudi2.h"
#include "gaudi2/gaudi2_packets.h"
#include "gaudi2/asic_reg/gaudi2_regs.h"
#include "gaudi2/gaudi2_async_events.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#define DCORE_TPC_OFFSET \
		(mmDCORE0_TPC1_QM_GLBL_CFG0 - mmDCORE0_TPC0_QM_GLBL_CFG0)

#define DCORE_EDMA_OFFSET \
		(mmDCORE0_EDMA1_QM_GLBL_CFG0 - mmDCORE0_EDMA0_QM_GLBL_CFG0)

#define SOB_VAL_LONG_MODE_MASK 0x7FFF /* 15 bits */

#define ARC_AUX_HBM0_LSB_OFFSET	(CFG_BASE + \
				mmARC_FARM_ARC0_AUX_HBM0_LSB_ADDR - \
				mmARC_FARM_ARC0_AUX_BASE)

#define ARC_AUX_HBM0_MSB_OFFSET	(CFG_BASE + \
				mmARC_FARM_ARC0_AUX_HBM0_MSB_ADDR - \
				mmARC_FARM_ARC0_AUX_BASE)

#define ARC_AUX_HBM0_OFF_OFFSET	(CFG_BASE + \
				mmARC_FARM_ARC0_AUX_HBM0_OFFSET - \
				mmARC_FARM_ARC0_AUX_BASE)

#define ARC_AUX_PCIE_LSB_OFFSET	(CFG_BASE + \
				mmARC_FARM_ARC0_AUX_PCIE_LSB_ADDR - \
				mmARC_FARM_ARC0_AUX_BASE)

#define ARC_AUX_PCIE_MSB_OFFSET	(CFG_BASE + \
				mmARC_FARM_ARC0_AUX_PCIE_MSB_ADDR - \
				mmARC_FARM_ARC0_AUX_BASE)

#define ARC_AUX_RUN_HALT_REQ_OFFSET	(CFG_BASE + \
					mmARC_FARM_ARC0_AUX_RUN_HALT_REQ - \
					mmARC_FARM_ARC0_AUX_BASE)

#define ARC_AUX_ARC_NUM_OFFSET		(CFG_BASE + \
					mmARC_FARM_ARC0_AUX_ARC_NUM - \
					mmARC_FARM_ARC0_AUX_BASE)

#define ARC_AUX_MME_ARC_UPPER_DCCM_EN_OFFSET \
					(CFG_BASE + \
					mmARC_FARM_ARC0_AUX_MME_ARC_UPPER_DCCM_EN - \
					mmARC_FARM_ARC0_AUX_BASE)

#define SCHED_FENCE_LBU_ADDR_OFFSET	(CFG_BASE + \
					SCHED_FENCE_LBU_ADDR - \
					mmARC_FARM_ARC0_AUX_BASE)

#define SCHED_FW_CONFIG_ADDR_OFFSET	(CFG_BASE + \
					SCHED_FW_CONFIG_ADDR - \
					mmARC_FARM_ARC0_AUX_BASE)

#define SCHED_FW_CONFIG_SIZE_OFFSET	(CFG_BASE + \
					SCHED_FW_CONFIG_SIZE - \
					mmARC_FARM_ARC0_AUX_BASE)

#define ARC_ACP_ENG_ACP_PR_REG_0_OFFSET	(CFG_BASE + \
					mmARC_FARM_ARC0_ACP_ENG_ACP_PR_REG_0 - \
					mmARC_FARM_ARC0_ACP_ENG_BASE)

#define ARC_DUP_ENG_TRANS_DATA_Q_OFFSET0		\
	(mmARC_FARM_ARC0_DUP_ENG_DUP_TRANS_DATA_Q_0_0 -	\
	 mmARC_FARM_ARC0_DUP_ENG_DUP_TPC_ENG_ADDR_0)
#define ARC_DUP_ENG_TRANS_DATA_Q_OFFSET1		\
	(mmARC_FARM_ARC0_DUP_ENG_DUP_TRANS_DATA_Q_1_0 -	\
	 mmARC_FARM_ARC0_DUP_ENG_DUP_TPC_ENG_ADDR_0)
#define ARC_DUP_ENG_TRANS_DATA_Q_OFFSET2		\
	(mmARC_FARM_ARC0_DUP_ENG_DUP_TRANS_DATA_Q_2_0 -	\
	 mmARC_FARM_ARC0_DUP_ENG_DUP_TPC_ENG_ADDR_0)
#define ARC_DUP_ENG_TRANS_DATA_Q_OFFSET3		\
	(mmARC_FARM_ARC0_DUP_ENG_DUP_TRANS_DATA_Q_3_0 -	\
	 mmARC_FARM_ARC0_DUP_ENG_DUP_TPC_ENG_ADDR_0)

#define SCHED_STREAM_PRIORITY		1

#define ARC_IMAGE_HBM_SIZE             SZ_128K
#define SCHED_ARC_IMAGE_DCCM_SIZE      SZ_64K
#define SCHED_ARC_IMAGE_SIZE           (SCHED_ARC_IMAGE_DCCM_SIZE + ARC_IMAGE_HBM_SIZE)
#define ENGINE_ARC_IMAGE_DCCM_SIZE     SZ_32K
#define ENGINE_ARC_IMAGE_SIZE          (ENGINE_ARC_IMAGE_DCCM_SIZE + ARC_IMAGE_HBM_SIZE)

#define MON_PER_ENG_GROUP 1
#define SOB_PER_ENG_GROUP 2

#define GAUDI2_CQ_SLEEP_USEC 1000

struct gaudi2_priv {
	struct hltests_cq *cq;
};

static uint32_t gaudi2_add_nop_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_nop packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_NOP;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;

	packet.ctl = htole32(packet.ctl);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi2_add_msg_barrier_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	/* Not supported in Gaudi2 */
	return buf_off;
}

static uint32_t gaudi2_add_wreg32_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_wreg32 packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_WREG_32;
	packet.reg_offset = pkt_info->wreg32.reg_addr;
	packet.value = pkt_info->wreg32.value;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.pred = pkt_info->pred;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi2_add_arb_point_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_arb_point packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_ARB_POINT;
	packet.priority = pkt_info->arb_point.priority;
	packet.rls = pkt_info->arb_point.release;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.pred = pkt_info->pred;

	packet.ctl = htole32(packet.ctl);
	packet.cfg = htole32(packet.cfg);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi2_add_msg_long_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_long packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_MSG_LONG;
	packet.addr = pkt_info->msg_long.address;
	packet.value = pkt_info->msg_long.value;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.pred = pkt_info->pred;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);
	packet.addr = htole64(packet.addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi2_add_msg_short_pkt(void *buffer, uint32_t buf_off,
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

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi2_add_config_monitor_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_short packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_MSG_SHORT;
	packet.msg_addr_offset = pkt_info->config_monitor.address;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.mon_config_register.wr_num = pkt_info->config_monitor.wr_num;
	packet.mon_config_register.msb_sid = pkt_info->config_monitor.msb_sob_id;
	packet.mon_config_register.long_sob = !!pkt_info->config_monitor.long_mode;
	packet.mon_config_register.cq_en = !!pkt_info->config_monitor.cq_enable;
	packet.mon_config_register.lbw_en = !!pkt_info->config_monitor.lbw_enable;
	packet.mon_config_register.long_high_group = !!pkt_info->config_monitor.long_high_group;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
							sizeof(packet));
}

static uint32_t gaudi2_add_arm_monitor_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_short packet;
	uint8_t mask_val;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_MSG_SHORT;
	packet.msg_addr_offset = pkt_info->arm_monitor.address;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
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

static uint32_t add_write_to_sob_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_short packet;

	memset(&packet, 0, sizeof(packet));

	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.opcode = PACKET_MSG_SHORT;
	packet.base = 1; /* Sync object base */
	packet.so_upd.mode = pkt_info->write_to_sob.mode;
	packet.msg_addr_offset = pkt_info->write_to_sob.sob_id * 4;
	packet.so_upd.sync_value = pkt_info->write_to_sob.value;
	packet.so_upd.long_mode = pkt_info->write_to_sob.long_mode;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
								sizeof(packet));
}

static uint32_t gaudi2_add_write_to_sob_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct hltests_pkt_info mod_pkt_info;
	int i, pkt_size = buf_off;

	memcpy(&mod_pkt_info, pkt_info, sizeof(mod_pkt_info));

	if (pkt_info->write_to_sob.long_mode &&
		pkt_info->write_to_sob.mode == SOB_SET) {
		/*
		 * In long mode use 4 sync objects
		 * setting index 0 zeros indexes 1-3, so start with index 0
		 */
		for (i = 0; i < 4; i++) {
			mod_pkt_info.write_to_sob.sob_id =
				pkt_info->write_to_sob.sob_id + i;
			mod_pkt_info.write_to_sob.long_mode = i ? 0 : 1;
			mod_pkt_info.write_to_sob.value =
				(pkt_info->write_to_sob.value >> (15 * i)) &
							SOB_VAL_LONG_MODE_MASK;
			pkt_size = add_write_to_sob_pkt(buffer, pkt_size,
						&mod_pkt_info);
		}
		return pkt_size;
	} else {
		return add_write_to_sob_pkt(buffer, buf_off, pkt_info);
	}
}

static uint32_t gaudi2_add_fence_pkt(void *buffer, uint32_t buf_off,
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
	packet.pred = pkt_info->pred;

	packet.ctl = htole32(packet.ctl);
	packet.cfg = htole32(packet.cfg);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi2_add_dma_pkt(void *buffer, uint32_t buf_off,
				struct hltests_pkt_info *pkt_info)
{
	struct packet_lin_dma packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_LIN_DMA;
	packet.src_addr = pkt_info->dma.src_addr;
	packet.dst_addr = pkt_info->dma.dst_addr;
	packet.tsize = pkt_info->dma.size;
	packet.endian = pkt_info->dma.endian_swap;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.memset = pkt_info->dma.memset;

	packet.ctl = htole32(packet.ctl);
	packet.tsize = htole32(packet.tsize);
	packet.src_addr = htole64(packet.src_addr);
	packet.dst_addr = htole64(packet.dst_addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi2_add_cp_dma_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_cp_dma packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_CP_DMA;
	packet.src_addr = pkt_info->cp_dma.src_addr;
	packet.tsize = pkt_info->cp_dma.size;
	packet.upper_cp = pkt_info->cp_dma.upper_cp;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.pred = pkt_info->pred;

	packet.ctl = htole32(packet.ctl);
	packet.tsize = htole32(packet.tsize);
	packet.src_addr = htole64(packet.src_addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi2_add_cb_list_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_cb_list packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_CB_LIST;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.pred = pkt_info->pred;
	packet.table_addr = pkt_info->cb_list.table_addr;
	packet.index_addr = pkt_info->cb_list.index_addr;
	packet.size_desc = 0; /* ENTRY_SIZE of 16B is the only supported size */

	packet.ctl = htole32(packet.ctl);
	packet.index_addr = htole64(packet.index_addr);
	packet.table_addr = htole64(packet.table_addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi2_add_load_and_exe_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_load_and_exe packet;

	memset(&packet, 0, sizeof(packet));

	packet.opcode = PACKET_LOAD_AND_EXE;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.pred = pkt_info->pred;
	packet.src_addr = pkt_info->load_and_exe.src_addr;
	packet.load = pkt_info->load_and_exe.load;
	packet.exe = pkt_info->load_and_exe.exe;
	packet.dst = pkt_info->load_and_exe.load_dst;
	packet.pmap = pkt_info->load_and_exe.pred_map;
	packet.etype = pkt_info->load_and_exe.exe_type;

	packet.cfg = htole32(packet.cfg);
	packet.ctl = htole32(packet.ctl);
	packet.src_addr = htole64(packet.src_addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint64_t gaudi2_get_fence_addr(int fd, uint32_t qid, bool cmdq_fence)
{
	uint64_t fence_addr = 0;
	uint32_t index = 0;

	/* When using arcs, upper cp in NA, hence in this case we enforce using lower cp fence */
	if (!hltests_is_legacy_mode_enabled(fd))
		cmdq_fence = true;

	switch (qid) {
	case GAUDI2_QUEUE_ID_PDMA_0_0:
		if (cmdq_fence)
			fence_addr = mmPDMA0_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmPDMA0_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_PDMA_0_1:
		/* Only one available lower cp fence for all streams, and its assigned to stream0 */
		if (cmdq_fence)
			fail();
		else
			fence_addr = mmPDMA0_QM_CP_FENCE0_RDATA_1;
		break;
	case GAUDI2_QUEUE_ID_PDMA_0_2:
		if (cmdq_fence)
			fail();
		else
			fence_addr = mmPDMA0_QM_CP_FENCE0_RDATA_2;
		break;
	case GAUDI2_QUEUE_ID_PDMA_0_3:
		if (cmdq_fence)
			fail();
		else
			fence_addr = mmPDMA0_QM_CP_FENCE0_RDATA_3;
		break;
	case GAUDI2_QUEUE_ID_PDMA_1_0:
		if (cmdq_fence)
			fence_addr = mmPDMA1_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmPDMA1_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_PDMA_1_1:
		if (cmdq_fence)
			fail();
		else
			fence_addr = mmPDMA1_QM_CP_FENCE0_RDATA_1;
		break;
	case GAUDI2_QUEUE_ID_PDMA_1_2:
		if (cmdq_fence)
			fail();
		else
			fence_addr = mmPDMA1_QM_CP_FENCE0_RDATA_2;
		break;
	case GAUDI2_QUEUE_ID_PDMA_1_3:
		if (cmdq_fence)
			fail();
		else
			fence_addr = mmPDMA1_QM_CP_FENCE0_RDATA_3;
		break;
	case GAUDI2_QUEUE_ID_DCORE0_EDMA_0_0:
		if (cmdq_fence)
			fence_addr = mmDCORE0_EDMA0_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmDCORE0_EDMA0_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE0_EDMA_1_0:
		if (cmdq_fence)
			fence_addr = mmDCORE0_EDMA1_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmDCORE0_EDMA1_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE1_EDMA_0_0:
		if (cmdq_fence)
			fence_addr = mmDCORE1_EDMA0_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmDCORE1_EDMA0_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE1_EDMA_1_0:
		if (cmdq_fence)
			fence_addr = mmDCORE1_EDMA1_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmDCORE1_EDMA1_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE2_EDMA_0_0:
		if (cmdq_fence)
			fence_addr = mmDCORE2_EDMA0_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmDCORE2_EDMA0_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE2_EDMA_1_0:
		if (cmdq_fence)
			fence_addr = mmDCORE2_EDMA1_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmDCORE2_EDMA1_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE3_EDMA_0_0:
		if (cmdq_fence)
			fence_addr = mmDCORE3_EDMA0_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmDCORE3_EDMA0_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE3_EDMA_1_0:
		if (cmdq_fence)
			fence_addr = mmDCORE3_EDMA1_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmDCORE3_EDMA1_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE0_MME_0_0:
		if (cmdq_fence)
			fence_addr = mmDCORE0_MME_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmDCORE0_MME_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE1_MME_0_0:
		if (cmdq_fence)
			fence_addr = mmDCORE1_MME_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmDCORE1_MME_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE2_MME_0_0:
		if (cmdq_fence)
			fence_addr = mmDCORE2_MME_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmDCORE2_MME_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE3_MME_0_0:
		if (cmdq_fence)
			fence_addr = mmDCORE3_MME_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmDCORE3_MME_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE0_TPC_0_0:
	case GAUDI2_QUEUE_ID_DCORE0_TPC_1_0:
	case GAUDI2_QUEUE_ID_DCORE0_TPC_2_0:
	case GAUDI2_QUEUE_ID_DCORE0_TPC_3_0:
	case GAUDI2_QUEUE_ID_DCORE0_TPC_4_0:
	case GAUDI2_QUEUE_ID_DCORE0_TPC_5_0:
	case GAUDI2_QUEUE_ID_DCORE0_TPC_6_0:
		index = (qid - GAUDI2_QUEUE_ID_DCORE0_TPC_0_0) >> 2;
		if (cmdq_fence)
			fence_addr = index * DCORE_TPC_OFFSET +
				mmDCORE0_TPC0_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = index * DCORE_TPC_OFFSET +
				mmDCORE0_TPC0_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE1_TPC_0_0:
	case GAUDI2_QUEUE_ID_DCORE1_TPC_1_0:
	case GAUDI2_QUEUE_ID_DCORE1_TPC_2_0:
	case GAUDI2_QUEUE_ID_DCORE1_TPC_3_0:
	case GAUDI2_QUEUE_ID_DCORE1_TPC_4_0:
	case GAUDI2_QUEUE_ID_DCORE1_TPC_5_0:
		index = (qid - GAUDI2_QUEUE_ID_DCORE1_TPC_0_0) >> 2;
		if (cmdq_fence)
			fence_addr = index * DCORE_TPC_OFFSET +
				mmDCORE1_TPC0_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = index * DCORE_TPC_OFFSET +
				mmDCORE1_TPC0_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE2_TPC_0_0:
	case GAUDI2_QUEUE_ID_DCORE2_TPC_1_0:
	case GAUDI2_QUEUE_ID_DCORE2_TPC_2_0:
	case GAUDI2_QUEUE_ID_DCORE2_TPC_3_0:
	case GAUDI2_QUEUE_ID_DCORE2_TPC_4_0:
	case GAUDI2_QUEUE_ID_DCORE2_TPC_5_0:
		index = (qid - GAUDI2_QUEUE_ID_DCORE2_TPC_0_0) >> 2;
		if (cmdq_fence)
			fence_addr = index * DCORE_TPC_OFFSET +
				mmDCORE2_TPC0_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = index * DCORE_TPC_OFFSET +
				mmDCORE2_TPC0_QM_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_DCORE3_TPC_0_0:
	case GAUDI2_QUEUE_ID_DCORE3_TPC_1_0:
	case GAUDI2_QUEUE_ID_DCORE3_TPC_2_0:
	case GAUDI2_QUEUE_ID_DCORE3_TPC_3_0:
	case GAUDI2_QUEUE_ID_DCORE3_TPC_4_0:
	case GAUDI2_QUEUE_ID_DCORE3_TPC_5_0:
		index = (qid - GAUDI2_QUEUE_ID_DCORE3_TPC_0_0) >> 2;
		if (cmdq_fence)
			fence_addr = index * DCORE_TPC_OFFSET +
				mmDCORE3_TPC0_QM_CP_FENCE0_RDATA_4;
		else
			fence_addr = index * DCORE_TPC_OFFSET +
				mmDCORE3_TPC0_QM_CP_FENCE0_RDATA_0;
		break;
	default:
		printf("Failed to configure fence - invalid QID %d\n", qid);
		fail();
	}

	return CFG_BASE + fence_addr;
}

static uint32_t gaudi2_add_monitor(void *buffer, uint32_t buf_off,
			struct hltests_monitor *mon_info)
{
	uint64_t address, monitor_base;
	uint16_t msg_addr_offset;
	uint8_t base = 0; /* monitor base address */
	struct hltests_pkt_info pkt_info;
	uint32_t fence_gate_val = mon_info->mon_payload;
	bool dummy_mon_wr;
	int i;

	if (mon_info->cq_enable)
		address = mon_info->cq_id;
	else
		address = mon_info->mon_address;

	/* monitor_base should be the content of the base0 address registers,
	 * so it will be added to the msg short offsets
	 */
	monitor_base = mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_ADDRL_0;

	/*
	 * there is a bug (H6-3342) in which SM can fire 2 expiration messages when long SOB
	 * is armed with a single payload.
	 * The W/A to this issue is to always configure long monitors to fire at least 2 payloads.
	 * In case there’s only one payload to send, a second (dummy) payload should be added
	 * to the monitor.
	 */
	dummy_mon_wr = mon_info->long_mode && (mon_info->num_writes == WR_NUM_1_WRITE);
	if (dummy_mon_wr)
		mon_info->num_writes = WR_NUM_2_WRITES;

	/* First monitor config packet: set long mode and CQ properties */
	msg_addr_offset = (mmDCORE0_SYNC_MNGR_OBJS_MON_CONFIG_0 +
			mon_info->mon_id * 4) - monitor_base;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.config_monitor.address = msg_addr_offset;
	pkt_info.config_monitor.wr_num = mon_info->num_writes;
	pkt_info.config_monitor.long_mode = mon_info->long_mode;
	pkt_info.config_monitor.cq_enable = mon_info->cq_enable;
	pkt_info.config_monitor.lbw_enable = mon_info->cq_enable;
	pkt_info.config_monitor.msb_sob_id = (mon_info->sob_id / 8) >> 8;
	buf_off = gaudi2_add_config_monitor_pkt(buffer, buf_off, &pkt_info);

	/* Second monitor config packet: low address of the sync */
	msg_addr_offset = (mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_ADDRL_0 +
			mon_info->mon_id * 4) - monitor_base;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_short.base = base;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = lower_32_bits(address);
	buf_off = gaudi2_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	/* Third config packet: high address of the sync */
	msg_addr_offset = (mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_ADDRH_0 +
			mon_info->mon_id * 4) - monitor_base;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_short.base = base;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = upper_32_bits(address);
	buf_off = gaudi2_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	/* Fourth config packet: the payload, i.e. what to write when the sync
	 * triggers
	 */
	msg_addr_offset = (mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_DATA_0 +
			mon_info->mon_id * 4) - monitor_base;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_short.base = base;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = fence_gate_val;
	buf_off = gaudi2_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	if (dummy_mon_wr) {
		/* dummy monitor config packet: low address of the sync */
		address = CFG_BASE + mmDCORE0_SYNC_MNGR_OBJS_SOB_OBJ_8184;
		msg_addr_offset = (mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_ADDRL_0 +
				(mon_info->mon_id + 1) * 4) - monitor_base;
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.msg_short.base = base;
		pkt_info.msg_short.address = msg_addr_offset;
		pkt_info.msg_short.value = lower_32_bits(address);
		buf_off = gaudi2_add_msg_short_pkt(buffer, buf_off, &pkt_info);

		/* dummy config packet: high address of the sync */
		msg_addr_offset = (mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_ADDRH_0 +
				(mon_info->mon_id + 1) * 4) - monitor_base;
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.msg_short.base = base;
		pkt_info.msg_short.address = msg_addr_offset;
		pkt_info.msg_short.value = upper_32_bits(address);
		buf_off = gaudi2_add_msg_short_pkt(buffer, buf_off, &pkt_info);

		msg_addr_offset = (mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_DATA_0 +
				(mon_info->mon_id + 1) * 4) - monitor_base;
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.msg_short.base = base;
		pkt_info.msg_short.address = msg_addr_offset;
		pkt_info.msg_short.value = 0;
		buf_off = gaudi2_add_msg_short_pkt(buffer, buf_off, &pkt_info);
	}

	if (mon_info->avoid_arm_mon)
		goto out;

	/* Fifth config packets: bind the monitor to a sync object */
	if (mon_info->long_mode) {
		for (i = 3 ; i >= 0 ; i--) {
			msg_addr_offset = (mmDCORE0_SYNC_MNGR_OBJS_MON_ARM_0 +
				(mon_info->mon_id + i) * 4) -
								monitor_base;
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_TRUE;
			pkt_info.arm_monitor.address = msg_addr_offset;
			pkt_info.arm_monitor.mon_mode = EQUAL;
			pkt_info.arm_monitor.sob_val =
				(mon_info->sob_val >> (15 * i)) &
							SOB_VAL_LONG_MODE_MASK;
			pkt_info.arm_monitor.sob_id = i ? 0 :
				mon_info->sob_id;
			buf_off = gaudi2_add_arm_monitor_pkt(buffer, buf_off,
					&pkt_info);
		}
	} else {
		msg_addr_offset = (mmDCORE0_SYNC_MNGR_OBJS_MON_ARM_0 +
				mon_info->mon_id * 4) - monitor_base;
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.arm_monitor.address = msg_addr_offset;
		pkt_info.arm_monitor.mon_mode = EQUAL;
		pkt_info.arm_monitor.sob_val = mon_info->sob_val;
		pkt_info.arm_monitor.sob_id = mon_info->sob_id;
		buf_off =
			gaudi2_add_arm_monitor_pkt(buffer, buf_off, &pkt_info);
	}
out:
	return buf_off;
}

static uint32_t gaudi2_add_monitor_and_fence(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			void *buffer, uint32_t buf_off,
			struct hltests_monitor_and_fence *mon_and_fence_info)
{
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor mon_info = {0};
	uint64_t address;
	uint32_t qid = mon_and_fence_info->queue_id;
	uint8_t fence_gate_val = mon_and_fence_info->mon_payload;
	bool cmdq_fence = mon_and_fence_info->cmdq_fence;

	if (mon_and_fence_info->mon_address)
		address = mon_and_fence_info->mon_address;
	else
		address = gaudi2_get_fence_addr(fd, qid, cmdq_fence);

	mon_info.mon_address = address;
	mon_info.sob_val = mon_and_fence_info->sob_val;
	mon_info.mon_payload = mon_and_fence_info->mon_payload;
	mon_info.sob_id = mon_and_fence_info->sob_id;
	mon_info.mon_id = mon_and_fence_info->mon_id;
	mon_info.num_writes = mon_and_fence_info->num_writes;
	mon_info.long_mode = mon_and_fence_info->long_mode;

	buf_off = gaudi2_add_monitor(buffer, buf_off, &mon_info);

	/* Fence packet */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.fence.dec_val = mon_and_fence_info->dec_fence ? fence_gate_val : 0;
	pkt_info.fence.gate_val = fence_gate_val;
	pkt_info.fence.fence_id = 0;
	buf_off = gaudi2_add_fence_pkt(buffer, buf_off, &pkt_info);

	return buf_off;
}

static int gaudi2_get_arb_cfg_reg_off(uint32_t queue_id, uint32_t *cfg_offset,
		uint32_t *wrr_cfg_offset, uint32_t *arb_mst_quiet)
{
	switch (queue_id) {
	case GAUDI2_QUEUE_ID_PDMA_0_0:
	case GAUDI2_QUEUE_ID_PDMA_0_1:
	case GAUDI2_QUEUE_ID_PDMA_0_2:
	case GAUDI2_QUEUE_ID_PDMA_0_3:
		*cfg_offset = mmPDMA0_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmPDMA0_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmPDMA0_QM_ARB_MST_QUIET_PER;
		break;
	case GAUDI2_QUEUE_ID_PDMA_1_0:
	case GAUDI2_QUEUE_ID_PDMA_1_1:
	case GAUDI2_QUEUE_ID_PDMA_1_2:
	case GAUDI2_QUEUE_ID_PDMA_1_3:
		*cfg_offset = mmPDMA1_QM_ARB_CFG_0;
		*wrr_cfg_offset = mmPDMA1_QM_ARB_WRR_WEIGHT_0;
		*arb_mst_quiet = mmPDMA1_QM_ARB_MST_QUIET_PER;
		break;
	default:
		printf("QMAN id %u does not support arbitration\n", queue_id);
		return -EINVAL;
	}

	return 0;
}

static uint32_t gaudi2_add_arb_en_pkt(void *buffer, uint32_t buf_off,
				     struct hltests_pkt_info *pkt_info,
				     struct hltests_arb_info *arb_info,
				     uint32_t queue_id, bool enable)
{
	uint32_t i, arb_reg_off, arb_wrr_reg_off, arb_mst_quiet_off;
	int rc;

	rc = gaudi2_get_arb_cfg_reg_off(queue_id, &arb_reg_off,
			&arb_wrr_reg_off, &arb_mst_quiet_off);
	if (rc)
		return buf_off;

	/* Set all QMAN Arbiter arb/master/enable */
	pkt_info->msg_long.value = !!arb_info->arb << 0 | 1 << 4 | enable << 8;
	pkt_info->msg_long.address = CFG_BASE + arb_reg_off;

	buf_off = gaudi2_add_msg_long_pkt(buffer, buf_off, pkt_info);

	/* Set QMAN quiet period Between Grants */
	pkt_info->msg_long.value = arb_info->arb_mst_quiet_val;
	pkt_info->msg_long.address = CFG_BASE + arb_mst_quiet_off;

	buf_off = gaudi2_add_msg_long_pkt(buffer, buf_off, pkt_info);

	if (arb_info->arb == ARB_PRIORITY)
		return buf_off;

	for (i = 0 ; i < NUM_OF_STREAMS ; i++) {
		pkt_info->msg_long.value = arb_info->weight[i];
		pkt_info->msg_long.address =
				CFG_BASE + arb_wrr_reg_off + (4 * i);

		buf_off = gaudi2_add_msg_long_pkt(buffer, buf_off, pkt_info);
	}

	return buf_off;
}

static uint32_t gaudi2_add_cq_config_pkt(void *buffer, uint32_t buf_off,
					struct hltests_cq_config *cq_config)
{
	struct hltests_pkt_info pkt_info = {};
	uint64_t msix_db_reg = mmPCIE_MSIX_BASE;
	uint32_t offset;

	offset = cq_config->cq_id * 4;
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;

	/* Configure CQ Address */
	pkt_info.msg_long.value = (uint32_t) cq_config->cq_address;
	pkt_info.msg_long.address =
		CFG_BASE + mmDCORE0_SYNC_MNGR_GLBL_CQ_BASE_ADDR_L_0 + offset;
	buf_off = gaudi2_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = cq_config->cq_address >> 32;
	pkt_info.msg_long.address =
		CFG_BASE + mmDCORE0_SYNC_MNGR_GLBL_CQ_BASE_ADDR_H_0 + offset;
	buf_off = gaudi2_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = cq_config->cq_size_log2;
	pkt_info.msg_long.address =
		CFG_BASE + mmDCORE0_SYNC_MNGR_GLBL_CQ_SIZE_LOG2_0 + offset;
	buf_off = gaudi2_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	/* Configure CQ LBW Address */
	pkt_info.msg_long.value = (uint32_t) msix_db_reg;
	pkt_info.msg_long.address =
		CFG_BASE + mmDCORE0_SYNC_MNGR_GLBL_LBW_ADDR_L_0 + offset;
	buf_off = gaudi2_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = msix_db_reg >> 32;
	pkt_info.msg_long.address =
		CFG_BASE + mmDCORE0_SYNC_MNGR_GLBL_LBW_ADDR_H_0 + offset;
	buf_off = gaudi2_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = cq_config->interrupt_id;
	pkt_info.msg_long.address =
		CFG_BASE + mmDCORE0_SYNC_MNGR_GLBL_LBW_DATA_0 + offset;
	buf_off = gaudi2_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	/* Configure CQ mode - “0”: 32 bits, “1”: 64 bits with data increment */
	pkt_info.msg_long.value = !!cq_config->inc_mode ? 0x1 : 0x0;
	pkt_info.msg_long.address =
		CFG_BASE + mmDCORE0_SYNC_MNGR_GLBL_CQ_INC_MODE_0 + offset;
	buf_off = gaudi2_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	return buf_off;
}

static uint32_t gaudi2_get_dma_down_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			enum hltests_stream_id stream)
{
	return GAUDI2_QUEUE_ID_PDMA_0_0 + stream;
}

static uint32_t gaudi2_get_dma_up_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			enum hltests_stream_id stream)
{
	return GAUDI2_QUEUE_ID_PDMA_1_0 + stream;
}

static uint8_t gaudi2_get_ddma_cnt(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode)
{
	struct hlthunk_hw_ip_info hw_ip;
	int rc;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	return (uint8_t)__builtin_popcount(hw_ip.edma_enabled_mask);
}

static uint32_t gaudi2_get_ddma_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			int ch,
			enum hltests_stream_id stream)
{
	assert_in_range(ch, 0, gaudi2_get_ddma_cnt(fd, dcore_sep_mode) - 1);

	switch (ch) {
	case 0: return GAUDI2_QUEUE_ID_DCORE0_EDMA_0_0 + stream;
	case 1: return GAUDI2_QUEUE_ID_DCORE0_EDMA_1_0 + stream;
	case 2: return GAUDI2_QUEUE_ID_DCORE1_EDMA_0_0 + stream;
	case 3: return GAUDI2_QUEUE_ID_DCORE1_EDMA_1_0 + stream;
	case 4: return GAUDI2_QUEUE_ID_DCORE2_EDMA_0_0 + stream;
	case 5: return GAUDI2_QUEUE_ID_DCORE2_EDMA_1_0 + stream;
	case 6: return GAUDI2_QUEUE_ID_DCORE3_EDMA_0_0 + stream;
	case 7: return GAUDI2_QUEUE_ID_DCORE3_EDMA_1_0 + stream;
	default:
		break;
	}

	return GAUDI2_QUEUE_ID_SIZE;
}

static uint8_t gaudi2_get_tpc_cnt(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode)
{
	return NUM_DCORE0_TPC + NUM_DCORE1_TPC + NUM_DCORE2_TPC + NUM_DCORE3_TPC;
}

static uint32_t gaudi2_get_tpc_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			uint8_t tpc_id, enum hltests_stream_id stream)
{
	uint8_t dcore, instance;
	uint32_t qid_base;

	if (tpc_id == (gaudi2_get_tpc_cnt(fd, DCORE_MODE_FULL_CHIP) - 1))
		return GAUDI2_QUEUE_ID_DCORE0_TPC_6_0 + stream;

	dcore = tpc_id / NUM_OF_TPC_PER_DCORE;
	instance = tpc_id - (dcore * NUM_OF_TPC_PER_DCORE);

	switch (dcore) {
	case 0:
		qid_base = GAUDI2_QUEUE_ID_DCORE0_TPC_0_0;
		break;
	case 1:
		qid_base = GAUDI2_QUEUE_ID_DCORE1_TPC_0_0;
		break;
	case 2:
		qid_base = GAUDI2_QUEUE_ID_DCORE2_TPC_0_0;
		break;
	case 3:
		qid_base = GAUDI2_QUEUE_ID_DCORE3_TPC_0_0;
		break;
	default:
		printf("invalid tpc_id %d\n", tpc_id);
		return GAUDI2_QUEUE_ID_SIZE;
	}

	return qid_base + (NUM_OF_PQ_PER_QMAN * instance) + stream;
}

static uint32_t gaudi2_get_mme_qid(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			uint8_t mme_id,	enum hltests_stream_id stream)
{
	switch (mme_id) {
	case 0: return GAUDI2_QUEUE_ID_DCORE0_MME_0_0 + stream;
	case 1: return GAUDI2_QUEUE_ID_DCORE1_MME_0_0 + stream;
	case 2: return GAUDI2_QUEUE_ID_DCORE2_MME_0_0 + stream;
	case 3: return GAUDI2_QUEUE_ID_DCORE3_MME_0_0 + stream;
	default:
		printf("invalid mme_id %d\n", mme_id);
		return GAUDI2_QUEUE_ID_SIZE;
	}
}

#define NUM_MME_PER_DCORE	1

static uint8_t gaudi2_get_mme_cnt(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			bool master_slave_mode)
{
	return NUM_MME_PER_DCORE * NUM_OF_DCORES;
}

static uint16_t gaudi2_get_first_avail_sob(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hlthunk_sync_manager_info info = {0};

	hlthunk_get_sync_manager_info(fd, 0, &info);

	return info.first_available_sync_object + hdev->counters.reserved_sobs;
}

static uint16_t gaudi2_get_first_avail_mon(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hlthunk_sync_manager_info info = {0};

	hlthunk_get_sync_manager_info(fd, 0, &info);

	return info.first_available_monitor + hdev->counters.reserved_mons;
}

static uint16_t gaudi2_get_first_avail_cq(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hlthunk_sync_manager_info info = {0};

	hlthunk_get_sync_manager_info(fd, 0, &info);

	return info.first_available_cq + hdev->counters.reserved_cqs;
}

static uint64_t gaudi2_get_sob_base_addr(int fd)
{
	return CFG_BASE + mmDCORE0_SYNC_MNGR_OBJS_SOB_OBJ_0;
}

static uint16_t gaudi2_get_cache_line_size(void)
{
	return DEVICE_CACHE_LINE_SIZE;
}

static int gaudi2_asic_priv_init(struct hltests_device *hdev)
{
	struct hlthunk_hw_ip_info hw_ip;
	struct gaudi2_priv *gaudi2;
	int rc;

	rc = hlthunk_get_hw_ip_info(hdev->fd, &hw_ip);
	assert_int_equal(rc, 0);

	hdev->sim_dram_on_host = false;

	hdev->priv = hlthunk_malloc(sizeof(struct gaudi2_priv));
	assert_non_null(hdev->priv);

	gaudi2 = hdev->priv;

	return 0;
}

static void gaudi2_asic_priv_fini(struct hltests_device *hdev)
{
	struct gaudi2_priv *gaudi2 = hdev->priv;

	if (!gaudi2)
		return;

	hlthunk_free(hdev->priv);
	hdev->priv = NULL;
}

static int gaudi2_asic_priv_nic_init(struct hltests_device *hdev)
{
	return 0;
}

static int gaudi2_dram_pool_alloc(struct hltests_device *hdev, uint64_t size,
				uint64_t *return_addr)
{
	return -EFAULT;
}

static void gaudi2_dram_pool_free(struct hltests_device *hdev, uint64_t addr,
					uint64_t size)
{

}

static int gaudi2_get_default_cfg(void *cfg, enum hltests_id id)
{
	return 0;
}

static int gaudi2_submit_cs(int fd, struct hltests_cs_chunk *restore_arr,
		uint32_t restore_arr_size, struct hltests_cs_chunk *execute_arr,
		uint32_t execute_arr_size, uint32_t flags, uint32_t timeout,
		uint64_t *seq)
{
	return hltests_submit_legacy_cs(fd, restore_arr,
			restore_arr_size, execute_arr, execute_arr_size,
			flags, timeout, seq);
}

static int gaudi2_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us)
{
	return hltests_wait_for_legacy_cs(fd, seq, timeout_us);
}

static int gaudi2_wait_for_cs_until_not_busy(int fd, uint64_t seq)
{
	int status;

	if (hltests_is_legacy_mode_enabled(fd))
		do {
			status = gaudi2_wait_for_cs(fd, seq, WAIT_FOR_CS_DEFAULT_TIMEOUT);
		} while (status == HL_WAIT_CS_STATUS_BUSY);
	else
		status = gaudi2_wait_for_cs(fd, seq, WAIT_FOR_CS_DEFAULT_TIMEOUT_NON_LEGACY);

	return status;
}

static int gaudi2_get_max_pll_idx(void)
{
	return HL_GAUDI2_PLL_MAX;
}

static const char *gaudi2_stringify_pll_idx(uint32_t pll_idx)
{
	switch (pll_idx) {
	case HL_GAUDI2_CPU_PLL: return "HL_GAUDI2_CPU_PLL";
	case HL_GAUDI2_PCI_PLL: return "HL_GAUDI2_PCI_PLL";
	case HL_GAUDI2_SRAM_PLL: return "HL_GAUDI2_SRAM_PLL";
	case HL_GAUDI2_HBM_PLL: return "HL_GAUDI2_HBM_PLL";
	case HL_GAUDI2_NIC_PLL: return "HL_GAUDI2_NIC_PLL";
	case HL_GAUDI2_DMA_PLL: return "HL_GAUDI2_DMA_PLL";
	case HL_GAUDI2_MESH_PLL: return "HL_GAUDI2_MESH_PLL";
	case HL_GAUDI2_MME_PLL: return "HL_GAUDI2_MME_PLL";
	case HL_GAUDI2_TPC_PLL: return "HL_GAUDI2_TPC_PLL";
	case HL_GAUDI2_IF_PLL: return "HL_GAUDI2_IF_PLL";
	case HL_GAUDI2_VID_PLL: return "HL_GAUDI2_VID_PLL";
	case HL_GAUDI2_MSS_PLL: return "HL_GAUDI2_MSS_PLL";
	default: return "INVALID_PLL_INDEX";
	}
}

static const char *gaudi2_stringify_pll_type(uint32_t pll_idx, uint8_t type_idx)
{
	switch (pll_idx) {
	case HL_GAUDI2_CPU_PLL:
		switch (type_idx) {
		case 0: return "CPU_CLK|PSOC_HBW_CLK|PSOC_LBW_CLK";
		case 1: return "CPU_LBW_CLK";
		case 2: return "PSOC_CFG_CLK|PSOC_DBG_CLK|PMMU_DBG_CLK";
		case 3: return "CPU_TS_CLK|PSOC_UART_CLK|PSOC_SPI_CLK|PSOC_I2C_CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI2_PCI_PLL:
		switch (type_idx) {
		case 0: return "PCI_LBW_CLK|PMMU_LBW_CLK|XDMA_CLK";
		case 1: return "PCI_TRACE_CLK|PMMU_TRACE_CLK|XDMA_TRACE_CLK";
		case 2: return "PMMU_DBG_CLK|PCI_DBG_CLK|XDMA_DBG_CLK|PCI_AUX_CLK";
		case 3: return "PCI_PHY_CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI2_MESH_PLL:
	case HL_GAUDI2_MME_PLL:
	case HL_GAUDI2_TPC_PLL:
	case HL_GAUDI2_IF_PLL:
	case HL_GAUDI2_HBM_PLL:
	case HL_GAUDI2_DMA_PLL:
	case HL_GAUDI2_VID_PLL:
	case HL_GAUDI2_MSS_PLL:
		switch (type_idx) {
		case 0: return "HBW_CLK";
		case 1: return "LBW_CLK";
		case 2: return "TRACE_CLK";
		case 3: return "DBG_CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI2_NIC_PLL:
		switch (type_idx) {
		case 0: return "PRT_HBW_CLK";
		case 1: return "PRT_LBW_CLK|NIC_CLK";
		case 2: return "PRT_TRACE_CLK";
		case 3: return "PRT_ANK_CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI2_SRAM_PLL:
		switch (type_idx) {
		case 0: return "HBW_CLK";
		case 1 ... 3: return "NA";
		default: return "INVALID_REQ";
		}
	default: return "INVALID_PLL_INDEX";
	}
}

uint64_t gaudi2_get_dram_va_hint_mask(void)
{
	return DRAM_VA_HINT_MASK;
}

uint64_t gaudi2_get_dram_va_reserved_addr_start(void)
{
	return RESERVED_VA_RANGE_FOR_ARC_ON_HBM_START;
}

static uint32_t gaudi2_get_sob_id(uint32_t base_addr_off)
{
	return 0;
}

static uint16_t gaudi2_get_mon_cnt_per_dcore(void)
{
	return (((mmDCORE0_SYNC_MNGR_OBJS_MON_STATUS_2047 -
			mmDCORE0_SYNC_MNGR_OBJS_MON_STATUS_0) + 4) >> 2);
}

static int gaudi2_get_stream_master_qid_arr(uint32_t **qid_arr)
{
	return -1;
}

static uint64_t gaudi2_get_tc_base_addr(uint32_t core_id)
{
	switch (core_id) {
	case 0: return mmDCORE0_DEC0_CMD_BASE;
	case 1: return mmDCORE0_DEC1_CMD_BASE;
	case 2: return mmDCORE1_DEC0_CMD_BASE;
	case 3: return mmDCORE1_DEC1_CMD_BASE;
	case 4: return mmDCORE2_DEC0_CMD_BASE;
	case 5: return mmDCORE2_DEC1_CMD_BASE;
	case 6: return mmDCORE3_DEC0_CMD_BASE;
	case 7: return mmDCORE3_DEC1_CMD_BASE;
	case 8: return mmPCIE_DEC0_CMD_BASE;
	case 9: return mmPCIE_DEC1_CMD_BASE;
	default: return 0;
	}
}

static int gaudi2_get_async_event_id(enum hltests_async_event_id hltests_event_id,
					uint32_t *asic_event_id)
{
	switch (hltests_event_id) {
	case FIX_POWER_ENV_S:
		*asic_event_id = GAUDI2_EVENT_CPU_FIX_POWER_ENV_S;
		break;

	case FIX_POWER_ENV_E:
		*asic_event_id = GAUDI2_EVENT_CPU_FIX_POWER_ENV_E;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static uint32_t gaudi2_get_cq_patch_size(uint32_t qid)
{
	/* TODO - implementation is possible once needed */
	return 0;
}

static uint32_t gaudi2_pdma_get_max_ch_id(int fd)
{
	return 0;
}

uint32_t gaudi2_get_max_pkt_size(int fd, bool mb, bool eb, uint32_t qid)
{
	return sizeof(struct packet_lin_dma);
}

static uint16_t gaudi2_cq_db_get_available_sob(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct sm_global_counters *cnt =  &hdev->counters;
	uint16_t sob = hltests_get_first_avail_sob(fd);

	cnt->reserved_sobs++;

	return sob;
}

static uint16_t gaudi2_cq_db_get_available_mon(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct sm_global_counters *cnt =  &hdev->counters;
	uint16_t mon = hltests_get_first_avail_mon(fd);

	cnt->reserved_mons++;

	return mon;
}

static uint16_t gaudi2_cq_db_get_available_cq(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct sm_global_counters *cnt =  &hdev->counters;
	uint16_t sob = hltests_get_first_avail_cq(fd);

	cnt->reserved_cqs++;

	return sob;
}

static const struct hltests_asic_funcs gaudi2_funcs = {
	.add_arb_en_pkt = gaudi2_add_arb_en_pkt,
	.add_cq_config_pkt = gaudi2_add_cq_config_pkt,
	.add_monitor_and_fence = gaudi2_add_monitor_and_fence,
	.add_monitor = gaudi2_add_monitor,
	.get_fence_addr = gaudi2_get_fence_addr,
	.add_nop_pkt = gaudi2_add_nop_pkt,
	.add_msg_barrier_pkt = gaudi2_add_msg_barrier_pkt,
	.add_wreg32_pkt = gaudi2_add_wreg32_pkt,
	.add_arb_point_pkt = gaudi2_add_arb_point_pkt,
	.add_msg_long_pkt = gaudi2_add_msg_long_pkt,
	.add_msg_short_pkt = gaudi2_add_msg_short_pkt,
	.add_arm_monitor_pkt = gaudi2_add_arm_monitor_pkt,
	.add_write_to_sob_pkt = gaudi2_add_write_to_sob_pkt,
	.add_fence_pkt = gaudi2_add_fence_pkt,
	.add_dma_pkt = gaudi2_add_dma_pkt,
	.add_cp_dma_pkt = gaudi2_add_cp_dma_pkt,
	.add_cb_list_pkt = gaudi2_add_cb_list_pkt,
	.add_load_and_exe_pkt = gaudi2_add_load_and_exe_pkt,
	.get_dma_down_qid = gaudi2_get_dma_down_qid,
	.get_dma_up_qid = gaudi2_get_dma_up_qid,
	.get_ddma_qid = gaudi2_get_ddma_qid,
	.get_ddma_cnt = gaudi2_get_ddma_cnt,
	.get_tpc_qid = gaudi2_get_tpc_qid,
	.get_mme_qid = gaudi2_get_mme_qid,
	.get_tpc_cnt = gaudi2_get_tpc_cnt,
	.get_mme_cnt = gaudi2_get_mme_cnt,
	.get_first_avail_sob = gaudi2_get_first_avail_sob,
	.get_first_avail_mon = gaudi2_get_first_avail_mon,
	.get_first_avail_cq = gaudi2_get_first_avail_cq,
	.get_sob_base_addr = gaudi2_get_sob_base_addr,
	.get_cache_line_size = gaudi2_get_cache_line_size,
	.asic_priv_init = gaudi2_asic_priv_init,
	.asic_priv_fini = gaudi2_asic_priv_fini,
	.dram_pool_alloc = gaudi2_dram_pool_alloc,
	.dram_pool_free = gaudi2_dram_pool_free,
	.get_default_cfg = gaudi2_get_default_cfg,
	.submit_cs = gaudi2_submit_cs,
	.wait_for_cs = gaudi2_wait_for_cs,
	.wait_for_cs_until_not_busy = gaudi2_wait_for_cs_until_not_busy,
	.get_max_pll_idx = gaudi2_get_max_pll_idx,
	.stringify_pll_idx = gaudi2_stringify_pll_idx,
	.stringify_pll_type = gaudi2_stringify_pll_type,
	.get_dram_va_hint_mask = gaudi2_get_dram_va_hint_mask,
	.get_dram_va_reserved_addr_start = gaudi2_get_dram_va_reserved_addr_start,
	.get_sob_id = gaudi2_get_sob_id,
	.get_mon_cnt_per_dcore = gaudi2_get_mon_cnt_per_dcore,
	.get_stream_master_qid_arr = gaudi2_get_stream_master_qid_arr,
	.get_tc_base_addr = gaudi2_get_tc_base_addr,
	.get_async_event_id = gaudi2_get_async_event_id,
	.get_cq_patch_size = gaudi2_get_cq_patch_size,
	.get_max_pkt_size = gaudi2_get_max_pkt_size,
	.add_direct_write_cq_pkt = NULL,
	.monitor_dma_test_progress = NULL,
	.cq_db_get_available_sob = gaudi2_cq_db_get_available_sob,
	.cq_db_get_available_mon = gaudi2_cq_db_get_available_mon,
	.cq_db_get_available_cq = gaudi2_cq_db_get_available_cq,
	.mme_dma_init = NULL,
};

void gaudi2_tests_set_asic_funcs(struct hltests_device *hdev)
{
	hdev->asic_funcs = &gaudi2_funcs;
}
