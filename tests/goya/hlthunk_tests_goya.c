// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "goya/goya.h"
#include "goya/goya_packets.h"
#include "goya/asic_reg/goya_regs.h"
#include "goya/goya_async_events.h"

#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define mmSYNC_MNGR_MON_STATUS_0                                     0x114000
#define mmSYNC_MNGR_MON_STATUS_255                                   0x1143FC

static uint32_t goya_add_nop_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_nop packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_NOP;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;

	packet.ctl = htole32(packet.ctl);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t goya_add_msg_barrier_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	/* Not supported in Goya */
	return buf_off;
}

static uint32_t goya_add_wreg32_pkt(void *buffer, uint32_t buf_off,
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

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t goya_add_arb_point_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	return buf_off;
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

	memset(&packet, 0, sizeof(packet));
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
	packet.memset_mode = pkt_info->dma.memset;

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

static uint32_t goya_add_cb_list_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	return 0;
}

static uint32_t goya_add_load_and_exe_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	return 0;
}

static uint64_t goya_get_fence_addr(int fd, uint32_t qid, bool cmdq_fence)
{
	uint64_t fence_addr = 0;

	switch (qid) {
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
		printf("Failed to configure fence - invalid QID %d\n", qid);
		fail();
	}

	return CFG_BASE + fence_addr;
}

static uint32_t goya_add_monitor(void *buffer, uint32_t buf_off,
			struct hltests_monitor *mon_info)
{
	uint64_t address, monitor_base;
	uint16_t msg_addr_offset;
	struct hltests_pkt_info pkt_info;
	uint8_t base = 0; /* monitor base address */
	uint8_t fence_gate_val = mon_info->mon_payload;

	address = mon_info->mon_address;

	/* monitor_base should be the content of the base0 address registers,
	 * so it will be added to the msg short offsets
	 */
	monitor_base = mmSYNC_MNGR_MON_PAY_ADDRL_0;

	/* First monitor config packet: low address of the sync */
	msg_addr_offset = (mmSYNC_MNGR_MON_PAY_ADDRL_0 +
			mon_info->mon_id * 4) - monitor_base;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_short.base = base;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = (uint32_t) address;
	buf_off = goya_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	/* Second config packet: high address of the sync */
	msg_addr_offset = (mmSYNC_MNGR_MON_PAY_ADDRH_0 +
				mon_info->mon_id * 4) - monitor_base;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_short.base = base;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = (uint32_t) (address >> 32);
	buf_off = goya_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	/* Third config packet: the payload, i.e. what to write when the sync
	 * triggers
	 */
	msg_addr_offset = (mmSYNC_MNGR_MON_PAY_DATA_0 +
				mon_info->mon_id * 4) - monitor_base;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_short.base = base;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = fence_gate_val;
	buf_off = goya_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	if (mon_info->avoid_arm_mon)
		goto out;

	/* Fourth config packet: bind the monitor to a sync object */
	msg_addr_offset = (mmSYNC_MNGR_MON_ARM_0 +
				mon_info->mon_id * 4) - monitor_base;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.arm_monitor.address = msg_addr_offset;
	pkt_info.arm_monitor.mon_mode = EQUAL;
	pkt_info.arm_monitor.sob_val = mon_info->sob_val;
	pkt_info.arm_monitor.sob_id = mon_info->sob_id;
	buf_off = goya_add_arm_monitor_pkt(buffer, buf_off, &pkt_info);

out:
	return buf_off;
}

static uint32_t goya_add_monitor_and_fence(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			void *buffer, uint32_t buf_off,
			struct hltests_monitor_and_fence *mon_and_fence_info)
{
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor mon_info = {0};
	uint64_t address;
	uint8_t fence_gate_val = mon_and_fence_info->mon_payload;
	bool cmdq_fence = mon_and_fence_info->cmdq_fence;

	if (mon_and_fence_info->mon_address)
		address = mon_and_fence_info->mon_address;
	else
		address = goya_get_fence_addr(fd, mon_and_fence_info->queue_id, cmdq_fence);

	mon_info.mon_address = address;
	mon_info.sob_val = mon_and_fence_info->sob_val;
	mon_info.mon_payload = mon_and_fence_info->mon_payload;
	mon_info.sob_id = mon_and_fence_info->sob_id;
	mon_info.mon_id = mon_and_fence_info->mon_id;

	buf_off = goya_add_monitor(buffer, buf_off, &mon_info);

	/* Fence packet */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.fence.dec_val = mon_and_fence_info->dec_fence ? fence_gate_val : 0;
	pkt_info.fence.gate_val = fence_gate_val;
	pkt_info.fence.fence_id = 0;
	buf_off = goya_add_fence_pkt(buffer, buf_off, &pkt_info);

	return buf_off;
}

static uint32_t goya_add_arb_en_pkt(void *buffer, uint32_t buf_off,
				    struct hltests_pkt_info *pkt_info,
				    struct hltests_arb_info *arb_info,
				    uint32_t queue_id, bool enable)
{
	return buf_off;
}

static uint32_t goya_add_cq_config_pkt(void *buffer, uint32_t buf_off,
					struct hltests_cq_config *cq_config)
{
	return buf_off;
}

static uint32_t goya_get_dma_down_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			enum hltests_stream_id stream)
{
	return GOYA_QUEUE_ID_DMA_1;
}

static uint32_t goya_get_dma_up_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			enum hltests_stream_id stream)
{
	return GOYA_QUEUE_ID_DMA_2;
}

static uint32_t goya_get_ddma_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			int ch,
			enum hltests_stream_id stream)
{
	return GOYA_QUEUE_ID_DMA_3 + ch;
}

static uint8_t goya_get_ddma_cnt(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode)
{
	return 2;
}

static uint32_t goya_get_tpc_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			uint8_t tpc_id,	enum hltests_stream_id stream)
{
	return GOYA_QUEUE_ID_TPC0 + tpc_id;
}

static uint32_t goya_get_mme_qid(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			uint8_t mme_id, enum hltests_stream_id stream)
{
	return GOYA_QUEUE_ID_MME;
}

static uint8_t goya_get_tpc_cnt(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode)
{
	return TPC_MAX_NUM;
}

static uint8_t goya_get_mme_cnt(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			bool master_slave_mode)
{
	return MME_MAX_NUM;
}

static uint16_t goya_get_first_avail_sob(int fd)
{
	struct hlthunk_sync_manager_info info = {0};

	hlthunk_get_sync_manager_info(fd, 0, &info);

	return info.first_available_sync_object;
}

static uint16_t goya_get_first_avail_mon(int fd)
{
	struct hlthunk_sync_manager_info info = {0};

	hlthunk_get_sync_manager_info(fd, 0, &info);

	return info.first_available_sync_object;
}

static uint16_t goya_get_first_avail_cq(int fd)
{
	struct hlthunk_sync_manager_info info = {0};

	hlthunk_get_sync_manager_info(fd, 0, &info);

	return info.first_available_cq;
}

static uint64_t goya_get_sob_base_addr(int fd)
{
	return CFG_BASE + mmSYNC_MNGR_SOB_OBJ_0;
}

static int goya_asic_priv_init(struct hltests_device *hdev)
{
	return 0;
}

static void goya_asic_priv_fini(struct hltests_device *hdev)
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

int goya_submit_cs(int fd, struct hltests_cs_chunk *restore_arr,
		uint32_t restore_arr_size, struct hltests_cs_chunk *execute_arr,
		uint32_t execute_arr_size, uint32_t flags, uint32_t timeout,
		uint64_t *seq)
{
	return hltests_submit_legacy_cs(fd, restore_arr, restore_arr_size,
				execute_arr, execute_arr_size, flags, timeout,
				seq);
}

int goya_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us)
{
	return hltests_wait_for_legacy_cs(fd, seq, timeout_us);
}

static int goya_wait_for_cs_until_not_busy(int fd, uint64_t seq)
{
	int status;

	do {
		status = goya_wait_for_cs(fd, seq, WAIT_FOR_CS_DEFAULT_TIMEOUT);
	} while (status == HL_WAIT_CS_STATUS_BUSY);

	return status;
}

static int goya_get_max_pll_idx(void)
{
	return HL_GOYA_PLL_MAX;
}

static const char *goya_stringify_pll_idx(uint32_t pll_idx)
{
	switch (pll_idx) {
	case HL_GOYA_CPU_PLL: return "HL_GOYA_CPU_PLL";
	case HL_GOYA_IC_PLL: return "HL_GOYA_IC_PLL";
	case HL_GOYA_MC_PLL: return "HL_GOYA_MC_PLL";
	case HL_GOYA_MME_PLL: return "HL_GOYA_MME_PLL";
	case HL_GOYA_PCI_PLL: return "HL_GOYA_PCI_PLL";
	case HL_GOYA_EMMC_PLL: return "HL_GOYA_EMMC_PLL";
	case HL_GOYA_TPC_PLL: return "HL_GOYA_TPC_PLL";
	default: return "INVALID_PLL_INDEX";
	}
}

static const char *goya_stringify_pll_type(uint32_t pll_idx, uint8_t type_idx)
{
	switch (pll_idx) {
	case HL_GOYA_CPU_PLL:
		switch (type_idx) {
		case 0: return "CPU_CLK";
		case 1: return "CPU_CFG_CLK";
		case 2: return "DMA_LBW_CLK";
		case 3: return "NA";
		default: return "INVALID_REQ";
		}
	case HL_GOYA_IC_PLL:
	case HL_GOYA_MME_PLL:
		switch (type_idx) {
		case 0: return "HBW_CLK";
		case 1: return "LBW_CLK";
		case 2: return "TRACE_CLK";
		case 3: return "DBG_CLK";
		default: return "INVALID_REQ";
		}
	case HL_GOYA_MC_PLL:
		switch (type_idx) {
		case 0: return "MC_CLK";
		case 1 ... 3: return "NA";
		default: return "INVALID_REQ";
		}
	case HL_GOYA_PCI_PLL:
		switch (type_idx) {
		case 0: return "PCI_LBW__CLK|PSOC_LBW_CLK";
		case 1: return "PCI_DBG_CLK|PCI_AUX_CLK|EMMC_200_TX_CLK|PSOC_CFG_CLK|PSOC_DBG_CLK";
		case 2: return "PCI_PHY_CLK";
		case 3: return "EMMC_TM_CLK";
		default: return "INVALID_REQ";
		}
	case HL_GOYA_EMMC_PLL:
		switch (type_idx) {
		case 0: return "EMMC_52_TX_CLK";
		case 1: return "EMMC_26_TX_CLK";
		case 2 ... 3: return "NA";
		default: return "INVALID_REQ";
		}
	case HL_GOYA_TPC_PLL:
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

uint64_t goya_get_dram_va_hint_mask(void)
{
	return ULONG_MAX;
}

uint64_t goya_get_dram_va_reserved_addr_start(void)
{
	return 0;
}

static uint32_t goya_get_sob_id(uint32_t base_addr_off)
{
	return 0;
}

static uint16_t goya_get_mon_cnt_per_dcore(void)
{
	return (((mmSYNC_MNGR_MON_STATUS_255 - mmSYNC_MNGR_MON_STATUS_0) + 4) >> 2);
}

static int goya_get_stream_master_qid_arr(uint32_t **qid_arr)
{
	return -1;
}

static int goya_get_async_event_id(enum hltests_async_event_id hltests_event_id,
					uint32_t *asic_event_id)
{
	switch (hltests_event_id) {
	case FIX_POWER_ENV_S:
		*asic_event_id = GOYA_ASYNC_EVENT_ID_FIX_POWER_ENV_S;
		break;

	case FIX_POWER_ENV_E:
		*asic_event_id = GOYA_ASYNC_EVENT_ID_FIX_POWER_ENV_E;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static uint32_t goya_get_cq_patch_size(uint32_t qid)
{
	return 0;
}

static uint32_t goya_get_max_pkt_size(int fd, bool mb, bool eb, uint32_t qid)
{
	return sizeof(struct packet_lin_dma);
}

static const struct hltests_asic_funcs goya_funcs = {
	.add_arb_en_pkt = goya_add_arb_en_pkt,
	.add_cq_config_pkt = goya_add_cq_config_pkt,
	.add_monitor_and_fence = goya_add_monitor_and_fence,
	.add_monitor = goya_add_monitor,
	.get_fence_addr = goya_get_fence_addr,
	.add_nop_pkt = goya_add_nop_pkt,
	.add_msg_barrier_pkt = goya_add_msg_barrier_pkt,
	.add_wreg32_pkt = goya_add_wreg32_pkt,
	.add_arb_point_pkt = goya_add_arb_point_pkt,
	.add_msg_long_pkt = goya_add_msg_long_pkt,
	.add_msg_short_pkt = goya_add_msg_short_pkt,
	.add_arm_monitor_pkt = goya_add_arm_monitor_pkt,
	.add_write_to_sob_pkt = goya_add_write_to_sob_pkt,
	.add_fence_pkt = goya_add_fence_pkt,
	.add_dma_pkt = goya_add_dma_pkt,
	.add_cp_dma_pkt = goya_add_cp_dma_pkt,
	.add_cb_list_pkt = goya_add_cb_list_pkt,
	.add_load_and_exe_pkt = goya_add_load_and_exe_pkt,
	.get_dma_down_qid = goya_get_dma_down_qid,
	.get_dma_up_qid = goya_get_dma_up_qid,
	.get_ddma_qid = goya_get_ddma_qid,
	.get_ddma_cnt = goya_get_ddma_cnt,
	.get_tpc_qid = goya_get_tpc_qid,
	.get_mme_qid = goya_get_mme_qid,
	.get_tpc_cnt = goya_get_tpc_cnt,
	.get_mme_cnt = goya_get_mme_cnt,
	.get_first_avail_sob = goya_get_first_avail_sob,
	.get_first_avail_mon = goya_get_first_avail_mon,
	.get_first_avail_cq = goya_get_first_avail_cq,
	.get_sob_base_addr = goya_get_sob_base_addr,
	.asic_priv_init = goya_asic_priv_init,
	.asic_priv_fini = goya_asic_priv_fini,
	.dram_pool_alloc = goya_dram_pool_alloc,
	.dram_pool_free = goya_dram_pool_free,
	.submit_cs = goya_submit_cs,
	.wait_for_cs = goya_wait_for_cs,
	.wait_for_cs_until_not_busy = goya_wait_for_cs_until_not_busy,
	.get_max_pll_idx = goya_get_max_pll_idx,
	.stringify_pll_idx = goya_stringify_pll_idx,
	.stringify_pll_type = goya_stringify_pll_type,
	.get_dram_va_hint_mask = goya_get_dram_va_hint_mask,
	.get_dram_va_reserved_addr_start = goya_get_dram_va_reserved_addr_start,
	.get_sob_id = goya_get_sob_id,
	.get_mon_cnt_per_dcore = goya_get_mon_cnt_per_dcore,
	.get_stream_master_qid_arr = goya_get_stream_master_qid_arr
};

void goya_tests_set_asic_funcs(struct hltests_device *hdev)
{
	hdev->asic_funcs = &goya_funcs;
}
