// SPDX-License-Identifier: MIT

/*
 * Copyright 2019-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */
#include "gaudi/asic_reg/gaudi_regs.h"
#include "gaudi/gaudi.h"
#include "gaudi/gaudi_async_events.h"
#include "gaudi/gaudi_packets.h"
#include "gaudi_nic.h"
#include "hlthunk.h"
#include "hlthunk_tests.h"
#include "specs/hw_ip/nic/nic_v1_0.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define GAUDI_CQ_SLEEP_USEC 1000

static uint32_t gaudi_nic_get_wq_offset(int fd, int port, uint32_t conn_id)
{
	return 0;
}

static int gaudi_nic_fill_wqe(int fd, void *p_in)
{
	struct hltests_nic_wqe_params *in_params = (struct hltests_nic_wqe_params *) p_in;
	struct sq_wqe *swq = (struct sq_wqe *) in_params->sq_wqe;
	struct rq_wqe *rwq = (struct rq_wqe *) in_params->rq_wqe;

	memset(swq, 0, sizeof(*swq));
	swq->number_of_strides = 0;
	swq->reduction_opcode = 0;
	swq->reserved0 = 0;
	swq->stride_type = 0;
	swq->ackreq = in_params->ackreq || (in_params->cmpl != NONE);
	swq->opcode = WQE_LINEAR;
	swq->local_address_31_0 = in_params->local_address & 0xFFFFFFFF;
	swq->local_address_49_32 = (in_params->local_address >> 32) & 0x3FFFF;
	swq->size = in_params->size;
	swq->remote_address_31_0 = in_params->remote_address & 0xFFFFFFFF;
	swq->remote_address_43_32 = (in_params->remote_address >> 32) & 0x3FFFF;
	swq->stride_size = 0;
	swq->remote_sync_object = (in_params->cmpl & CQ_USR) ? 0 :
				(REMOTE_SOB_ADDR + 4 * in_params->remote_sob_id);
	swq->reserved1 = 0;
	swq->sync_object_valid = in_params->cmpl != NONE;
	swq->remote_sync_object_data = (in_params->cmpl & CQ_USR) ?
						in_params->tag : 0x80000001;
	swq->stride = 0;

	memset(rwq, 0, sizeof(*rwq));
	rwq->local_sync_object_address = LOCAL_SOB_ADDR + 4 * in_params->local_sob_id;
	rwq->reserved = 0;
	rwq->cq_valid = !!(in_params->cmpl & CQ_USR);
	rwq->valid = in_params->cmpl == SOB;
	rwq->local_sync_object_data = 0x80000001;

	return 0;
}

static void *gaudi_nic_get_swqe(void *swq, int offset)
{
	return ((struct sq_wqe *) swq) + offset;
}

static void *gaudi_nic_get_rwqe(void *rwq, int offset)
{
	return ((struct rq_wqe *) rwq) + offset;
}

static uint8_t gaudi_nic_get_swqe_size(void)
{
	return NIC_SEND_WQE_SIZE;
}

static uint8_t gaudi_nic_get_rwqe_size(void)
{
	return NIC_RECV_WQE_SIZE;
}

static uint32_t gaudi_nic_add_bulk_doorbell_pkt(void *buf, uint32_t buf_size,
						int nic, uint64_t conn_id,
						uint64_t db_val)
{
	struct packet_wreg_bulk *bulk_doorbell;

	bulk_doorbell =
		(struct packet_wreg_bulk *) ((uintptr_t) buf + buf_size);
	bulk_doorbell->opcode = PACKET_WREG_BULK;
	bulk_doorbell->eng_barrier = 0;
	bulk_doorbell->reg_barrier = 1;
	bulk_doorbell->msg_barrier = 1;
	bulk_doorbell->size64 = 1;
	bulk_doorbell->values[0] = (conn_id << 22) | db_val;

	return buf_size + sizeof(*bulk_doorbell) + 8;
}

static void gaudi_nic_pre_setup_ctx(int fd, struct hltests_nic_requester_conn_ctx *req_ctx)
{

}

static int gaudi_nic_setup_ctx_lpbk(int fd, int port,
					struct hltests_nic_requester_conn_ctx *req_ctx,
					struct hltests_nic_responder_conn_ctx *res_ctx,
					uint32_t conn, struct hltests_nic_lpbk_cfg *cfg)
{
	return 0;
}

static int gaudi_nic_setup_ctx_e2e(int fd, int port,
					struct hltests_nic_requester_conn_ctx *req_ctx,
					struct hltests_nic_responder_conn_ctx *res_ctx,
					struct hltests_nic_e2e_cfg *cfg)
{
	return 0;
}

static void gaudi_nic_pre_setup_default_ctx_rdv(int fd,
						struct hltests_nic_requester_conn_ctx *req_ctx,
						enum hltests_nic_test_opcode test_opcode,
						bool is_rdv_send, bool swq_granularity)
{

}
static void gaudi_nic_setup_default_ctx_rdv(int fd, int port,
						struct hltests_nic_requester_conn_ctx *req_ctx,
						struct hltests_nic_responder_conn_ctx *res_ctx,
						bool is_rdv_send, uint32_t conn_id,
						bool swq_granularity)
{

}

static uint32_t gaudi_add_nop_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_nop packet = {0};

	packet.opcode = PACKET_NOP;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.reg_barrier = 1;

	packet.ctl = htole32(packet.ctl);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi_add_msg_barrier_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	/* Not supported in Gaudi */
	return buf_off;
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
	packet.base = pkt_info->write_to_sob.base ? 3 : 1;
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

static uint64_t gaudi_get_fence_addr(int fd, uint32_t qid, bool cmdq_fence)
{
	uint64_t fence_addr = 0;

	switch (qid) {
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
	case GAUDI_QUEUE_ID_NIC_0_0:
		fence_addr = mmNIC0_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI_QUEUE_ID_NIC_1_0:
		fence_addr = mmNIC0_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI_QUEUE_ID_NIC_2_0:
		fence_addr = mmNIC1_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI_QUEUE_ID_NIC_3_0:
		fence_addr = mmNIC1_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI_QUEUE_ID_NIC_4_0:
		fence_addr = mmNIC2_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI_QUEUE_ID_NIC_5_0:
		fence_addr = mmNIC2_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI_QUEUE_ID_NIC_6_0:
		fence_addr = mmNIC3_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI_QUEUE_ID_NIC_7_0:
		fence_addr = mmNIC3_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI_QUEUE_ID_NIC_8_0:
		fence_addr = mmNIC4_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI_QUEUE_ID_NIC_9_0:
		fence_addr = mmNIC4_QM1_CP_FENCE0_RDATA_0;
		break;

	default:
		printf("Failed to configure fence - invalid QID %d\n", qid);
		fail();
	}

	return CFG_BASE + fence_addr;
}

static uint32_t gaudi_add_monitor(void *buffer, uint32_t buf_off,
			struct hltests_monitor *mon_info)
{
	uint64_t address, monitor_base;
	uint16_t msg_addr_offset;
	struct hltests_pkt_info pkt_info;
	uint8_t fence_gate_val = mon_info->mon_payload;

	address = mon_info->mon_address;

	/* monitor_base should be the content of the base0 address registers,
	 * so it will be added to the msg short offsets
	 */
	monitor_base = mmSYNC_MNGR_E_N_SYNC_MNGR_OBJS_MON_PAY_ADDRL_0;

	/* First monitor config packet: low address of the sync */
	msg_addr_offset =
		(mmSYNC_MNGR_E_N_SYNC_MNGR_OBJS_MON_PAY_ADDRL_0 +
				mon_info->mon_id * 4) - monitor_base;
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
				mon_info->mon_id * 4) - monitor_base;
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
				mon_info->mon_id * 4) - monitor_base;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_short.base = 0;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = fence_gate_val;
	buf_off = gaudi_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	if (mon_info->avoid_arm_mon)
		goto out;

	/* Fourth config packet: bind the monitor to a sync object */
	msg_addr_offset =
		(mmSYNC_MNGR_E_N_SYNC_MNGR_OBJS_MON_ARM_0 +
				mon_info->mon_id * 4) - monitor_base;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.arm_monitor.address = msg_addr_offset;
	pkt_info.arm_monitor.mon_mode = mon_info->mon_mode;
	pkt_info.arm_monitor.sob_val = mon_info->sob_val;
	pkt_info.arm_monitor.sob_id = mon_info->sob_id;
	buf_off = gaudi_add_arm_monitor_pkt(buffer, buf_off, &pkt_info);

out:
	return buf_off;
}

static uint32_t gaudi_add_monitor_and_fence(int fd,
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
		address = gaudi_get_fence_addr(fd, mon_and_fence_info->queue_id,
							cmdq_fence);

	mon_info.mon_address = address;
	mon_info.sob_val = mon_and_fence_info->sob_val;
	mon_info.mon_payload = mon_and_fence_info->mon_payload;
	mon_info.sob_id = mon_and_fence_info->sob_id;
	mon_info.mon_id = mon_and_fence_info->mon_id;
	mon_info.mon_mode = mon_and_fence_info->mon_mode;

	buf_off = gaudi_add_monitor(buffer, buf_off, &mon_info);

	/* Fence packet */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.fence.dec_val = mon_and_fence_info->dec_fence ? fence_gate_val : 0;
	pkt_info.fence.gate_val = fence_gate_val;
	pkt_info.fence.fence_id = 0;
	buf_off = gaudi_add_fence_pkt(buffer, buf_off, &pkt_info);

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

static uint32_t gaudi_add_cq_config_pkt(void *buffer, uint32_t buf_off,
					struct hltests_cq_config *cq_config)
{
	return buf_off;
}

static uint32_t gaudi_get_dma_down_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			enum hltests_stream_id stream)
{
	return GAUDI_QUEUE_ID_DMA_0_0 + stream;
}

static uint32_t gaudi_get_dma_up_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			enum hltests_stream_id stream)
{
	return GAUDI_QUEUE_ID_DMA_1_0 + stream;
}

static uint8_t gaudi_get_ddma_cnt(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode)
{
	return DMA_NUMBER_OF_CHANNELS - 2;
}

static uint32_t gaudi_get_ddma_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			int dma_ch,
			enum hltests_stream_id stream)
{
	assert_in_range(dma_ch, 0, gaudi_get_ddma_cnt(fd, dcore_sep_mode) - 1);

	return GAUDI_QUEUE_ID_DMA_2_0 + dma_ch * NUM_OF_STREAMS + stream;
}

static uint32_t gaudi_get_tpc_qid(int fd,
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

static uint32_t gaudi_get_nic_qid(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			uint8_t nic_id, enum hltests_stream_id stream)
{
	return GAUDI_QUEUE_ID_NIC_0_0 + nic_id * NUM_OF_STREAMS + stream;
}

static uint8_t gaudi_get_tpc_cnt(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode)
{
	return TPC_NUMBER_OF_ENGINES;
}

static uint8_t gaudi_get_mme_cnt(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			bool master_slave_mode)
{
	return MME_NUMBER_OF_MASTER_ENGINES;
}

static uint16_t gaudi_get_first_avail_sob(int fd)
{
	struct hlthunk_sync_manager_info info = {0};

	hlthunk_get_sync_manager_info(fd, HL_GAUDI_EN_DCORE, &info);

	return info.first_available_sync_object;
}

static uint16_t gaudi_get_first_avail_mon(int fd)
{
	struct hlthunk_sync_manager_info info = {0};

	hlthunk_get_sync_manager_info(fd, HL_GAUDI_EN_DCORE, &info);

	return info.first_available_monitor;
}

static uint16_t gaudi_get_first_avail_cq(int fd)
{
	struct hlthunk_sync_manager_info info = {0};

	hlthunk_get_sync_manager_info(fd, 0, &info);

	return info.first_available_cq;
}

static uint64_t gaudi_get_sob_base_addr(int fd)
{
	return CFG_BASE + mmSYNC_MNGR_E_N_SYNC_MNGR_OBJS_SOB_OBJ_0;
}

static uint64_t gaudi_get_any_mappable_hw_block_base_addr(int fd)
{
	return 0;
}

static uint16_t gaudi_get_cache_line_size(void)
{
	return DEVICE_CACHE_LINE_SIZE;
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

static int gaudi_va_pool_alloc(struct hltests_device *hdev, uint64_t size, uint64_t *return_addr)
{
	return -EOPNOTSUPP;
}

static void gaudi_va_pool_free(struct hltests_device *hdev, uint64_t addr, uint64_t size)
{

}

int gaudi_submit_cs(int fd, struct hltests_cs_chunk *restore_arr,
		uint32_t restore_arr_size, struct hltests_cs_chunk *execute_arr,
		uint32_t execute_arr_size, uint32_t flags, uint32_t timeout,
		uint64_t *seq)
{
	return hltests_submit_legacy_cs(fd, restore_arr, restore_arr_size,
				execute_arr, execute_arr_size, flags, timeout,
				seq);
}

int gaudi_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us)
{
	return hltests_wait_for_legacy_cs(fd, seq, timeout_us);
}

static int gaudi_wait_for_cs_until_not_busy(int fd, uint64_t seq)
{
	int status;

	do {
		status = gaudi_wait_for_cs(fd, seq, WAIT_FOR_CS_DEFAULT_TIMEOUT);
	} while (status == HL_WAIT_CS_STATUS_BUSY);

	return status;
}

static int gaudi_asic_priv_init(struct hltests_device *hdev)
{
	struct hlthunk_hw_ip_info hw_ip;
	int rc;

	rc = hlthunk_get_hw_ip_info(hdev->fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled)
		return 0;

	hdev->priv = hltests_mem_pool_init(hw_ip.dram_base_address,
						hw_ip.dram_size,
						PAGE_SHIFT_2MB);
	assert_non_null(hdev->priv);

	return 0;
}

static void gaudi_asic_priv_fini(struct hltests_device *hdev)
{
	if (hdev->priv)
		hltests_mem_pool_fini(hdev->priv);
	hdev->priv = NULL;
}

static int gaudi_nic_asic_priv_init(struct hltests_device *hdev, void *arg, uint64_t ctx_port_mask)
{
	return 0;
}

static void *gaudi_cq_th(void *args)
{
	struct hltests_nic_port_cq *port_cq = (struct hltests_nic_port_cq *) args;
	struct hltests_nic_cq *cq = port_cq->thread_params.cq;
	int rc, cqe_cnt = 0, fd = cq->fd, port = port_cq->thread_params.port;
	pthread_spinlock_t *cq_lock = &cq->user_cq.cq_lock;
	struct nic_cqe_raw *cq_hw_arr = port_cq->cq_buf;
	struct nic_cqe_raw *cqe_hw;
	struct hl_nic_cqe *cq_sw_arr = cq->cq_buf, cqe;
	uint32_t hw_ci = 0, user_cq_buf_len = port_cq->cq_buf_len, user_cqe_cnt_local,
		 cq_buf_len = cq->cq_buf_len, cq_pi;
	_Atomic uint32_t *user_cqe_cnt = (_Atomic uint32_t *)&cq->user_cq.cqe_cnt;

	__sync_fetch_and_add(&cq->user_cq.thread_count, 1);

	while (1) {
		cqe_hw = &cq_hw_arr[hw_ci & (user_cq_buf_len - 1)];

		if (!(CQE_IS_VALID(cqe_hw))) {
			/* sleep is needed for pthread_cancel() to stop the thread */
			usleep(GAUDI_CQ_SLEEP_USEC);
			continue;
		}

		/* Make sure we read CQE contents after the valid bit check */
		__sync_synchronize();

		memset(&cqe, 0, sizeof(cqe));
		cqe.port = port;

		if (CQE_TYPE(cqe_hw)) {
			cqe.type = HL_NIC_CQE_TYPE_RES;
			cqe.responder.msg_id = (CQE_RES_IMDT_31_22(cqe_hw) << 22) |
						CQE_RES_IMDT_21_0(cqe_hw);

			/*
			 * the even port publishes its responder CQEs on
			 * the odd port CQ.
			 * take the correct port in this case.
			 */
			if (!CQE_RES_NIC(cqe_hw))
				cqe.port--;
		} else {
			cqe.type = HL_NIC_CQE_TYPE_REQ;
			cqe.requester.wqe_index = CQE_REQ_WQE_IDX(cqe_hw);
			cqe.qp_number = CQE_REQ_QPN(cqe_hw);
		}

		pthread_spin_lock(cq_lock);

		cq_pi = cq->cq_pi++ & (cq_buf_len - 1);
		memcpy(&cq_sw_arr[cq_pi], &cqe, sizeof(cqe));

		user_cqe_cnt_local = atomic_fetch_add(user_cqe_cnt, 1);
		if (user_cqe_cnt_local >= (cq_buf_len - 1))
			printf("CQ overflow, port %d\n", port);

		pthread_spin_unlock(cq_lock);

		CQE_SET_INVALID(cqe_hw);

		/* the H/W CI does wraparound every 32 bit */
		hw_ci++;

		/* update CI once in half cycle */
		if (cqe_cnt++ > (user_cq_buf_len >> 1)) {
			rc = hlthunk_nic_user_cq_update_ci(fd, port, hw_ci);
			if (rc) {
				printf("failed to update CI, port:%d\n", port);
				return NULL;
			}

			cqe_cnt = 0;
		}
	}

	return args;
}

static int gaudi_nic_user_cq_create(int fd, struct hltests_nic_cq *cq)
{
	int i, rc, thread_count = 0;
	pthread_t thread_id;
	uint32_t cq_buf_len;
	void *cq_buf_raw;
	uint32_t size;
	void *cq_buf;

	assert_int_equal(cq->type, HLTESTS_NIC_CQ_TYPE_PORT);

	cq->fd = fd;

	cq->user_cq.port_cq = hlthunk_malloc(NIC_NUMBER_OF_PORTS *
						sizeof(struct hltests_nic_port_cq));
	assert_non_null(cq->user_cq.port_cq);

	cq->cq_buf = calloc(cq->cq_buf_len, sizeof(struct hl_nic_cqe));
	assert_non_null(cq->cq_buf);

	pthread_spin_init(&cq->user_cq.cq_lock, PTHREAD_PROCESS_PRIVATE);
	cq->user_cq.thread_count = 0;

	cq_buf_len = cq->user_cq.cq_buf_len;
	size = cq_buf_len * sizeof(struct nic_cqe_raw);

	for (i = 0 ; i < NIC_NUMBER_OF_PORTS ; i++) {
		if (!(cq->user_cq.port_mask[0] & BIT_ULL(i)))
			continue;

		cq_buf_raw = hlthunk_malloc(size + DEVICE_CACHE_LINE_SIZE);
		assert_non_null(cq_buf_raw);

		cq_buf = (void *) ALIGN_UP((uint64_t) (uintptr_t) cq_buf_raw,
						DEVICE_CACHE_LINE_SIZE);

		/* use the old API so the backward compatibility will be tested regularly in CI */
		rc = hlthunk_nic_user_cq_set(fd, i, (uint64_t) (uintptr_t) cq_buf, cq_buf_len);
		assert_int_equal(rc, 0);

		cq->user_cq.port_cq[i].cq_buf_len = cq_buf_len;
		cq->user_cq.port_cq[i].cq_buf_raw = cq_buf_raw;
		cq->user_cq.port_cq[i].cq_buf = cq_buf;
		cq->user_cq.port_cq[i].port = i;
		cq->user_cq.port_cq[i].thread_params.cq = cq;
		cq->user_cq.port_cq[i].thread_params.port = i;

		rc = pthread_create(&thread_id, NULL, gaudi_cq_th, &cq->user_cq.port_cq[i]);
		assert_int_equal(rc, 0);

		cq->user_cq.port_cq[i].thread_id = thread_id;
		cq->user_cq.port_cq[i].enabled = true;
		thread_count++;
	}

	while (cq->user_cq.thread_count < thread_count)
		usleep(GAUDI_CQ_SLEEP_USEC);

	return 0;
}

static int gaudi_nic_user_cq_destroy(int fd, struct hltests_nic_cq *cq)
{
	struct hltests_nic_port_cq *port_cq = cq->user_cq.port_cq;
	void *retval;
	int rc, i;

	for (i = 0 ; i < NIC_NUMBER_OF_PORTS ; i++) {
		if (!(cq->user_cq.port_mask[0] & BIT_ULL(i)))
			continue;

		rc = pthread_cancel(port_cq[i].thread_id);
		assert_int_equal(rc, 0);
		rc = pthread_join(port_cq[i].thread_id, &retval);
		assert_int_equal(rc, 0);
		assert_true(retval == PTHREAD_CANCELED);
		assert_int_equal(hlthunk_nic_user_cq_unset(fd, i), 0);
		hlthunk_free(port_cq[i].cq_buf_raw);
	}

	pthread_spin_destroy(&cq->user_cq.cq_lock);

	free(cq->cq_buf);
	free(cq->user_cq.port_cq);

	return 0;
}

static int gaudi_nic_get_max_num_of_ports(void)
{
	return NIC_NUMBER_OF_PORTS;
}

static int gaudi_nic_get_min_conn_id(int fd, uint32_t port)
{
	return NIC_MIN_CONN_ID;
}

static int gaudi_nic_get_max_conn_id(int fd, uint32_t port)
{
	return NIC_MAX_CONN_ID;
}

static int gaudi_nic_get_max_num_of_qps(int fd, uint32_t port)
{
	return NIC_MAX_CONN_ID + 1;
}

static uint64_t gaudi_nic_get_port_mask(void)
{
	return GAUDI_NICS_MASK;
}

static uint32_t gaudi_nic_get_base_qid(void)
{
	return GAUDI_QUEUE_ID_NIC_0_0;
}

static int gaudi_nic_get_default_cfg(void *cfg, enum hltests_nic_id id)
{
	struct hltests_nic_lpbk_cfg *lpbk_cfg;
	struct hltests_nic_gen_test_cfg *gen_test_cfg;
	int port;

	switch (id) {
	case HLTESTS_NIC_E2E_LPBK:
		lpbk_cfg = cfg;
		for (port = 0 ; port < MAX_NIC_NUMBER_OF_PORTS ; port++) {
			lpbk_cfg->ports[port] = port;
			lpbk_cfg->qps_per_port[port] = 16;
		}
		lpbk_cfg->ports_num = MAX_NIC_NUMBER_OF_PORTS;
		lpbk_cfg->qps_per_port_num_elements = MAX_NIC_NUMBER_OF_PORTS;
		lpbk_cfg->max_qps_per_port = 16;
		lpbk_cfg->iterations_mem = 4;
		lpbk_cfg->iterations_db = 1;
		lpbk_cfg->cq_buf_len_shift = 20;
		lpbk_cfg->user_cq_buf_len_shift = 18;
		lpbk_cfg->user_cq_idx = 0;
		lpbk_cfg->data_loc = DATA_LOC_ALL;
		lpbk_cfg->wq_loc = WQ_LOC_HOST;
		lpbk_cfg->cmpl = CQ_USR;
		lpbk_cfg->data_size_shift = 18;
		lpbk_cfg->wqe_size_shift = 12;
		lpbk_cfg->data_cmp = true;
		lpbk_cfg->single_alloc = false;
		lpbk_cfg->cleanup = true;
		lpbk_cfg->wait_for_cleanup = false;
		lpbk_cfg->verbose = true;
		lpbk_cfg->db_qman = true;
		lpbk_cfg->wtd_en = false;
		lpbk_cfg->eq_poll = false;
		lpbk_cfg->user_db = false;

		break;

	case HLTESTS_NIC_GEN_TEST:
		gen_test_cfg = cfg;

		if (gen_test_cfg->is_pldm) {
			if (gen_test_cfg->num_threads == 1)
				gen_test_cfg->num_iterations = 2;
			else if (gen_test_cfg->num_threads == 8)
				gen_test_cfg->num_iterations = 2;
			else if (gen_test_cfg->num_threads == 512)
				gen_test_cfg->num_iterations = 0;
			else if (gen_test_cfg->num_threads == 1023)
				gen_test_cfg->num_iterations = 0;
			else
				gen_test_cfg->num_iterations = 2;

		} else {
			if (gen_test_cfg->num_threads == 1)
				gen_test_cfg->num_iterations = 2;
			else if (gen_test_cfg->num_threads == 8)
				gen_test_cfg->num_iterations = 20;
			else if (gen_test_cfg->num_threads == 512)
				gen_test_cfg->num_iterations = 2;
			else if (gen_test_cfg->num_threads == 1023)
				gen_test_cfg->num_iterations = 1;
			else
				gen_test_cfg->num_iterations = 4;

		}
		gen_test_cfg->wq_loc = WQ_LOC_HOST;
		gen_test_cfg->dst_conn_id = 1;
		gen_test_cfg->num_wqs_shift = 10;
		gen_test_cfg->num_wqes_shift = 6;

		break;

	default:
		printf("default cfg not supported for test ID: %d\n", id);
		return -ENOENT;
	}

	return 0;
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

uint64_t gaudi_get_dram_va_hint_mask(void)
{
	return ULONG_MAX;
}

uint64_t gaudi_get_dram_va_reserved_addr_start(void)
{
	return 0;
}

/* WTD is not supported in Gaudi */
static int gaudi_nic_run_wtd(int fd, void *p_in)
{
	printf("WQE to doorbell feature is not supported\n");
	return -ENOTSUP;
}

static uint32_t gaudi_get_sob_id(uint32_t base_addr_off)
{
	return (base_addr_off - (mmSYNC_MNGR_W_S_SYNC_MNGR_OBJS_SOB_OBJ_0)) / 4;
}

static uint16_t gaudi_get_mon_cnt_per_dcore(void)
{
	return (((mmSYNC_MNGR_E_N_SYNC_MNGR_OBJS_MON_STATUS_511 -
			mmSYNC_MNGR_E_N_SYNC_MNGR_OBJS_MON_STATUS_0) + 4) >> 2);
}

static uint32_t gaudi_stream_master[] = {
	GAUDI_QUEUE_ID_DMA_0_0,
	GAUDI_QUEUE_ID_DMA_0_1,
	GAUDI_QUEUE_ID_DMA_0_2,
	GAUDI_QUEUE_ID_DMA_0_3,
	GAUDI_QUEUE_ID_DMA_1_0,
	GAUDI_QUEUE_ID_DMA_1_1,
	GAUDI_QUEUE_ID_DMA_1_2,
	GAUDI_QUEUE_ID_DMA_1_3
};

static int gaudi_get_stream_master_qid_arr(uint32_t **qid_arr)
{
	*qid_arr = gaudi_stream_master;

	return ARRAY_SIZE(gaudi_stream_master);
}

static int gaudi_nic_config_reduction(int fd, enum hltests_nic_reduction_operation red_op,
					enum hltests_nic_reduction_datatype red_data_type,
					uint64_t *reduction)
{
	return -ENOTSUP;
}

static int gaudi_get_async_event_id(enum hltests_async_event_id hltests_event_id,
					uint32_t *asic_event_id)
{
	switch (hltests_event_id) {
	case FIX_POWER_ENV_S:
		*asic_event_id = GAUDI_EVENT_FIX_POWER_ENV_S;
		break;

	case FIX_POWER_ENV_E:
		*asic_event_id = GAUDI_EVENT_FIX_POWER_ENV_E;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static uint32_t gaudi_get_cq_patch_size(uint32_t qid)
{
	return 0;
}

uint32_t gaudi_get_max_pkt_size(int fd, bool mb, bool eb, uint32_t qid)
{
	return sizeof(struct packet_lin_dma);
}

static uint64_t gaudi_get_hbw_rr_addr(void)
{
	return CFG_BASE + PCIE_FW_SRAM_ADDR;
}

static uint64_t gaudi_get_lbw_rr_addr(void)
{
	return CFG_BASE + mmMME1_QM_GLBL_STS0;
}

static uint64_t gaudi_get_addr_dec_err_addr(void)
{
	/* point to the reserved area below the SP_SRAM */
	return PSOC_SCRATCHPAD_ADDR - 0x8;
}

static uint64_t gaudi_get_razwi_addr(enum err_trigger  type)
{
	uint64_t addr;

	switch (type) {
	case RAZWI_TYPE_LBW_RR:
		addr = gaudi_get_lbw_rr_addr();
		break;
	case RAZWI_TYPE_HBW_RR:
		addr = gaudi_get_hbw_rr_addr();
		break;
	case RAZWI_TYPE_ADDR_DEC:
		addr = gaudi_get_addr_dec_err_addr();
		break;
	default:
		addr = ULONG_MAX;
	}

	return addr;
}

static uint64_t gaudi_get_pb_secured_addr(void)
{
	return CFG_BASE + mmMME0_QM_GLBL_CFG0;
}

static void gaudi_nic_write_desc_to_db_fifo(struct hltests_state *tests_state,
					    struct hltests_nic_db_fifo_data *db_fifo,
					    struct hltests_nic_db_fifo_packet *db_fifo_packet,
					    uint32_t port, bool is_dup)
{
	hltests_nic_write_desc_to_db_fifo_default(tests_state, db_fifo, db_fifo_packet, port,
						  is_dup);
}

static struct hltests_nic_asic_funcs gaudi_nic_funcs = {
	.asic_priv_init = gaudi_nic_asic_priv_init,
	.get_default_cfg = gaudi_nic_get_default_cfg,
	.run_wtd = gaudi_nic_run_wtd,
	.run_coll_op = NULL,
	.get_max_num_of_ports = gaudi_nic_get_max_num_of_ports,
	.get_port_mask = gaudi_nic_get_port_mask,
	.get_base_qid = gaudi_nic_get_base_qid,
	.get_wq_offset = gaudi_nic_get_wq_offset,
	.fill_wqe = gaudi_nic_fill_wqe,
	.get_swqe = gaudi_nic_get_swqe,
	.get_rwqe = gaudi_nic_get_rwqe,
	.get_swqe_size = gaudi_nic_get_swqe_size,
	.get_rwqe_size = gaudi_nic_get_rwqe_size,
	.get_max_pi = NULL,
	.get_min_conn_id = gaudi_nic_get_min_conn_id,
	.get_max_conn_id = gaudi_nic_get_max_conn_id,
	.get_max_num_of_qps = gaudi_nic_get_max_num_of_qps,
	.get_min_coll_conn_id = NULL,
	.get_max_coll_conn_id = NULL,
	.get_coll_qps_offset = NULL,
	.get_max_num_of_coll_qps = NULL,
	.pre_setup_ctx = gaudi_nic_pre_setup_ctx,
	.pre_setup_default_ctx_rdv = gaudi_nic_pre_setup_default_ctx_rdv,
	.setup_ctx_lpbk = gaudi_nic_setup_ctx_lpbk,
	.setup_ctx_e2e = gaudi_nic_setup_ctx_e2e,
	.setup_default_ctx_rdv = gaudi_nic_setup_default_ctx_rdv,
	.get_user_cqe = NULL,
	.user_cq_create = gaudi_nic_user_cq_create,
	.user_cq_destroy = gaudi_nic_user_cq_destroy,
	.add_bulk_doorbell_pkt = gaudi_nic_add_bulk_doorbell_pkt,
	.get_db_fifo_umr = NULL,
	.get_db_fifo_dup = NULL,
	.get_db_fifo_entry_size = NULL,
	.get_db_fifo_element_size = NULL,
	.get_hw_wq_pi = NULL,
	.config_reduction = gaudi_nic_config_reduction,
	.clear_lbw_memory = NULL,
	.create_dwq_packet = NULL,
	.parse_eqe_qp_syndrome = NULL,
	.read_mem_cmpl = NULL,
	.get_mem_cmpl_addr = NULL,
	.map_lbw_block = NULL,
	.get_half_port_mask = NULL,
	.fill_bp_offs_params = NULL,
	.ovrd_wqes_data_size = NULL,
	.submit_wtd = NULL,
	.submit_db = NULL,
	.write_desc_to_db_fifo = gaudi_nic_write_desc_to_db_fifo,
};

static const struct hltests_asic_funcs gaudi_funcs = {
	.add_arb_en_pkt = gaudi_add_arb_en_pkt,
	.add_cq_config_pkt = gaudi_add_cq_config_pkt,
	.add_pdma_ch_bw_config_pkt = NULL,
	.add_monitor_and_fence = gaudi_add_monitor_and_fence,
	.add_monitor = gaudi_add_monitor,
	.get_fence_addr = gaudi_get_fence_addr,
	.add_nop_pkt = gaudi_add_nop_pkt,
	.add_msg_barrier_pkt = gaudi_add_msg_barrier_pkt,
	.add_wreg32_pkt = gaudi_add_wreg32_pkt,
	.add_arb_point_pkt = gaudi_add_arb_point_pkt,
	.add_msg_long_pkt = gaudi_add_msg_long_pkt,
	.add_msg_short_pkt = gaudi_add_msg_short_pkt,
	.add_arm_monitor_pkt = gaudi_add_arm_monitor_pkt,
	.add_write_to_sob_pkt = gaudi_add_write_to_sob_pkt,
	.add_fence_pkt = gaudi_add_fence_pkt,
	.add_dma_pkt = gaudi_add_dma_pkt,
	.add_cp_dma_pkt = gaudi_add_cp_dma_pkt,
	.add_cb_list_pkt = gaudi_add_cb_list_pkt,
	.add_load_and_exe_pkt = gaudi_add_load_and_exe_pkt,
	.get_dma_down_qid = gaudi_get_dma_down_qid,
	.get_dma_up_qid = gaudi_get_dma_up_qid,
	.get_ddma_qid = gaudi_get_ddma_qid,
	.get_ddma_cnt = gaudi_get_ddma_cnt,
	.get_tpc_qid = gaudi_get_tpc_qid,
	.get_mme_qid = gaudi_get_mme_qid,
	.get_nic_qid = gaudi_get_nic_qid,
	.get_tpc_cnt = gaudi_get_tpc_cnt,
	.get_mme_cnt = gaudi_get_mme_cnt,
	.get_first_avail_sob = gaudi_get_first_avail_sob,
	.get_first_avail_mon = gaudi_get_first_avail_mon,
	.get_first_avail_cq = gaudi_get_first_avail_cq,
	.get_sob_base_addr = gaudi_get_sob_base_addr,
	.get_any_mappable_hw_block_base_addr = gaudi_get_any_mappable_hw_block_base_addr,
	.get_cache_line_size = gaudi_get_cache_line_size,
	.asic_priv_init = gaudi_asic_priv_init,
	.asic_priv_fini = gaudi_asic_priv_fini,
	.dram_pool_alloc = gaudi_dram_pool_alloc,
	.dram_pool_free = gaudi_dram_pool_free,
	.va_pool_alloc = gaudi_va_pool_alloc,
	.va_pool_free = gaudi_va_pool_free,
	.submit_cs = gaudi_submit_cs,
	.wait_for_cs = gaudi_wait_for_cs,
	.wait_for_cs_until_not_busy = gaudi_wait_for_cs_until_not_busy,
	.get_max_pll_idx = gaudi_get_max_pll_idx,
	.stringify_pll_idx = gaudi_stringify_pll_idx,
	.stringify_pll_type = gaudi_stringify_pll_type,
	.get_dram_va_hint_mask = gaudi_get_dram_va_hint_mask,
	.get_dram_va_reserved_addr_start = gaudi_get_dram_va_reserved_addr_start,
	.get_sob_id = gaudi_get_sob_id,
	.get_mon_cnt_per_dcore = gaudi_get_mon_cnt_per_dcore,
	.get_stream_master_qid_arr = gaudi_get_stream_master_qid_arr,
	.add_sched_arc_nop_cmd = NULL,
	.add_sched_arc_dispatch_static_ecb_list = NULL,
	.get_arc_cb_suffix_size = NULL,
	.arc_get_max_cpuid = NULL,
	.arc_get_va_range_host_start = NULL,
	.arc_get_va_range_dram_start = NULL,
	.arc_get_sched_cpuid_range = NULL,
	.arc_get_engine_cpuid_range = NULL,
	.set_arc_asic_fw_load_params = NULL,
	.asic_load_fw_to_arcs = NULL,
	.arc_set_regions = NULL,
	.arc_set_config = NULL,
	.arc_map_lbw_blocks = NULL,
	.arc_get_num_schedulers = NULL,
	.wait_arc_run_done = NULL,
	.arc_activate = NULL,
	.arc_unmap_lbw_blocks = NULL,
	.arc_set_enabled_cores = NULL,
	.arc_configure_scheduler_streams = NULL,
	.pdma_get_max_ch_id = NULL,
	.pdma_map_lbw_blocks = NULL,
	.pdma_unmap_lbw_blocks = NULL,
	.pdma_config_ch_blocks = NULL,
	.arc_get_cpu_id_eng_group = NULL,
	.get_tc_base_addr = NULL,
	.get_async_event_id = gaudi_get_async_event_id,
	.get_cq_patch_size = gaudi_get_cq_patch_size,
	.get_max_pkt_size = gaudi_get_max_pkt_size,
	.add_direct_write_cq_pkt = NULL,
	.monitor_dma_test_progress = NULL,
	.cq_db_get_available_sob = NULL,
	.cq_db_get_available_mon = NULL,
	.cq_db_get_available_cq = NULL,
	.mme_dma_init = NULL,
	.prepare_mme_dma_req = NULL,
	.get_razwi_addr = gaudi_get_razwi_addr,
	.get_pb_secured_addr = gaudi_get_pb_secured_addr,
	.nic_funcs = &gaudi_nic_funcs,
};

void gaudi_tests_set_asic_funcs(struct hltests_device *hdev)
{
	hdev->asic_funcs = &gaudi_funcs;
}
