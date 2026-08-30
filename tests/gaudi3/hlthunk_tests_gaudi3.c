// SPDX-License-Identifier: MIT

/*
 * Copyright 2021-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */
#include "hlthunk_tests.h"
#include "hlthunk_nic_tests.h"
#include "gaudi3/gaudi3.h"
#include "gaudi3/gaudi3_packets.h"
#include "gaudi3/gaudi3_pqm_packets.h"
#include "gaudi3/asic_reg/gaudi3_regs.h"
#include "gaudi3/asic_reg/sob_objs_masks.h"
#include "gaudi3/gaudi3_nic.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <linux/ethtool.h>
#include <immintrin.h>
#include <inttypes.h>
#include "engines-arc/include/gaudi3/gaudi3_arc_common_packets.h"
#include "engines-arc/include/gaudi3/gaudi3_arc_host_packets.h"
#include "engines-arc/common/include/arc_host_packets.h"
#include "engines-arc/common/include/arc_common_packets.h"
#include "nic_patcher_cmds.h"

#include <infiniband/hbldv.h>

#define GAUDI3_MAX_NUM_DIES	2
#define QP_ALLOC_RETRIES	5

#define ARC_AUX_RUN_REQ_OFFSET		(CFG_BAR_BASE + \
					mmHD0_ARC_FARM_ARC0_AUX_RUN_REQ - \
					mmHD0_ARC_FARM_ARC0_AUX_BASE)

#define ARC_AUX_HALT_REQ_OFFSET		(CFG_BAR_BASE + \
					mmHD0_ARC_FARM_ARC0_AUX_HALT_REQ - \
					mmHD0_ARC_FARM_ARC0_AUX_BASE)

#define PDMA_CH_ID(engine_id) \
	(engine_id - GAUDI3_DIE0_ENGINE_ID_PDMA_0_CH_0)

static const uint64_t gaudi3_pdma_grp_blocks_bases[NUM_OF_PDMA_GRP_PER_DIE * MAX_NUM_OF_DIES] = {
		mmD0_SPDMA0_CH0_A_PQM_CH_BASE,
		mmD0_SPDMA1_CH0_A_PQM_CH_BASE,
		mmD1_SPDMA0_CH0_A_PQM_CH_BASE,
		mmD1_SPDMA1_CH0_A_PQM_CH_BASE
};

#define ARC_FW_INIT_CONFIG_VER	0x2

#define SCHED_SOB_LBU_ADDR_OFFSET	(CFG_BAR_BASE + \
					SCHED_SOB_LBU_ADDR - \
					mmHD0_ARC_FARM_ARC0_AUX_BASE)

#define SCHED_SOB_LBU_VALUE_OFFSET	(CFG_BAR_BASE + \
					SCHED_SOB_LBU_VALUE - \
					mmHD0_ARC_FARM_ARC0_AUX_BASE)

#define SCHED_FW_CONFIG_ADDR_OFFSET	(CFG_BAR_BASE + \
					SCHED_FW_CONFIG_ADDR - \
					mmHD0_ARC_FARM_ARC0_AUX_BASE)

#define SCHED_FW_CONFIG_SIZE_OFFSET	(CFG_BAR_BASE + \
					SCHED_FW_CONFIG_SIZE - \
					mmHD0_ARC_FARM_ARC0_AUX_BASE)

#define SCHED_NEG_TEST_ARC_PAGE_FAULT_OFFSET	(CFG_BAR_BASE + \
					SCHED_NEG_TEST_ARC_PAGE_FAULT - \
					mmHD0_ARC_FARM_ARC0_AUX_BASE)

#define DUP_ENG_DUP_REG_OFFSET(reg, block_offset) \
	((mmHD0_ARC_FARM_ARC0_DUP_ENG_##reg) - \
	mmHD0_ARC_FARM_ARC0_DUP_ENG_DUP_ADDR_GR_0_0 + \
	 sizeof(uint32_t) * (block_offset))

#define MON_PER_ENG_GROUP	1
#define SOB_PER_ENG_GROUP	2
#define SOB_VAL_LONG_MODE_MASK	0x7FFF /* 15 bits */

#define ARC_IMAGE_HBM_SIZE             SZ_128K
#define SCHED_ARC_IMAGE_DCCM_SIZE      SZ_64K
#define SCHED_ARC_IMAGE_SIZE           (SCHED_ARC_IMAGE_DCCM_SIZE + ARC_IMAGE_HBM_SIZE)
#define ENGINE_ARC_IMAGE_DCCM_SIZE     SZ_32K
#define ENGINE_ARC_IMAGE_SIZE          (ENGINE_ARC_IMAGE_DCCM_SIZE + ARC_IMAGE_HBM_SIZE)

#define WQ_HW_INDICES_SIZE             BIT(22)
#define WQ_HW_INDICES_SIZE_MASK        (WQ_HW_INDICES_SIZE - 1)

#define NUM_OF_SOBS_IN_BATCH		8192
#define NUM_OF_MONITORS_IN_BATCH	1024
#define NUM_OF_CQS_IN_SM		64

/*
 * During the pre init phase we cannot use a regular completion mechanism.
 * So we implement an alternative approach, which requires a sync object
 * which is also exposed via the HW blocks mappings.
 * The first such SOB is SOB 0 on HDCORE 1. It is exposed on SM BLOCK at
 * offset 0.
 */
#define PRE_INIT_CQ_HDCORE		1
#define PRE_INIT_CQ_SOB_ID_IN_HDCORE	0
#define PRE_INIT_CQ_SOB_ID		(NUM_OF_SOBS_IN_BATCH * PRE_INIT_CQ_HDCORE + \
					PRE_INIT_CQ_SOB_ID_IN_HDCORE)
#define PRE_INIT_CQ_SM_BLOCK		(mmHD0_SYNC_MNGR_OBJS_BASE + \
					HDCORE_OFFSET * PRE_INIT_CQ_HDCORE)

#define AFA_CMPL_REG_1	1
#define AFA_CMPL_REG_2	3
#define AFA_SWQ_TAG	0x601

#define MME_OFFSET (mmHD1_MME_CTRL_LO_BASE - mmHD0_MME_CTRL_LO_BASE)

#define TEN_COUT_OFFSET (mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_COUT_BASE \
				- mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE)

/* Per current SW policy link speed is always same for all ports.up
 * Hence, we check speed on any enabled port.
 */
#define NIC_IS_200_GBPS_MODE(fd, port_mask) \
({ \
	struct hltests_device *__hdev; \
	struct gaudi3_priv *__gaudi3; \
\
	__hdev = get_hdev_from_fd(fd); \
	__gaudi3 = __hdev->priv; \
\
	__gaudi3->speed[LBS(port_mask) - 1] == SPEED_200000; \
})

static uint32_t gaudi3_add_dma_pkt(void *buffer, uint32_t buf_off,
				struct hltests_pkt_info *pkt_info);

static uint32_t gaudi3_add_fence_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info);

static uint64_t gaudi3_nic_get_half_port_mask(int fd, uint64_t port_mask, bool is_upper_half);

#define GAUDI3_SYNDROME_TYPE(syndrome)	((syndrome >> 7) & 0x7)
#define GAUDI3_SYNDROM_IS_RX(src)	((src == 4) || (src == 6))
#define GAUDI3_SYNDROM_IS_TX(src)	(src == 5)
#define GAUDI3_MAX_SYNDROM_STRING_LEN	256
#define GAUDI3_MAX_SYNDROMS		0x400
#define GAUDI3_MAX_SYNDROME_TYPE	3
#define GAUDI3_ERR_CAUSE_QPC_SHIFT	64
#define EQE_CQ_EVENT_CCQ_NUM(eqe)	((eqe)->data[1] & 0xffff)

#define GAUDI3_SYNDROME_CAUSE(syndrome)	(syndrome & 0x7f)
#define GAUDI3_SYNDROME_CAUSE_IS_QPC(cause)	(cause >= 64)

#define GAUDI3_MEM_CMPL_ADDR_OFF_MASK	0x1FFFFFFF

#define GAUDI3_NIC_MAX_ERR_INJ	(BIT_ULL(\
			PRT_MAC_CORE_MAC_ERR_INJ_CFG_DROP_PERCENTAGE_S) - 1)
#define GAUDI3_NIC_ERR_INJ_RESET_VALUE	0x40000000

enum qp_err_synd_src {
	GAUDI3_SYNDROME_ERR_SRC_RXE = 0,
	GAUDI3_SYNDROME_ERR_SRC_QPC,
	GAUDI3_SYNDROME_ERR_SRC_TXE
};

static char qp_err_eng_src_strs[][64] = { "RXE", "QPC", "TXE" };
static char qp_err_qpc_strs[][8][128] = {
	{
		"[qpc] [req DB] QP not valid",
		"[qpc] [req DB] ASID not valid",
		"[qpc] [req DB] security check",
		"[qpc] [req DB] (PI - CI) > last-index",
		"[qpc] [req DB] wq-type is READ",
	},
	{
		"[qpc] [patcher DB] QP not valid",
		"[qpc] [patcher DB] ASID not valid",
		"[qpc] [patcher DB] security check",
	},
	{
		"[qpc] [CC DB] QP not valid",
		"[qpc] [CC DB] ASID not valid",
		"[qpc] [CC DB] security check",
	},
	{
		"[qpc] [res TX] QP not valid",
	},
	{
		"[qpc] [res RX] max-retry-cnt exceeded",
		"[qpc] [res RX] QP stuck - remote CI to peer remote CI diff is too big",
	},
	{
		"[qpc] [req TX] QP not valid",
		"[qpc] [req TX] RDV WQE but wq-type is not WRITE",
	},
	{
		"[qpc] [req RX] QP not valid",
		"[qpc] [req RX] max-retry-cnt exceeded",
		"[qpc] [TMR] max-retry-cnt exceeded",
	},
	{
		"[qpc] [req RDV] QP not valid",
		"[qpc] [req RDV] wrong wq-type",
	},
};

static char qp_err_rxe_strs[][64] = {
	"[RX] pkt err, pkt bad format",
	"[RX] pkt err, parser FSM invalid",
	"[RX] pkt err, HDR size invalid",
	"[RX] pkt err, IPv4-len invalid",
	"[RX] pkt err, IPv6-len invalid",
	"[RX] pkt err, pkt tunnel invalid",
	"[RX] pkt err, parser hint invalid",
	"[RX] pkt err, BTH opcode invalid",
	"[RX] pkt err, syndrome invalid",
	"[RX] pkt err, RC max size invalid",
	"[RX] pkt err, RC min size invalid",
	"[RX] pkt err, Raw pkt invalid",
	"[RX] pkt err, Raw max size invalid",
	"[RX] pkt err, Raw min size invalid",
	"[RX] pkt err, Raw max size invalid",
	"[RX] QPC err, QP invalid",
	"[RX] QPC err, QPC Transport Service mismatch",
	"[RX] QPC err, QPC Requester connection state invalid",
	"[RX] QPC err, QPC Responder Connection state invalid",
	"[RX] QPC err, QPC Responder resync invalid",
	"[RX] QPC err, QPC Requester PSN invalid",
	"[RX] QPC err, QPC Requester PSN unset",
	"[RX] QPC err, Requester SAL NTS invalid",
	"[RX] QPC err, QPC Responder RKEY invalid",
	"[RX] QPC err, Requester SAL PSN invalid",
	"[RX] WQE err, WQE-index miss-match",
	"[RX] WQE err, WQE write opcode invalid",
	"[RX] WQE err, WQE Rendezvous opcode invalid",
	"[RX] WQE err, WQE Read opcode invalid",
	"[RX] WQE err, WQE Write Zero",
	"[RX] WQE err, WQE multi zero",
	"[RX] WQE err, WQE Write send big",
	"[RX] WQE err, WQE multi big",
};

static char qp_err_txe_strs[][128] = {
	"[TX] QPC.wq_type is write does not support WQE.opcode",
	"[TX] QPC.wq_type is rendezvous does not support WQE.opcode",
	"[TX] QPC.wq_type is read does not support WQE.opcode",
	"[TX] WQE is inline but does not support WQE.opcode",
	"[TX] WQE.opcode is write but WQE.size is 0",
	"[TX] WQE.opcode is multi-stride|local-stride|multi-dual but WQE.size is 0",
	"[TX] WQE.opcode is send but WQE.size is 0",
	"[TX] WQE.opcode is rendezvous-write|rendezvous-read but WQE.size is 0",
	"[TX] WQE.opcode is write but size > configured max-write-send-size",
	"[TX] WQE.opcode is multi-stride|local-stride|multi-dual but size > configured max-stride-size",
	"[TX] WQE.opcode is rendezvous-write|rendezvous-read but QPC.remote_wq_log_size <= configured min-remote-log-size",
	"[TX] WQE.opcode is rendezvous-write but WQE.size != configured rdv-wqe-size (per granularity)",
	"[TX] WQE.opcode is rendezvous-read but WQE.size != configured rdv-wqe-size (per granularity)",
	"[TX] WQE.inline is set but WQE.size != configured inline-wqe-size (per granularity)",
	"[TX] WQE.opcode is multi-stride|local-stride|multi-dual but QPC.swq_granularity is 0",
	"[TX] QP-RAW and not compression nor down/up-convert",
	"[TX] WQE.opcode is multi-stride|local-stride|multi-dual but WQE.size < stride-size",
	"[TX] Upscale with unaligned remote address",
	"[TX] WQE.reduction_opcode is upscale but does not support WQE.opcode",
	"[TX] RAW packet but WQE.size not supported",
	"[TX] QP-SACK with WQE NOP",
	"[TX] QP-RAW with non-linear WQE opcode",
	"[TX] Wrong opcode for QP-plain-RDMA",
	"[TX] QP-plain RDMA with up/down-convert",
	"[TX] Down/up-convert with non 4B align size/address/stride",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] N/A",
	"[TX] WQE's sent bytes exceeds WQE's size",
	"[TX] QPC WQ-log-size below cfg",
	"[TX] QPC WQ-log-size above cfg",
	"[TX] QP-RAW with WQE size above cfg",
	"[TX] QP-RAW with WQE size below cfg",
	"[TX] WQE.opcode is RD-RDV but WQE.inline is set",
	"[TX] WQE fetch&add WR size not 0",
	"[TX] WQE fetch&add WR addr not mod4",
	"[TX] WQE.opcode above 15",
	"[TX] WQE bad opcode",
	"[TX] WQE bad size",
	"[TX] Tunnel 0-size",
	"[TX] Tunnel max size",
};

static const uint64_t gaudi3_arc_blocks_bases[NUM_ACTIVE_ARCS] = {
	[CPU_ID_SCHED_ARC0] = mmHD0_ARC_FARM_ARC0_AUX_BASE,
	[CPU_ID_SCHED_ARC1] = mmHD0_ARC_FARM_ARC1_AUX_BASE,
	[CPU_ID_SCHED_ARC2] = mmHD1_ARC_FARM_ARC0_AUX_BASE,
	[CPU_ID_SCHED_ARC3] = mmHD1_ARC_FARM_ARC1_AUX_BASE,
	[CPU_ID_SCHED_ARC4] = mmHD2_ARC_FARM_ARC0_AUX_BASE,
	[CPU_ID_SCHED_ARC5] = mmHD2_ARC_FARM_ARC1_AUX_BASE,
	[CPU_ID_SCHED_ARC6] = mmHD3_ARC_FARM_ARC0_AUX_BASE,
	[CPU_ID_SCHED_ARC7] = mmHD3_ARC_FARM_ARC1_AUX_BASE,
	[CPU_ID_SCHED_ARC8] = mmHD4_ARC_FARM_ARC0_AUX_BASE,
	[CPU_ID_SCHED_ARC9] = mmHD4_ARC_FARM_ARC1_AUX_BASE,
	[CPU_ID_SCHED_ARC10] = mmHD5_ARC_FARM_ARC0_AUX_BASE,
	[CPU_ID_SCHED_ARC11] = mmHD5_ARC_FARM_ARC1_AUX_BASE,
	[CPU_ID_SCHED_ARC12] = mmHD6_ARC_FARM_ARC0_AUX_BASE,
	[CPU_ID_SCHED_ARC13] = mmHD6_ARC_FARM_ARC1_AUX_BASE,
	[CPU_ID_SCHED_ARC14] = mmHD7_ARC_FARM_ARC0_AUX_BASE,
	[CPU_ID_SCHED_ARC15] = mmHD7_ARC_FARM_ARC1_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC0] = mmHD0_TPC0_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC1] = mmHD0_TPC1_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC2] = mmHD0_TPC2_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC3] = mmHD0_TPC3_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC4] = mmHD0_TPC4_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC5] = mmHD0_TPC5_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC6] = mmHD0_TPC6_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC7] = mmHD0_TPC7_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC8] = mmHD1_TPC0_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC9] = mmHD1_TPC1_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC10] = mmHD1_TPC2_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC11] = mmHD1_TPC3_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC12] = mmHD1_TPC4_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC13] = mmHD1_TPC5_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC14] = mmHD1_TPC6_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC15] = mmHD1_TPC7_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC16] = mmHD2_TPC0_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC17] = mmHD2_TPC1_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC18] = mmHD2_TPC2_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC19] = mmHD2_TPC3_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC20] = mmHD2_TPC4_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC21] = mmHD2_TPC5_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC22] = mmHD2_TPC6_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC23] = mmHD2_TPC7_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC24] = mmHD3_TPC0_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC25] = mmHD3_TPC1_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC26] = mmHD3_TPC2_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC27] = mmHD3_TPC3_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC28] = mmHD3_TPC4_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC29] = mmHD3_TPC5_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC30] = mmHD3_TPC6_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC31] = mmHD3_TPC7_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC32] = mmHD4_TPC0_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC33] = mmHD4_TPC1_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC34] = mmHD4_TPC2_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC35] = mmHD4_TPC3_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC36] = mmHD4_TPC4_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC37] = mmHD4_TPC5_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC38] = mmHD4_TPC6_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC39] = mmHD4_TPC7_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC40] = mmHD5_TPC0_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC41] = mmHD5_TPC1_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC42] = mmHD5_TPC2_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC43] = mmHD5_TPC3_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC44] = mmHD5_TPC4_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC45] = mmHD5_TPC5_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC46] = mmHD5_TPC6_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC47] = mmHD5_TPC7_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC48] = mmHD6_TPC0_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC49] = mmHD6_TPC1_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC50] = mmHD6_TPC2_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC51] = mmHD6_TPC3_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC52] = mmHD6_TPC4_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC53] = mmHD6_TPC5_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC54] = mmHD6_TPC6_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC55] = mmHD6_TPC7_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC56] = mmHD7_TPC0_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC57] = mmHD7_TPC1_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC58] = mmHD7_TPC2_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC59] = mmHD7_TPC3_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC60] = mmHD7_TPC4_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC61] = mmHD7_TPC5_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC62] = mmHD7_TPC6_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC63] = mmHD7_TPC7_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC64] = mmHD0_TPC8_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC65] = mmHD2_TPC8_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC66] = mmHD5_TPC8_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC67] = mmHD7_TPC8_QM_ARC_AUX_BASE,
	[CPU_ID_MME_QMAN_ARC0] = mmHD0_MME_QM_ARC_AUX_BASE,
	[CPU_ID_MME_QMAN_ARC1] = mmHD1_MME_QM_ARC_AUX_BASE,
	[CPU_ID_MME_QMAN_ARC2] = mmHD2_MME_QM_ARC_AUX_BASE,
	[CPU_ID_MME_QMAN_ARC3] = mmHD3_MME_QM_ARC_AUX_BASE,
	[CPU_ID_MME_QMAN_ARC4] = mmHD4_MME_QM_ARC_AUX_BASE,
	[CPU_ID_MME_QMAN_ARC5] = mmHD5_MME_QM_ARC_AUX_BASE,
	[CPU_ID_MME_QMAN_ARC6] = mmHD6_MME_QM_ARC_AUX_BASE,
	[CPU_ID_MME_QMAN_ARC7] = mmHD7_MME_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC0] = mmHD1_SEDMA0_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC1] = mmHD1_SEDMA1_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC2] = mmHD3_SEDMA0_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC3] = mmHD3_SEDMA1_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC4] = mmHD4_SEDMA0_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC5] = mmHD4_SEDMA1_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC6] = mmHD6_SEDMA0_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC7] = mmHD6_SEDMA1_QM_ARC_AUX_BASE,
	[CPU_ID_ROT_QMAN_ARC0] = mmHD1_ROT0_QM_ARC_AUX_BASE,
	[CPU_ID_ROT_QMAN_ARC1] = mmHD1_ROT1_QM_ARC_AUX_BASE,
	[CPU_ID_ROT_QMAN_ARC2] = mmHD3_ROT0_QM_ARC_AUX_BASE,
	[CPU_ID_ROT_QMAN_ARC3] = mmHD3_ROT1_QM_ARC_AUX_BASE,
	[CPU_ID_ROT_QMAN_ARC4] = mmHD4_ROT0_QM_ARC_AUX_BASE,
	[CPU_ID_ROT_QMAN_ARC5] = mmHD4_ROT1_QM_ARC_AUX_BASE,
	[CPU_ID_ROT_QMAN_ARC6] = mmHD6_ROT0_QM_ARC_AUX_BASE,
	[CPU_ID_ROT_QMAN_ARC7] = mmHD6_ROT1_QM_ARC_AUX_BASE,
};

static const uint32_t gaudi3_arc_eng_id_to_cpu_id[GAUDI3_ENGINE_ID_SIZE] = {
		[GAUDI3_HDCORE0_ENGINE_ID_TPC_0] = CPU_ID_TPC_QMAN_ARC0,
		[GAUDI3_HDCORE0_ENGINE_ID_TPC_1] = CPU_ID_TPC_QMAN_ARC1,
		[GAUDI3_HDCORE0_ENGINE_ID_TPC_2] = CPU_ID_TPC_QMAN_ARC2,
		[GAUDI3_HDCORE0_ENGINE_ID_TPC_3] = CPU_ID_TPC_QMAN_ARC3,
		[GAUDI3_HDCORE0_ENGINE_ID_TPC_4] = CPU_ID_TPC_QMAN_ARC4,
		[GAUDI3_HDCORE0_ENGINE_ID_TPC_5] = CPU_ID_TPC_QMAN_ARC5,
		[GAUDI3_HDCORE0_ENGINE_ID_TPC_6] = CPU_ID_TPC_QMAN_ARC6,
		[GAUDI3_HDCORE0_ENGINE_ID_TPC_7] = CPU_ID_TPC_QMAN_ARC7,
		[GAUDI3_HDCORE1_ENGINE_ID_TPC_0] = CPU_ID_TPC_QMAN_ARC8,
		[GAUDI3_HDCORE1_ENGINE_ID_TPC_1] = CPU_ID_TPC_QMAN_ARC9,
		[GAUDI3_HDCORE1_ENGINE_ID_TPC_2] = CPU_ID_TPC_QMAN_ARC10,
		[GAUDI3_HDCORE1_ENGINE_ID_TPC_3] = CPU_ID_TPC_QMAN_ARC11,
		[GAUDI3_HDCORE1_ENGINE_ID_TPC_4] = CPU_ID_TPC_QMAN_ARC12,
		[GAUDI3_HDCORE1_ENGINE_ID_TPC_5] = CPU_ID_TPC_QMAN_ARC13,
		[GAUDI3_HDCORE1_ENGINE_ID_TPC_6] = CPU_ID_TPC_QMAN_ARC14,
		[GAUDI3_HDCORE1_ENGINE_ID_TPC_7] = CPU_ID_TPC_QMAN_ARC15,
		[GAUDI3_HDCORE2_ENGINE_ID_TPC_0] = CPU_ID_TPC_QMAN_ARC16,
		[GAUDI3_HDCORE2_ENGINE_ID_TPC_1] = CPU_ID_TPC_QMAN_ARC17,
		[GAUDI3_HDCORE2_ENGINE_ID_TPC_2] = CPU_ID_TPC_QMAN_ARC18,
		[GAUDI3_HDCORE2_ENGINE_ID_TPC_3] = CPU_ID_TPC_QMAN_ARC19,
		[GAUDI3_HDCORE2_ENGINE_ID_TPC_4] = CPU_ID_TPC_QMAN_ARC20,
		[GAUDI3_HDCORE2_ENGINE_ID_TPC_5] = CPU_ID_TPC_QMAN_ARC21,
		[GAUDI3_HDCORE2_ENGINE_ID_TPC_6] = CPU_ID_TPC_QMAN_ARC22,
		[GAUDI3_HDCORE2_ENGINE_ID_TPC_7] = CPU_ID_TPC_QMAN_ARC23,
		[GAUDI3_HDCORE3_ENGINE_ID_TPC_0] = CPU_ID_TPC_QMAN_ARC24,
		[GAUDI3_HDCORE3_ENGINE_ID_TPC_1] = CPU_ID_TPC_QMAN_ARC25,
		[GAUDI3_HDCORE3_ENGINE_ID_TPC_2] = CPU_ID_TPC_QMAN_ARC26,
		[GAUDI3_HDCORE3_ENGINE_ID_TPC_3] = CPU_ID_TPC_QMAN_ARC27,
		[GAUDI3_HDCORE3_ENGINE_ID_TPC_4] = CPU_ID_TPC_QMAN_ARC28,
		[GAUDI3_HDCORE3_ENGINE_ID_TPC_5] = CPU_ID_TPC_QMAN_ARC29,
		[GAUDI3_HDCORE3_ENGINE_ID_TPC_6] = CPU_ID_TPC_QMAN_ARC30,
		[GAUDI3_HDCORE3_ENGINE_ID_TPC_7] = CPU_ID_TPC_QMAN_ARC31,
		[GAUDI3_HDCORE4_ENGINE_ID_TPC_0] = CPU_ID_TPC_QMAN_ARC32,
		[GAUDI3_HDCORE4_ENGINE_ID_TPC_1] = CPU_ID_TPC_QMAN_ARC33,
		[GAUDI3_HDCORE4_ENGINE_ID_TPC_2] = CPU_ID_TPC_QMAN_ARC34,
		[GAUDI3_HDCORE4_ENGINE_ID_TPC_3] = CPU_ID_TPC_QMAN_ARC35,
		[GAUDI3_HDCORE4_ENGINE_ID_TPC_4] = CPU_ID_TPC_QMAN_ARC36,
		[GAUDI3_HDCORE4_ENGINE_ID_TPC_5] = CPU_ID_TPC_QMAN_ARC37,
		[GAUDI3_HDCORE4_ENGINE_ID_TPC_6] = CPU_ID_TPC_QMAN_ARC38,
		[GAUDI3_HDCORE4_ENGINE_ID_TPC_7] = CPU_ID_TPC_QMAN_ARC39,
		[GAUDI3_HDCORE5_ENGINE_ID_TPC_0] = CPU_ID_TPC_QMAN_ARC40,
		[GAUDI3_HDCORE5_ENGINE_ID_TPC_1] = CPU_ID_TPC_QMAN_ARC41,
		[GAUDI3_HDCORE5_ENGINE_ID_TPC_2] = CPU_ID_TPC_QMAN_ARC42,
		[GAUDI3_HDCORE5_ENGINE_ID_TPC_3] = CPU_ID_TPC_QMAN_ARC43,
		[GAUDI3_HDCORE5_ENGINE_ID_TPC_4] = CPU_ID_TPC_QMAN_ARC44,
		[GAUDI3_HDCORE5_ENGINE_ID_TPC_5] = CPU_ID_TPC_QMAN_ARC45,
		[GAUDI3_HDCORE5_ENGINE_ID_TPC_6] = CPU_ID_TPC_QMAN_ARC46,
		[GAUDI3_HDCORE5_ENGINE_ID_TPC_7] = CPU_ID_TPC_QMAN_ARC47,
		[GAUDI3_HDCORE6_ENGINE_ID_TPC_0] = CPU_ID_TPC_QMAN_ARC48,
		[GAUDI3_HDCORE6_ENGINE_ID_TPC_1] = CPU_ID_TPC_QMAN_ARC49,
		[GAUDI3_HDCORE6_ENGINE_ID_TPC_2] = CPU_ID_TPC_QMAN_ARC50,
		[GAUDI3_HDCORE6_ENGINE_ID_TPC_3] = CPU_ID_TPC_QMAN_ARC51,
		[GAUDI3_HDCORE6_ENGINE_ID_TPC_4] = CPU_ID_TPC_QMAN_ARC52,
		[GAUDI3_HDCORE6_ENGINE_ID_TPC_5] = CPU_ID_TPC_QMAN_ARC53,
		[GAUDI3_HDCORE6_ENGINE_ID_TPC_6] = CPU_ID_TPC_QMAN_ARC54,
		[GAUDI3_HDCORE6_ENGINE_ID_TPC_7] = CPU_ID_TPC_QMAN_ARC55,
		[GAUDI3_HDCORE7_ENGINE_ID_TPC_0] = CPU_ID_TPC_QMAN_ARC56,
		[GAUDI3_HDCORE7_ENGINE_ID_TPC_1] = CPU_ID_TPC_QMAN_ARC57,
		[GAUDI3_HDCORE7_ENGINE_ID_TPC_2] = CPU_ID_TPC_QMAN_ARC58,
		[GAUDI3_HDCORE7_ENGINE_ID_TPC_3] = CPU_ID_TPC_QMAN_ARC59,
		[GAUDI3_HDCORE7_ENGINE_ID_TPC_4] = CPU_ID_TPC_QMAN_ARC60,
		[GAUDI3_HDCORE7_ENGINE_ID_TPC_5] = CPU_ID_TPC_QMAN_ARC61,
		[GAUDI3_HDCORE7_ENGINE_ID_TPC_6] = CPU_ID_TPC_QMAN_ARC62,
		[GAUDI3_HDCORE7_ENGINE_ID_TPC_7] = CPU_ID_TPC_QMAN_ARC63,
		[GAUDI3_HDCORE0_ENGINE_ID_TPC_8] = CPU_ID_TPC_QMAN_ARC64,
		[GAUDI3_HDCORE2_ENGINE_ID_TPC_8] = CPU_ID_TPC_QMAN_ARC65,
		[GAUDI3_HDCORE5_ENGINE_ID_TPC_8] = CPU_ID_TPC_QMAN_ARC66,
		[GAUDI3_HDCORE7_ENGINE_ID_TPC_8] = CPU_ID_TPC_QMAN_ARC67,
		[GAUDI3_HDCORE0_ENGINE_ID_MME_0] = CPU_ID_MME_QMAN_ARC0,
		[GAUDI3_HDCORE1_ENGINE_ID_MME_0] = CPU_ID_MME_QMAN_ARC1,
		[GAUDI3_HDCORE2_ENGINE_ID_MME_0] = CPU_ID_MME_QMAN_ARC2,
		[GAUDI3_HDCORE3_ENGINE_ID_MME_0] = CPU_ID_MME_QMAN_ARC3,
		[GAUDI3_HDCORE4_ENGINE_ID_MME_0] = CPU_ID_MME_QMAN_ARC4,
		[GAUDI3_HDCORE5_ENGINE_ID_MME_0] = CPU_ID_MME_QMAN_ARC5,
		[GAUDI3_HDCORE6_ENGINE_ID_MME_0] = CPU_ID_MME_QMAN_ARC6,
		[GAUDI3_HDCORE7_ENGINE_ID_MME_0] = CPU_ID_MME_QMAN_ARC7,
		[GAUDI3_HDCORE1_ENGINE_ID_EDMA_0] = CPU_ID_EDMA_QMAN_ARC0,
		[GAUDI3_HDCORE1_ENGINE_ID_EDMA_1] = CPU_ID_EDMA_QMAN_ARC1,
		[GAUDI3_HDCORE3_ENGINE_ID_EDMA_0] = CPU_ID_EDMA_QMAN_ARC2,
		[GAUDI3_HDCORE3_ENGINE_ID_EDMA_1] = CPU_ID_EDMA_QMAN_ARC3,
		[GAUDI3_HDCORE4_ENGINE_ID_EDMA_0] = CPU_ID_EDMA_QMAN_ARC4,
		[GAUDI3_HDCORE4_ENGINE_ID_EDMA_1] = CPU_ID_EDMA_QMAN_ARC5,
		[GAUDI3_HDCORE6_ENGINE_ID_EDMA_0] = CPU_ID_EDMA_QMAN_ARC6,
		[GAUDI3_HDCORE6_ENGINE_ID_EDMA_1] = CPU_ID_EDMA_QMAN_ARC7,
};

const uint32_t gaudi3_engine_arc_cpu_id_to_eng_group[] = {
	[CPU_ID_SCHED_ARC0 ... CPU_ID_SCHED_ARC15] = ENG_GROUP_INVALID,
	[CPU_ID_TPC_QMAN_ARC0 ... CPU_ID_TPC_QMAN_ARC63] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC64 ... CPU_ID_TPC_QMAN_ARC67] = ENG_GROUP_INVALID,
	[CPU_ID_MME_QMAN_ARC0 ... CPU_ID_MME_QMAN_ARC7] = ENG_GROUP_MME_COMPUTE,
	[CPU_ID_EDMA_QMAN_ARC0 ... CPU_ID_EDMA_QMAN_ARC7] = ENG_GROUP_EDMA_COMPUTE,
	[CPU_ID_ROT_QMAN_ARC0 ... CPU_ID_ROT_QMAN_ARC7] = ENG_GROUP_INVALID,
};

unsigned int gaudi3_tpc_id_to_engine_id[] = {
	GAUDI3_HDCORE0_ENGINE_ID_TPC_0,
	GAUDI3_HDCORE0_ENGINE_ID_TPC_1,
	GAUDI3_HDCORE0_ENGINE_ID_TPC_2,
	GAUDI3_HDCORE0_ENGINE_ID_TPC_3,
	GAUDI3_HDCORE0_ENGINE_ID_TPC_4,
	GAUDI3_HDCORE0_ENGINE_ID_TPC_5,
	GAUDI3_HDCORE0_ENGINE_ID_TPC_6,
	GAUDI3_HDCORE0_ENGINE_ID_TPC_7,
	GAUDI3_HDCORE1_ENGINE_ID_TPC_0,
	GAUDI3_HDCORE1_ENGINE_ID_TPC_1,
	GAUDI3_HDCORE1_ENGINE_ID_TPC_2,
	GAUDI3_HDCORE1_ENGINE_ID_TPC_3,
	GAUDI3_HDCORE1_ENGINE_ID_TPC_4,
	GAUDI3_HDCORE1_ENGINE_ID_TPC_5,
	GAUDI3_HDCORE1_ENGINE_ID_TPC_6,
	GAUDI3_HDCORE1_ENGINE_ID_TPC_7,
	GAUDI3_HDCORE2_ENGINE_ID_TPC_0,
	GAUDI3_HDCORE2_ENGINE_ID_TPC_1,
	GAUDI3_HDCORE2_ENGINE_ID_TPC_2,
	GAUDI3_HDCORE2_ENGINE_ID_TPC_3,
	GAUDI3_HDCORE2_ENGINE_ID_TPC_4,
	GAUDI3_HDCORE2_ENGINE_ID_TPC_5,
	GAUDI3_HDCORE2_ENGINE_ID_TPC_6,
	GAUDI3_HDCORE2_ENGINE_ID_TPC_7,
	GAUDI3_HDCORE3_ENGINE_ID_TPC_0,
	GAUDI3_HDCORE3_ENGINE_ID_TPC_1,
	GAUDI3_HDCORE3_ENGINE_ID_TPC_2,
	GAUDI3_HDCORE3_ENGINE_ID_TPC_3,
	GAUDI3_HDCORE3_ENGINE_ID_TPC_4,
	GAUDI3_HDCORE3_ENGINE_ID_TPC_5,
	GAUDI3_HDCORE3_ENGINE_ID_TPC_6,
	GAUDI3_HDCORE3_ENGINE_ID_TPC_7,
	GAUDI3_HDCORE4_ENGINE_ID_TPC_0,
	GAUDI3_HDCORE4_ENGINE_ID_TPC_1,
	GAUDI3_HDCORE4_ENGINE_ID_TPC_2,
	GAUDI3_HDCORE4_ENGINE_ID_TPC_3,
	GAUDI3_HDCORE4_ENGINE_ID_TPC_4,
	GAUDI3_HDCORE4_ENGINE_ID_TPC_5,
	GAUDI3_HDCORE4_ENGINE_ID_TPC_6,
	GAUDI3_HDCORE4_ENGINE_ID_TPC_7,
	GAUDI3_HDCORE5_ENGINE_ID_TPC_0,
	GAUDI3_HDCORE5_ENGINE_ID_TPC_1,
	GAUDI3_HDCORE5_ENGINE_ID_TPC_2,
	GAUDI3_HDCORE5_ENGINE_ID_TPC_3,
	GAUDI3_HDCORE5_ENGINE_ID_TPC_4,
	GAUDI3_HDCORE5_ENGINE_ID_TPC_5,
	GAUDI3_HDCORE5_ENGINE_ID_TPC_6,
	GAUDI3_HDCORE5_ENGINE_ID_TPC_7,
	GAUDI3_HDCORE6_ENGINE_ID_TPC_0,
	GAUDI3_HDCORE6_ENGINE_ID_TPC_1,
	GAUDI3_HDCORE6_ENGINE_ID_TPC_2,
	GAUDI3_HDCORE6_ENGINE_ID_TPC_3,
	GAUDI3_HDCORE6_ENGINE_ID_TPC_4,
	GAUDI3_HDCORE6_ENGINE_ID_TPC_5,
	GAUDI3_HDCORE6_ENGINE_ID_TPC_6,
	GAUDI3_HDCORE6_ENGINE_ID_TPC_7,
	GAUDI3_HDCORE7_ENGINE_ID_TPC_0,
	GAUDI3_HDCORE7_ENGINE_ID_TPC_1,
	GAUDI3_HDCORE7_ENGINE_ID_TPC_2,
	GAUDI3_HDCORE7_ENGINE_ID_TPC_3,
	GAUDI3_HDCORE7_ENGINE_ID_TPC_4,
	GAUDI3_HDCORE7_ENGINE_ID_TPC_5,
	GAUDI3_HDCORE7_ENGINE_ID_TPC_6,
	GAUDI3_HDCORE7_ENGINE_ID_TPC_7,
	GAUDI3_HDCORE0_ENGINE_ID_TPC_8,
	GAUDI3_HDCORE2_ENGINE_ID_TPC_8,
	GAUDI3_HDCORE5_ENGINE_ID_TPC_8,
	GAUDI3_HDCORE7_ENGINE_ID_TPC_8
};

unsigned int gaudi3_mme_id_to_engine_id[] = {
	GAUDI3_HDCORE0_ENGINE_ID_MME_0,
	GAUDI3_HDCORE1_ENGINE_ID_MME_0,
	GAUDI3_HDCORE2_ENGINE_ID_MME_0,
	GAUDI3_HDCORE3_ENGINE_ID_MME_0,
	GAUDI3_HDCORE4_ENGINE_ID_MME_0,
	GAUDI3_HDCORE5_ENGINE_ID_MME_0,
	GAUDI3_HDCORE6_ENGINE_ID_MME_0,
	GAUDI3_HDCORE7_ENGINE_ID_MME_0
};

unsigned int gaudi3_edma_id_to_engine_id[] = {
	GAUDI3_HDCORE1_ENGINE_ID_EDMA_0,
	GAUDI3_HDCORE1_ENGINE_ID_EDMA_1,
	GAUDI3_HDCORE3_ENGINE_ID_EDMA_0,
	GAUDI3_HDCORE3_ENGINE_ID_EDMA_1,
	GAUDI3_HDCORE4_ENGINE_ID_EDMA_0,
	GAUDI3_HDCORE4_ENGINE_ID_EDMA_1,
	GAUDI3_HDCORE6_ENGINE_ID_EDMA_0,
	GAUDI3_HDCORE6_ENGINE_ID_EDMA_1
};

struct gaudi3_submission_ctx {
	uint64_t arc_flow_seq;
	uint64_t pqm_flow_seq;
};

KHASH_MAP_INIT_INT64(sctx, struct gaudi3_submission_ctx)

#define khash_submission_ctx_t khash_t(sctx)

struct gaudi3_priv {
	struct hltests_nic_cq *cq;
	pthread_mutex_t inflight_submissions_lock;
	khash_submission_ctx_t *inflight_submissions;
	uint64_t next_seq;
	uint64_t nic_ports_mask;
	uint32_t speed[NIC_MAX_NUM_OF_PORTS];
	uint32_t max_num_of_qps[NIC_MAX_NUM_OF_PORTS];
	uint32_t qp_idx_offset[NIC_MAX_NUM_OF_PORTS];
	uint32_t coll_qps_offset[NIC_MAX_NUM_OF_PORTS];
	uint32_t base_coll_qp_idx[NIC_MAX_NUM_OF_PORTS];
	uint32_t base_scale_out_coll_qp_idx[NIC_MAX_NUM_OF_PORTS];
	uint32_t max_num_of_coll_qps[NIC_MAX_NUM_OF_PORTS];
	uint32_t max_num_of_scale_out_coll_qps[NIC_MAX_NUM_OF_PORTS];
};

static uint32_t gaudi3_nic_get_max_num_of_ports(void)
{
	/* we support up to 2 ports per each NIC macro/engine */
	return NIC_MAX_NUM_OF_ENGINES * 2;
}

static int gaudi3_asic_priv_init(struct hltests_device *hdev)
{
	struct hlthunk_hw_ip_info hw_ip;
	struct gaudi3_priv *gaudi3;
	int rc, fd = hdev->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled)
		hdev->sim_dram_on_host = true;
	else
		hdev->sim_dram_on_host = false;

	hdev->priv = hlthunk_malloc(sizeof(struct gaudi3_priv));
	assert_non_null(hdev->priv);

	gaudi3 = hdev->priv;

	rc = pthread_mutex_init(&gaudi3->inflight_submissions_lock, NULL);
	assert_int_equal(rc, 0);

	gaudi3->inflight_submissions = kh_init(sctx);
	assert_non_null(gaudi3->inflight_submissions);

	gaudi3->next_seq = 1;

	return 0;
}

static void gaudi3_asic_priv_fini(struct hltests_device *hdev)
{
	struct gaudi3_priv *gaudi3 = hdev->priv;

	if (!gaudi3)
		return;

	kh_destroy(sctx, gaudi3->inflight_submissions);
	pthread_mutex_destroy(&gaudi3->inflight_submissions_lock);

	hlthunk_free(hdev->priv);
	hdev->priv = NULL;
}

static uint32_t ib_speed_to_nic_speed(uint32_t ib_speed)
{
	switch (ib_speed) {
	case HLTEST_IBV_SPEED_EDR:
		return SPEED_25000;
	case HLTEST_IBV_SPEED_HDR:
		return SPEED_50000;
	case HLTEST_IBV_SPEED_NDR:
		return SPEED_100000;
	default:
		return SPEED_50000;
	}
}

static uint32_t ib_width_to_lanes(uint32_t ib_width)
{
	switch (ib_width) {
	case HLTEST_IBV_WIDTH_1X:
		return 1;
	case HLTEST_IBV_WIDTH_2X:
		return 2;
	case HLTEST_IBV_WIDTH_4X:
		return 4;
	case HLTEST_IBV_WIDTH_8X:
		return 8;
	case HLTEST_IBV_WIDTH_12X:
		return 12;
	default:
		return 2;
	}
}

void gaudi3_calc_speed(uint32_t *speed, struct ibv_port_attr *ib_port_attr)
{
	uint32_t speed_per_lane, num_lanes;

	speed_per_lane = ib_speed_to_nic_speed(ib_port_attr->active_speed);
	num_lanes = ib_width_to_lanes(ib_port_attr->active_width);

	*speed = speed_per_lane * num_lanes;
}

static int gaudi3_nic_asic_priv_init(struct hltests_device *hdev, void *arg, uint64_t ctx_port_mask)
{
	struct hlthunk_nic_user_get_app_params_out app_params;
	struct hbldv_query_port_attr port_attr = {};
	struct gaudi3_priv *gaudi3 = hdev->priv;
	struct ibv_port_attr ib_port_attr = {};
	uint32_t port, max_n_ports;
	struct ibv_context *ibctx;
	int rc, fd = hdev->fd;

	rc = hlthunk_nic_get_enabled_ports_mask(fd, &gaudi3->nic_ports_mask);
	assert_int_equal(rc, 0);

	max_n_ports = gaudi3_nic_get_max_num_of_ports();

	if (hltests_nic_is_ibdev(fd))
		gaudi3->nic_ports_mask &= ctx_port_mask;

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(gaudi3->nic_ports_mask & BIT_ULL(port)))
			continue;

		if (hltests_nic_is_ibdev(fd)) {
			assert_non_null(arg);
			ibctx = (struct ibv_context *) arg;
			rc = hbldv_query_port(ibctx,
					      u8_safe(hltests_nic_to_ibdev_port_num(fd, port)),
					      &port_attr);
			assert_int_equal(rc, 0);

			rc = hlibv_query_port(ibctx,
					      (uint8_t)hltests_nic_to_ibdev_port_num(fd, port),
					      &ib_port_attr);
			assert_int_equal(rc, 0);

			gaudi3_calc_speed(&gaudi3->speed[port], &ib_port_attr);

			gaudi3->max_num_of_qps[port] = port_attr.max_num_of_qps;
			gaudi3->qp_idx_offset[port] = port_attr.max_allocated_qp_num;
			gaudi3->coll_qps_offset[port] = port_attr.coll_qps_offset;
			gaudi3->base_coll_qp_idx[port] = port_attr.base_coll_qp_num;
			gaudi3->base_scale_out_coll_qp_idx[port] =
							port_attr.base_scale_out_coll_qp_num;
			gaudi3->max_num_of_coll_qps[port] = port_attr.max_num_of_coll_qps;
			gaudi3->max_num_of_scale_out_coll_qps[port] =
							port_attr.max_num_of_scale_out_coll_qps;
		} else {
			memset(&app_params, 0, sizeof(app_params));

			rc = hlthunk_nic_user_get_app_params(fd, (uint32_t)port, &app_params);
			assert_int_equal(rc, 0);

			gaudi3->speed[port] = app_params.speed;
			gaudi3->max_num_of_qps[port] = app_params.max_num_of_qps;
			gaudi3->qp_idx_offset[port] = app_params.max_allocated_qp_idx;
			gaudi3->coll_qps_offset[port] = app_params.coll_qps_offset;
			gaudi3->base_coll_qp_idx[port] = app_params.base_coll_qp_idx;
			gaudi3->base_scale_out_coll_qp_idx[port] =
							app_params.base_scale_out_coll_qp_idx;
			gaudi3->max_num_of_coll_qps[port] = app_params.max_num_of_coll_qps;
			gaudi3->max_num_of_scale_out_coll_qps[port] =
							app_params.max_num_of_scale_out_coll_qps;
		}
	}

	return 0;
}

static int gaudi3_dram_pool_alloc(struct hltests_device *hdev, uint64_t size,
				uint64_t *return_addr)
{
	return -EOPNOTSUPP;
}

static void gaudi3_dram_pool_free(struct hltests_device *hdev, uint64_t addr,
					uint64_t size)
{

}

static int gaudi3_va_pool_alloc(struct hltests_device *hdev, uint64_t size, uint64_t *return_addr)
{
	return -EOPNOTSUPP;
}

static void gaudi3_va_pool_free(struct hltests_device *hdev, uint64_t addr, uint64_t size)
{

}

static uint64_t gaudi3_nic_get_port_mask(void)
{
	return (1ull << gaudi3_nic_get_max_num_of_ports()) - 1;
}

static int gaudi3_nic_get_min_conn_id(int fd, uint32_t port)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;

	assert_true(port < NIC_MAX_NUM_OF_PORTS);
	return uint_to_int_safe(NIC_MIN_CONN_ID + gaudi3->qp_idx_offset[port]);
}

static int gaudi3_nic_get_max_conn_id(int fd, uint32_t port)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;

	assert_true(port < NIC_MAX_NUM_OF_PORTS);
	return uint_to_int_safe(gaudi3->max_num_of_qps[port] + gaudi3->qp_idx_offset[port] - 1);
}

static int gaudi3_nic_get_max_num_of_qps(int fd, uint32_t port)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;

	assert_true(port < NIC_MAX_NUM_OF_PORTS);
	return uint_to_int_safe(gaudi3->max_num_of_qps[port]);
}

static uint32_t gaudi3_pdma_get_max_ch_id(int fd)
{
	return MAX_NUM_OF_DIES * NUM_OF_PDMA_CH_PER_DIE;
}

static bool hltests_is_sched_arc_eid(uint32_t engine_id)
{
	if ((engine_id >= GAUDI3_HDCORE1_ENGINE_ID_EDMA_0) &&
			(engine_id <= GAUDI3_HDCORE6_ENGINE_ID_EDMA_1))
		return true;

	if ((engine_id >= GAUDI3_HDCORE0_ENGINE_ID_MME_0) &&
			(engine_id <= GAUDI3_HDCORE7_ENGINE_ID_MME_0))
		return true;

	if ((engine_id >= GAUDI3_HDCORE0_ENGINE_ID_TPC_0) &&
			(engine_id <= GAUDI3_HDCORE7_ENGINE_ID_TPC_8))
		return true;

	if ((engine_id >= GAUDI3_HDCORE1_ENGINE_ID_ROT_0) &&
			(engine_id <= GAUDI3_HDCORE6_ENGINE_ID_ROT_1))
		return true;

	if ((engine_id >= GAUDI3_DIE0_ENGINE_ID_NIC_0) &&
			(engine_id <= GAUDI3_DIE1_ENGINE_ID_NIC_5))
		return true;

	return false;
}

static bool hltests_is_pdma_eid(uint32_t engine_id)
{
	return ((engine_id >= GAUDI3_DIE0_ENGINE_ID_PDMA_0_CH_0) &&
			(engine_id <= GAUDI3_DIE1_ENGINE_ID_PDMA_1_CH_5));
}

static uint64_t gaudi3_get_pdma_fence_addr(uint32_t qid)
{
	uint32_t grp_id, grp_ch_id, ch_id = PDMA_CH_ID(qid);

	grp_id = ch_id / NUM_OF_PDMA_CH_PER_GRP;
	grp_ch_id = ch_id % NUM_OF_PDMA_CH_PER_GRP;

	/* There are x4 possible fence addresses to be used for each PDMA channel
	 * Nevertheless, we will currently use only the 1st fence for each channel.
	 */
	return gaudi3_pdma_grp_blocks_bases[grp_id] +
			grp_ch_id * PDMA_CH_OFFSET + mmPDMA_CH_A_PQM_CH_FENCE_INC_0;
}

static uint64_t gaudi3_get_edma_fence_addr(uint32_t qid)
{
	uint64_t base_addr = 0;

	switch (qid) {
	case GAUDI3_HDCORE1_ENGINE_ID_EDMA_0:
		base_addr = mmHD1_SEDMA0_QM_BASE;
		break;
	case GAUDI3_HDCORE1_ENGINE_ID_EDMA_1:
		base_addr = mmHD1_SEDMA1_QM_BASE;
		break;
	case GAUDI3_HDCORE3_ENGINE_ID_EDMA_0:
		base_addr = mmHD3_SEDMA0_QM_BASE;
		break;
	case GAUDI3_HDCORE3_ENGINE_ID_EDMA_1:
		base_addr = mmHD3_SEDMA1_QM_BASE;
		break;
	case GAUDI3_HDCORE4_ENGINE_ID_EDMA_0:
		base_addr = mmHD4_SEDMA0_QM_BASE;
		break;
	case GAUDI3_HDCORE4_ENGINE_ID_EDMA_1:
		base_addr = mmHD4_SEDMA1_QM_BASE;
		break;
	case GAUDI3_HDCORE6_ENGINE_ID_EDMA_0:
		base_addr = mmHD6_SEDMA0_QM_BASE;
		break;
	case GAUDI3_HDCORE6_ENGINE_ID_EDMA_1:
		base_addr = mmHD6_SEDMA1_QM_BASE;
		break;
	default:
		return 0;
	}

	return base_addr + mmQMAN_CP_FENCE0_RDATA;
}

static uint64_t gaudi3_get_mme_fence_addr(uint32_t qid)
{
	return mmHD0_MME_QM_BASE +
		((qid - GAUDI3_HDCORE0_ENGINE_ID_MME_0) * HDCORE_OFFSET) + mmQMAN_CP_FENCE0_RDATA;
}

static uint64_t gaudi3_get_tpc_fence_addr(uint32_t qid)
{
	uint32_t hdcore_id, tpc_id;

	hdcore_id = (qid - GAUDI3_HDCORE0_ENGINE_ID_TPC_0) / NUM_OF_TPC_PER_HDCORE;
	tpc_id = (qid - GAUDI3_HDCORE0_ENGINE_ID_TPC_0) % NUM_OF_TPC_PER_HDCORE;

	return  mmHD0_TPC0_QM_BASE +
		(hdcore_id * HDCORE_OFFSET) +
		(tpc_id * (mmHD0_TPC1_QM_BASE - mmHD0_TPC0_QM_BASE)) + mmQMAN_CP_FENCE0_RDATA;
}

static uint64_t gaudi3_get_fence_addr(int fd, uint32_t qid, bool cmdq_fence)
{

	if ((qid >= GAUDI3_DIE0_ENGINE_ID_PDMA_0_CH_0) &&
			(qid <= GAUDI3_DIE1_ENGINE_ID_PDMA_1_CH_5))
		return gaudi3_get_pdma_fence_addr(qid);
	if ((qid >= GAUDI3_HDCORE1_ENGINE_ID_EDMA_0) &&
			(qid <= GAUDI3_HDCORE6_ENGINE_ID_EDMA_1))
		return gaudi3_get_edma_fence_addr(qid);
	if ((qid >= GAUDI3_HDCORE0_ENGINE_ID_MME_0) &&
			(qid <= GAUDI3_HDCORE7_ENGINE_ID_MME_0))
		return gaudi3_get_mme_fence_addr(qid);
	if ((qid >= GAUDI3_HDCORE0_ENGINE_ID_TPC_0) &&
			(qid <= GAUDI3_HDCORE7_ENGINE_ID_TPC_7))
		return gaudi3_get_tpc_fence_addr(qid);

	printf("Failed to configure fence - invalid QID %d\n", qid);
	fail_ret_val((uint64_t)-EINVAL);
}

static uint32_t gaudi3_add_pqm_ch_eb_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	struct hltests_pkt_info eb_pkt_info;

	/* Add LIN_PDMA packet, dma size=0 */
	memset(&eb_pkt_info, 0, sizeof(eb_pkt_info));
	eb_pkt_info.qid = pkt_info->qid;
	eb_pkt_info.eb = EB_FALSE;
	eb_pkt_info.mb = MB_FALSE;
	eb_pkt_info.dma.src_addr = 0;
	eb_pkt_info.dma.dst_addr = 0;
	eb_pkt_info.dma.size = 0;
	eb_pkt_info.dma.dma_dir = 0;
	eb_pkt_info.dma.comp_wr_addr =
			gaudi3_get_fence_addr(0, pkt_info->qid, false);
	eb_pkt_info.dma.comp_wr_data = 1;
	buf_off = gaudi3_add_dma_pkt(buffer, buf_off, &eb_pkt_info);

	/* Add FENCE packet */
	memset(&eb_pkt_info, 0, sizeof(eb_pkt_info));
	eb_pkt_info.qid = pkt_info->qid;
	eb_pkt_info.eb = EB_FALSE;
	eb_pkt_info.mb = MB_FALSE;
	eb_pkt_info.fence.dec_val = 1;
	eb_pkt_info.fence.gate_val = 1;
	eb_pkt_info.fence.fence_id = 0;
	buf_off = gaudi3_add_fence_pkt(buffer, buf_off, &eb_pkt_info);

	return buf_off;
}

static uint32_t gaudi3_add_pqm_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info, enum pqm_packet_id id)
{
	struct pqm_packet_nop packet;
	int rc;

	if (pkt_info->eb) {
		rc = !hltests_is_pdma_eid(pkt_info->qid);
		assert_int_equal_ret_val(rc, 0, buf_off);

		buf_off = gaudi3_add_pqm_ch_eb_pkt(buffer, buf_off, pkt_info);
	}

	memset(&packet, 0, sizeof(packet));
	packet.opcode = id;
	packet.msg_barrier = pkt_info->mb;

	packet.ctl = htole32(packet.ctl);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet, sizeof(packet));
}

static uint32_t gaudi3_add_pqm_nop_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	return gaudi3_add_pqm_pkt(buffer, buf_off, pkt_info, PQM_PACKET_NOP);
}

static uint32_t gaudi3_add_pqm_undef_opcode_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	return gaudi3_add_pqm_pkt(buffer, buf_off, pkt_info, PACKET_UNDEF_OPCODE);
}

static uint32_t gaudi3_add_msg_barrier_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	enum hltests_eb eb_prev = pkt_info->eb;

	if (hltests_is_pdma_eid(pkt_info->qid)) {
		pkt_info->eb = EB_FALSE;
		buf_off = gaudi3_add_pqm_nop_pkt(buffer, buf_off, pkt_info);
		pkt_info->eb = eb_prev;
	}

	return buf_off;
}

static uint32_t gaudi3_pqm_mb_eb_handler(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	if (hltests_is_pdma_eid(pkt_info->qid) && pkt_info->eb)
		buf_off = gaudi3_add_pqm_ch_eb_pkt(buffer, buf_off, pkt_info);

	if (pkt_info->mb)
		buf_off = gaudi3_add_msg_barrier_pkt(buffer, buf_off, pkt_info);

	return buf_off;
}

static uint32_t gaudi3_add_qman_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info, enum packet_id id)
{
	struct packet_nop packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = id;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;

	packet.ctl = htole32(packet.ctl);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi3_add_qman_nop_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	return gaudi3_add_qman_pkt(buffer, buf_off, pkt_info, PACKET_NOP);
}

static uint32_t gaudi3_add_qman_undef_opcode_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	return gaudi3_add_qman_pkt(buffer, buf_off, pkt_info, PACKET_UNDEF_OPCODE);
}

static uint32_t gaudi3_add_undef_opcode_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	if (hltests_is_pdma_eid(pkt_info->qid))
		return gaudi3_add_pqm_undef_opcode_pkt(buffer, buf_off, pkt_info);
	else if (hltests_is_sched_arc_eid(pkt_info->qid))
		return gaudi3_add_qman_undef_opcode_pkt(buffer, buf_off, pkt_info);

	printf("[%s] Error, QID %u isn't listed!\n", __func__, pkt_info->qid);

	return buf_off;
}

static uint32_t gaudi3_add_nop_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	if (hltests_is_pdma_eid(pkt_info->qid))
		return gaudi3_add_pqm_nop_pkt(buffer, buf_off, pkt_info);
	else if (hltests_is_sched_arc_eid(pkt_info->qid))
		return gaudi3_add_qman_nop_pkt(buffer, buf_off, pkt_info);
	else
		printf("[%s] Error, QID %u isn't listed!\n", __func__, pkt_info->qid);

	return buf_off;
}

static uint32_t gaudi3_add_pqm_msg_long_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	struct pqm_packet_msg_long packet;
	uint32_t buf_off_org = buf_off;
	int rc;

	rc = !hltests_is_pdma_eid(pkt_info->qid) && pkt_info->eb;
	assert_int_equal_ret_val(rc, 0, buf_off);

	buf_off = gaudi3_pqm_mb_eb_handler(buffer, buf_off, pkt_info);

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PQM_PACKET_MSG_LONG;
	packet.addr = pkt_info->msg_long.address;
	packet.value = pkt_info->msg_long.value;
	packet.pred = bitfield_safe_ret_val(pkt_info->pred, 5, buf_off_org);

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);
	packet.addr = htole64(packet.addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet, sizeof(packet));
}

static uint32_t gaudi3_add_qman_msg_long_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_long packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_MSG_LONG;
	packet.addr = pkt_info->msg_long.address;
	packet.value = pkt_info->msg_long.value;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.pred = bitfield_safe_ret_val(pkt_info->pred, 5, buf_off);

	/* TODO - decide on true values of weakly_ordered/no_snoop */
	packet.weakly_ordered = 0;
	packet.no_snoop = 0;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);
	packet.addr = htole64(packet.addr);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi3_add_msg_long_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	if (hltests_is_pdma_eid(pkt_info->qid))
		return gaudi3_add_pqm_msg_long_pkt(buffer, buf_off, pkt_info);
	else if (hltests_is_sched_arc_eid(pkt_info->qid))
		return gaudi3_add_qman_msg_long_pkt(buffer, buf_off, pkt_info);
	else
		printf("[%s] Error, QID %u isn't listed!\n", __func__, pkt_info->qid);

	return buf_off;
}

static uint32_t gaudi3_add_pqm_msg_short_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct pqm_packet_msg_short packet;
	uint32_t buf_off_org = buf_off;
	int rc;

	rc = !hltests_is_pdma_eid(pkt_info->qid) && pkt_info->eb;
	assert_int_equal_ret_val(rc, 0, buf_off_org);

	buf_off = gaudi3_pqm_mb_eb_handler(buffer, buf_off, pkt_info);

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PQM_PACKET_MSG_SHORT;
	packet.value = pkt_info->msg_short.value;

	/* Prior to using pqm_msg_short, verify that PQM_CMN_B_CP_MSG_BASE_ADDR
	 * is updated for the correct PDMA group.
	 */
	packet.base = bitfield_safe_ret_val(pkt_info->msg_short.base, 3, buf_off_org);
	packet.msg_addr_offset = pkt_info->msg_short.address;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet, sizeof(packet));
}

static uint32_t gaudi3_add_qman_msg_short_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_short packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_MSG_SHORT;
	packet.value = pkt_info->msg_short.value;
	packet.base_lsb = pkt_info->msg_short.base & (BIT(0) | BIT(1)); /* base[1:0] */
	packet.base_msb =
		bitfield_safe_ret_val((pkt_info->msg_short.base & BIT(2)) >> 2, /* base[2] */
				      1, buf_off);
	packet.msg_addr_offset = pkt_info->msg_short.address;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;

	/* TODO - decide on true values of weakly_ordered/no_snoop */
	packet.weakly_ordered = 0;
	packet.no_snoop = 0;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi3_add_msg_short_pkt(void *buffer, uint32_t buf_off,
				struct hltests_pkt_info *pkt_info)
{
	if (hltests_is_pdma_eid(pkt_info->qid))
		return gaudi3_add_pqm_msg_short_pkt(buffer, buf_off, pkt_info);
	else if (hltests_is_sched_arc_eid(pkt_info->qid))
		return gaudi3_add_qman_msg_short_pkt(buffer, buf_off, pkt_info);
	else
		printf("[%s] Error, QID %u isn't listed!\n", __func__, pkt_info->qid);

	return buf_off;
}

static bool gaudi3_is_pdma_direction_down(enum hltests_dma_direction dma_dir)
{
	if (DMA_DIR_HOST_TO_DRAM == dma_dir || DMA_DIR_HOST_TO_SRAM == dma_dir)
		return true;

	return false;
}

static uint32_t gaudi3_add_pqm_lin_pdma_pkt(void *buffer, uint32_t buf_off,
				struct hltests_pkt_info *pkt_info)
{
	uint64_t src_addr_hi, dst_addr_hi, comp_wr_addr_lo, comp_wr_addr_hi,
			comp_wr_data, fence_data;
	struct pqm_packet_lin_pdma *packet;
	uint32_t packet_size;
	int rc;

	/* We currently use a SINGLE completion write message upon an LPDMA completion.
	 * LPDMA pkt size will therefore grow by 3 * sizeof(uint64_t).
	 */
	packet_size = sizeof(*packet) + 3 * sizeof(packet->values[0]);

	packet = hlthunk_malloc(packet_size);
	if (!packet)
		return 0;

	rc = !hltests_is_pdma_eid(pkt_info->qid) && pkt_info->eb;
	assert_int_equal_ret_val(rc, 0, buf_off);

	buf_off = gaudi3_pqm_mb_eb_handler(buffer, buf_off, pkt_info);

	memset(packet, 0, packet_size);
	packet->opcode = PQM_PACKET_LIN_PDMA;
	packet->tsize = pkt_info->dma.size;
	packet->endian_swap = pkt_info->dma.endian_swap;
	packet->memset = pkt_info->dma.memset;
	packet->direction = gaudi3_is_pdma_direction_down(pkt_info->dma.dma_dir);

	/* WR_COMP0/1/2_ADDR_H are sent as part of the packet (depends on 'wrcomp' value) */
	packet->use_wr_comp_addr_hi_from_reg = 0;
	/* PDMA will NOT increment the CTX ID (See CTRL register) */
	packet->inc_context_id = 0;
	/* src/dst_addr are used as is (offset WON'T be added from SRC/DST_OFFSET_LO/HI regs */
	packet->add_offset_0 = 0;
	/* src/dst_addr_hi are configured here (values AREN'T taken from SRC/DST_BASE_ADDR_H regs */
	packet->src_dest_msb_from_reg = 0;
	/* Enable auto-write to COMMIT reg after config, to make the LinPDMA transaction start */
	packet->en_desc_commit = 1;

	packet->src_addr_lo = lower_32_bits(pkt_info->dma.src_addr);
	packet->dst_addr_lo = lower_32_bits(pkt_info->dma.dst_addr);

	src_addr_hi = upper_32_bits(pkt_info->dma.src_addr);
	dst_addr_hi = upper_32_bits(pkt_info->dma.dst_addr);
	packet->values[0] = src_addr_hi | (dst_addr_hi << 32);

	packet->ctl = htole32(packet->ctl);
	packet->tsize = htole32(packet->tsize);
	packet->src_addr_lo = htole32(packet->src_addr_lo);
	packet->dst_addr_lo = htole32(packet->dst_addr_lo);
	packet->values[0] = htole64(packet->values[0]);

	/* Configure a single message write upon completion */
	packet->wrcomp = 1;

	/* LPDMA of size > 0, is an indication that completion will write a DUMMY
	 * address (last SOB) to force serialization of LPDMA completion writes.
	 * Otherwise, completion is used as a part of EB-per-channel implementation.
	 */
	if (pkt_info->dma.size)
		pkt_info->dma.comp_wr_addr =
					mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_SOB_OBJ_0_0 +
					(8191 * sizeof(uint32_t));

	comp_wr_addr_lo = lower_32_bits(pkt_info->dma.comp_wr_addr);
	comp_wr_data = pkt_info->dma.comp_wr_data;
	packet->values[1] = comp_wr_addr_lo | (comp_wr_data << 32);
	packet->values[1] = htole64(packet->values[1]);

	comp_wr_addr_hi = upper_32_bits(pkt_info->dma.comp_wr_addr);
	fence_data = 0;
	packet->values[2] = comp_wr_addr_hi | (fence_data << 32);
	packet->values[2] = htole64(packet->values[2]);

	buf_off = hltests_add_packet_to_cb(buffer, buf_off, packet, packet_size);
	hlthunk_free(packet);

	return buf_off;
}

static uint32_t gaudi3_add_qman_lin_edma_pkt(void *buffer, uint32_t buf_off,
						struct hltests_pkt_info *pkt_info)
{
	uint32_t src_addr_hi, dst_addr_hi;
	struct packet_lin_dma packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_LIN_DMA;
	packet.src_addr_lo = lower_32_bits(pkt_info->dma.src_addr);
	packet.dst_addr_lo = lower_32_bits(pkt_info->dma.dst_addr);
	packet.tsize = pkt_info->dma.size;
	packet.wrcomp = 0;
	packet.endian_swap = pkt_info->dma.endian_swap;
	packet.memset = pkt_info->dma.memset;
	packet.fence_en = 0;
	packet.use_wr_comp_addr_hi_from_reg = 0;
	packet.consecutive_comp1_2_addr_l = 0;
	packet.inc_context_id = 0;
	packet.add_offset_0 = 0;
	packet.src_dest_msb_from_reg = 0;
	packet.en_desc_commit = 1;
	packet.predpack_convert_en = 0;
	packet.predpack_convert_en = 0;
	packet.convert_dataclipping = 0;
	packet.convert_rounding = 0;
	/* Force using EB as a W/A to EDMA's back-pressure HW failure */
	packet.eng_barrier = EB_TRUE;
	packet.msg_barrier = pkt_info->mb;

	packet.ctl = htole32(packet.ctl);
	packet.tsize = htole32(packet.tsize);
	packet.src_addr_lo = htole32(packet.src_addr_lo);
	packet.dst_addr_lo = htole32(packet.dst_addr_lo);

	buf_off = hltests_add_packet_to_cb(buffer, buf_off, &packet, sizeof(packet));

	src_addr_hi = htole32(upper_32_bits(pkt_info->dma.src_addr));
	buf_off = hltests_add_packet_to_cb(buffer, buf_off, &src_addr_hi, sizeof(src_addr_hi));

	dst_addr_hi = htole32(upper_32_bits(pkt_info->dma.dst_addr));
	return hltests_add_packet_to_cb(buffer, buf_off, &dst_addr_hi, sizeof(dst_addr_hi));
}

static uint32_t gaudi3_add_dma_pkt(void *buffer, uint32_t buf_off,
				struct hltests_pkt_info *pkt_info)
{
	if (hltests_is_pdma_eid(pkt_info->qid))
		return gaudi3_add_pqm_lin_pdma_pkt(buffer, buf_off, pkt_info);
	else if (hltests_is_sched_arc_eid(pkt_info->qid))
		return gaudi3_add_qman_lin_edma_pkt(buffer, buf_off, pkt_info);
	else
		printf("[%s] Error, QID %u isn't listed!\n", __func__, pkt_info->qid);

	return buf_off;
}

static void gaudi3_pdma_unmap_lbw_blocks(int fd, struct hltests_pdma_db *pdma_db)
{
	struct pdma_ch_info *ch_info = pdma_db->ch_info;
	int i;

	for (i = 0 ; i < pdma_db->pdma_ch_max ; i++) {
		if (ch_info[i].enabled)
			hltests_unmap_hw_block(fd, ch_info[i].ch_host_addr,
					ch_info[i].ch_block_size);
	}
}

/* H9 has a single PDMA engine in every die.
 * A PDMA engine shares its BW among x12 PDMA-channels, which are separated-
 * into x2 groups, 6-channel each (AKA SPDMA). Each group has its own PQM.
 * In the standard case of a dual-die-ASIC, we will have x2 PDMA engines,
 * x4 PDMA groups and x24 channels in total (most will belong to the user).
 */
static int gaudi3_pdma_map_lbw_blocks(int fd, struct hltests_pdma_db *pdma_db)
{
	struct pdma_ch_info *ch_info = pdma_db->ch_info;
	uint16_t ch_id, ch_cnt = 0, i, j;
	struct hlthunk_hw_ip_info hw_ip;
	uint64_t base_addr, block_addr;
	int rc;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	pdma_db->user_en_ch_mask = hw_ip.pdma_user_owned_ch_mask;

	pdma_db->pdma_ch_max = MAX_NUM_OF_DIES * NUM_OF_PDMA_CH_PER_DIE;
	pdma_db->pdma_grp_max = MAX_NUM_OF_DIES * NUM_OF_PDMA_GRP_PER_DIE;

	pdma_db->pdma_grp_ch_max = NUM_OF_PDMA_CH_PER_GRP;

	for (i = 0 ; i < pdma_db->pdma_grp_max ; i++) {
		base_addr = gaudi3_pdma_grp_blocks_bases[i];
		for (j = 0 ; j < pdma_db->pdma_grp_ch_max ; j++) {
			ch_id = (uint16_t)(i * pdma_db->pdma_grp_ch_max + j);
			block_addr = base_addr + j * PDMA_CH_OFFSET;
			if (!(pdma_db->user_en_ch_mask & BIT(ch_id)))
				continue;

			ch_info[ch_id].ch_host_addr =
					hltests_map_hw_block(fd, block_addr,
					&ch_info[ch_id].ch_block_size);
			if (!ch_info[ch_id].ch_host_addr) {
				printf("Failed to map HW block of PDMA ch %d\n",
						ch_id);
				rc = -ENOMEM;
				goto unmap_pdma_data;
			}

			ch_info[ch_id].enabled = true;

			if (ch_cnt < MAX_PDMA_CH_NUM)
				pdma_db->ch_qid_lut[ch_cnt++] =
						GAUDI3_DIE0_ENGINE_ID_PDMA_0_CH_0 + ch_id;
		}
	}
	assert_in_range(ch_cnt, 0, MAX_PDMA_CH_NUM);

	return 0;

unmap_pdma_data:
	gaudi3_pdma_unmap_lbw_blocks(fd, pdma_db);

	return rc;
}

/* Note that PQM has no streams - instead it supports multiple channels */
static uint32_t gaudi3_get_pdma_down_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			enum hltests_stream_id stream)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	assert_in_range_ret_val(stream, 0, NUM_OF_STREAMS - 1, (uint32_t)-1);

	return hdev->pdma_db.ch_qid_lut[stream];
}

/* Note that PQM has no streams - instead it supports multiple channels */
static uint32_t gaudi3_get_pdma_up_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			enum hltests_stream_id stream)
{
	assert_in_range_ret_val(stream, 0, NUM_OF_STREAMS - 1, (uint32_t)-1);

	return GAUDI3_DIE1_ENGINE_ID_PDMA_0_CH_0 + stream;
}

static int gaudi3_pdma_reset_pqm_ch(int fd, struct pdma_ch_info *ch_info)
{
	uint32_t q_size, q_handle_lo, q_handle_hi;
	uint8_t *reg_addr;
	uint64_t q_handle;
	uint32_t cfg_mode;
	int rc;

	/* Set PQM descriptor fetching to be of mode 'PI/CI in memory' (0x1).
	 * This write triggers a reset of the following registers:
	 * PI/CI, BASE H/L, SIZE.
	 */
	cfg_mode = FIELD_PREP((uint32_t)PDMA_CH_A_PQM_CH_DESC_SUBMIT_FIFO_CFG_MODE_M, 0x1);
	reg_addr = ch_info->ch_host_addr + mmPDMA_CH_A_PQM_CH_DESC_SUBMIT_FIFO_CFG;
	rc = hltests_write_lbw_reg(fd, reg_addr, cfg_mode);
	if (rc)
		return rc;

	/* Assumptions:
	 * - The size of the submission queue in Bytes.
	 * - In order to ease HW implementation, q size value written to HW must
	 * satisfy: q_size == 2^x -1.
	 * HW will add 0x1 to it, such that q_size in HW will be a power of 2.
	 */
	q_size = FIELD_PREP(PDMA_CH_A_PQM_CH_MSQ_SIZE_VAL_M,
			ch_info->submission_q_size - 0x1);
	reg_addr = ch_info->ch_host_addr + mmPDMA_CH_A_PQM_CH_MSQ_SIZE;
	rc = hltests_write_lbw_reg(fd, reg_addr, q_size);
	if (rc)
		return rc;

	q_handle = ch_info->submission_q_handle;

	q_handle_lo = FIELD_PREP(PDMA_CH_A_PQM_CH_MSQ_BASE_L_VAL_M,
			lower_32_bits(q_handle));
	reg_addr = ch_info->ch_host_addr + mmPDMA_CH_A_PQM_CH_MSQ_BASE_L;
	rc = hltests_write_lbw_reg(fd, reg_addr, q_handle_lo);
	if (rc)
		return rc;

	q_handle_hi = FIELD_PREP(PDMA_CH_A_PQM_CH_MSQ_BASE_H_VAL_M,
			upper_32_bits(q_handle));
	reg_addr = ch_info->ch_host_addr + mmPDMA_CH_A_PQM_CH_MSQ_BASE_H;

	return hltests_write_lbw_reg(fd, reg_addr, q_handle_hi);
}

static int gaudi3_pdma_config_pqm_cp_msg_base_addr(int fd, struct hltests_pdma_db *pdma_db)
{
	uint64_t pqm_cp_msg_base_addr[4], dev_addr, reg_base_addr;
	uint32_t base_lo, base_hi, cb_size = 0;
	struct hltests_pkt_info pkt_info = {};
	void *cb;
	unsigned int j;
	int i;

	cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	if (!cb)
		return -ENOMEM;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = hltests_get_dma_down_qid(fd, STREAM0);
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;

	/* We currently use only the first four base addresses */
	pqm_cp_msg_base_addr[0] = mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_MON_PAY_ADDRL_0_0;
	pqm_cp_msg_base_addr[1] = mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_SOB_OBJ_0_0;
	pqm_cp_msg_base_addr[2] =
		mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_MON_PAY_ADDRL_0_0 + HDCORE_OFFSET;
	pqm_cp_msg_base_addr[3] =
		mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_SOB_OBJ_0_0 + HDCORE_OFFSET;

	for (i = 0 ; i < pdma_db->pdma_grp_max ; i++) {
		reg_base_addr = gaudi3_pdma_grp_blocks_bases[i];

		for (j = 0 ; j < 4 ; j++) {
			base_lo = lower_32_bits(pqm_cp_msg_base_addr[j]);
			base_hi = upper_32_bits(pqm_cp_msg_base_addr[j]);
			dev_addr = reg_base_addr + PDMA_CMN_B_PQM_CP_MSG_BASE_ADDR_0_OFFSET;

			dev_addr += sizeof(uint64_t) * j;
			pkt_info.msg_long.address = dev_addr;
			pkt_info.msg_long.value = base_lo;
			cb_size = gaudi3_add_msg_long_pkt(cb, cb_size, &pkt_info);

			dev_addr += sizeof(uint32_t);
			pkt_info.msg_long.address = dev_addr;
			pkt_info.msg_long.value = base_hi;
			cb_size = gaudi3_add_msg_long_pkt(cb, cb_size, &pkt_info);
		}
	}

	return hltests_submit_and_wait_cs(fd, cb, cb_size, pkt_info.qid,
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

static int gaudi3_pdma_config_ch_blocks(int fd, struct hltests_pdma_db *pdma_db)
{
	struct pdma_ch_info *ch_info = pdma_db->ch_info;
	int i, rc;

	for (i = 0 ; i < pdma_db->pdma_ch_max ; i++) {
		if (!ch_info[i].enabled)
			continue;

		rc = gaudi3_pdma_reset_pqm_ch(fd, &ch_info[i]);
		if (rc)
			return rc;
	}

	rc = gaudi3_pdma_config_pqm_cp_msg_base_addr(fd, pdma_db);
	if (rc)
		return rc;

	return 0;
}

static int gaudi3_pqm_add_pkts_to_submission_q(int fd, struct hltests_device *hdev,
		uint8_t *cb, uint32_t cb_size, uint32_t queue_idx)
{
	uint32_t ch_idx = PDMA_CH_ID(queue_idx), first_cnk, second_cnk;
	struct pdma_ch_info *ch_info = &hdev->pdma_db.ch_info[ch_idx];
	uint32_t pi_shadow_mod = ch_info->pi_shadow % ch_info->submission_q_size;
	uint32_t ci_shadow_mod = ch_info->ci_shadow % ch_info->submission_q_size;

	if (pi_shadow_mod >= ci_shadow_mod) {
		first_cnk = MIN(ch_info->submission_q_size - pi_shadow_mod, cb_size);
		memcpy(ch_info->submission_q + pi_shadow_mod, cb, first_cnk);
		if (first_cnk == cb_size)
			goto end;
		second_cnk = cb_size - first_cnk;
		memcpy(ch_info->submission_q, cb + first_cnk, second_cnk);
	} else {
		memcpy(ch_info->submission_q + pi_shadow_mod, cb, cb_size);
	}

end:
	/* User should advance PI by the number of Bytes written.
	 * This number is expected to be a multiply of 8B (i.e., 8B aligned),
	 * thus lower 3b are expected to be 0.
	 */
	ch_info->pi_shadow += cb_size;
	assert_int_equal(!IS_8B_ALIGNED(ch_info->pi_shadow), 0);

	return 0;
}

static int gaudi3_pdma_pqm_send(int fd, uint32_t queue_idx)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	uint32_t ch_idx = PDMA_CH_ID(queue_idx);
	struct pdma_ch_info *ch_info = &hdev->pdma_db.ch_info[ch_idx];
	uint8_t *reg_addr;
	uint32_t pi_idx;

	pi_idx = u32_safe(ch_info->pi_shadow << PDMA_CH_A_PQM_CH_MSQ_PI_VAL_S);
	reg_addr = ch_info->ch_host_addr + mmPDMA_CH_A_PQM_CH_MSQ_PI;

	return hltests_write_lbw_reg(fd, reg_addr, pi_idx);
}

static int gaudi3_pdma_update_pqm_ch_ci(int fd, uint16_t queue_idx)
{
	uint32_t ci_asic, cid = PDMA_CH_ID(queue_idx);
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct pdma_ch_info *ch_info = &hdev->pdma_db.ch_info[cid];
	uint8_t *reg_addr;
	int rc;

	reg_addr = ch_info->ch_host_addr + mmPDMA_CH_A_PQM_CH_MSQ_CI;
	rc = hltests_read_lbw_reg(fd, reg_addr, &ci_asic);
	if (rc)
		return rc;

	ch_info->ci_shadow = ci_asic;

	return 0;
}

static bool gaudi3_pqm_check_sufficient_dispatch_space(int fd, uint32_t cb_size, uint16_t queue_idx)
{
	uint32_t space_in_bytes, cid = PDMA_CH_ID(queue_idx);
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct pdma_ch_info *ch_info = &hdev->pdma_db.ch_info[cid];
	int rc;

	assert_in_range(cb_size, 0, ch_info->submission_q_size);

	/* SW-172941: assert upon PQM wraparound */
	assert_in_range(cb_size, 0, ch_info->submission_q_size -
			ch_info->pi_shadow % ch_info->submission_q_size);

	space_in_bytes = ch_info->submission_q_size -
			(ch_info->pi_shadow - ch_info->ci_shadow);

	if (cb_size <= space_in_bytes)
		return true;

	/* We (allegedly) have no room for more packets, so we must update ci_shadow
	 * and accurately recalculate the free space. The submission queue - being so
	 * big - allows us to read PQM's CI only once PI has gone far enough.
	 */
	rc = gaudi3_pdma_update_pqm_ch_ci(fd, queue_idx);
	if (rc)
		return rc;

	space_in_bytes = ch_info->submission_q_size -
			(ch_info->pi_shadow - ch_info->ci_shadow);

	return (cb_size <= space_in_bytes);
}

static int gaudi3_pqm_send_cb_mode_pi_ci_mem(int fd, struct hltests_cs_chunk *chunk)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	int rc;

	if (chunk->queue_index > UINT16_MAX)
		return -E2BIG;

	if (!gaudi3_pqm_check_sufficient_dispatch_space(fd, chunk->cb_size,
							(uint16_t)chunk->queue_index))
		return -ENOMEM;

	rc = gaudi3_pqm_add_pkts_to_submission_q(fd, hdev, chunk->cb_ptr,
			chunk->cb_size, chunk->queue_index);
	if (rc)
		return rc;

	return gaudi3_pdma_pqm_send(fd, chunk->queue_index);
}

/* At this stage the completion mechanism is not initialized.
 * So we rely on a different, less robust mechnism. Simply add
 * a SOB write to the end of each CB, then wait for sob to reach
 * some value.
 * To zero SOB, use 2 SOBs: one active which is used for completion,
 * one inactive being zeroed. Swap the SOBs on each submission.
 * Limitation: only one CB can be in air at the given point in time.
 */
static int gaudi3_pqm_submit_cs_no_cq(int fd, struct hltests_cs_chunk *arr, uint32_t arr_size,
					uint64_t *seq)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	uint32_t cid = PDMA_CH_ID(arr[0].queue_index);
	struct hltests_pkt_info pkt_info;
	struct pdma_ch_info *ch_info;
	int rc, i;

	if (!hdev)
		return -ENODEV;

	if (!arr_size)
		return 0;

	ch_info = &hdev->pdma_db.ch_info[cid];

	assert_int_equal(pthread_mutex_lock(&ch_info->pi_ci_lock), 0);

	for (i = 0; i < arr_size; i++) {
		/* Zero inactive SOB */
		if (!i) {
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.qid = arr[i].queue_index;
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_FALSE;
			pkt_info.write_to_sob.sob_id = PRE_INIT_CQ_SOB_ID +
				!hdev->completion_db.pre_cq_ready_active_sob;
			pkt_info.write_to_sob.value = 0;
			pkt_info.write_to_sob.mode = SOB_SET;
			arr[i].cb_size = hltests_add_write_to_sob_pkt(
				fd, arr[i].cb_ptr, arr[i].cb_size, &pkt_info);
		}

		/* Inc active SOB */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = arr[i].queue_index;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.write_to_sob.sob_id = PRE_INIT_CQ_SOB_ID +
			hdev->completion_db.pre_cq_ready_active_sob;
		pkt_info.write_to_sob.value = 1;
		pkt_info.write_to_sob.mode = SOB_ADD;
		arr[i].cb_size = hltests_add_write_to_sob_pkt(
			fd, arr[i].cb_ptr, arr[i].cb_size, &pkt_info);

		rc = gaudi3_pqm_send_cb_mode_pi_ci_mem(fd, &arr[i]);
		if (rc)
			break;
	}

	*seq = arr_size;

	assert_int_equal(pthread_mutex_unlock(&ch_info->pi_ci_lock), 0);

	return rc;
}

static int gaudi3_debug_completion(int fd, uint32_t dbe_sob_idx, uint32_t sync_sob_idx,
					uint32_t expected_dbe_sob, uint32_t expected_sync_sob)
{
	uint32_t objs_blk_sz, *obj_blk, dbe_sob_val, sync_sob_val;
	int rc;

	obj_blk = hltests_map_hw_block(fd, PRE_INIT_CQ_SM_BLOCK, &objs_blk_sz);
	if (!obj_blk)
		return -EFAULT;

	dbe_sob_idx -= NUM_OF_SOBS_IN_BATCH;
	rc = hltests_read_lbw_mem(fd, &dbe_sob_val, &obj_blk[dbe_sob_idx], sizeof(dbe_sob_val));
	if (rc) {
		printf("failed to read dbe sob val %d\n", rc);
		goto out;
	}
	printf("dbe sob val = %u, expcted dbe sob val %u\n", dbe_sob_val, expected_dbe_sob);

	/* if dbe sob is not as expected then no point to test sync sob val */
	if (dbe_sob_val != expected_dbe_sob)
		goto out;

	sync_sob_idx -= NUM_OF_SOBS_IN_BATCH;
	rc = hltests_read_lbw_mem(fd, &sync_sob_val, &obj_blk[sync_sob_idx], sizeof(sync_sob_val));
	if (rc) {
		printf("failed to read sync sob val %d\n", rc);
		goto out;
	}

	printf("sync sob val = %u, expected sync sob val = %u\n", sync_sob_val, expected_sync_sob);

out:
	hltests_unmap_hw_block(fd, obj_blk, objs_blk_sz);
	return rc;
}

static int gaudi3_wait_for_cs_no_cq(int fd, uint64_t seq)
{
	uint64_t timeout_ns = WAIT_FOR_CS_DEFAULT_TIMEOUT * 1000UL;
	useconds_t sleep_us = 100;
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	uint32_t objs_blk_sz, *obj_blk, sob_idx, sob_val;
	struct timespec t_start, t_end;
	int rc;

	obj_blk = hltests_map_hw_block(fd, PRE_INIT_CQ_SM_BLOCK, &objs_blk_sz);
	if (!obj_blk)
		return -EFAULT;

	sob_idx = PRE_INIT_CQ_SOB_ID_IN_HDCORE +
		  hdev->completion_db.pre_cq_ready_active_sob;

	clock_gettime(CLOCK_REALTIME, &t_start);
	while (true) {
		rc = hltests_read_lbw_mem(fd, &sob_val, &obj_blk[sob_idx],
						sizeof(sob_val));
		if (rc)
			goto out;

		if (sob_val == seq)
			break;

		usleep(sleep_us);
		clock_gettime(CLOCK_REALTIME, &t_end);
		if (((uint64_t)t_end.tv_sec - (uint64_t)t_start.tv_sec) * 1000000000UL +
		    ((uint64_t)t_end.tv_nsec - (uint64_t)t_start.tv_nsec) > timeout_ns) {
			rc = HL_WAIT_CS_STATUS_TIMEDOUT;
			goto out;
		}
	}

	rc = HL_WAIT_CS_STATUS_COMPLETED;
out:
	hdev->completion_db.pre_cq_ready_active_sob =
		!hdev->completion_db.pre_cq_ready_active_sob;
	hltests_unmap_hw_block(fd, obj_blk, objs_blk_sz);

	return rc;
}

static int gaudi3_pqm_submit_cs(int fd, struct hltests_cs_chunk *arr,
		uint32_t arr_size, uint64_t *seq)
{
	uint32_t cid = PDMA_CH_ID(arr[0].queue_index);
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct pdma_ch_info *ch_info = &hdev->pdma_db.ch_info[cid];

	return hltests_submit_job(fd, arr, arr_size, seq,
						&ch_info->pi_ci_lock,
						gaudi3_pqm_send_cb_mode_pi_ci_mem);
}

static int gaudi3_split_array(struct hltests_cs_chunk *arr, uint32_t arr_size,
				struct hltests_cs_chunk **arc_arr, uint32_t *arc_arr_size,
				struct hltests_cs_chunk **pqm_arr, uint32_t *pqm_arr_size)
{
	uint32_t npqm = 0;
	int i, j, k;

	if (!arr && arr_size > 0)
		return -EINVAL;

	for (i = 0; i < arr_size; ++i) {
		if (hltests_is_pdma_eid(arr[i].queue_index))
			npqm++;
	}

	*pqm_arr_size = npqm;
	*arc_arr_size = arr_size - npqm;

	if (*pqm_arr_size) {
		*pqm_arr = hlthunk_malloc(*pqm_arr_size * sizeof(struct hltests_cs_chunk));
		if (!*pqm_arr)
			return -ENOMEM;
	} else {
		*pqm_arr = NULL;
	}

	if (*arc_arr_size) {
		*arc_arr = hlthunk_malloc(*arc_arr_size * sizeof(struct hltests_cs_chunk));
		if (!*arc_arr) {
			hlthunk_free(*pqm_arr);
			*pqm_arr = NULL;
			return -ENOMEM;
		}
	} else {
		*arc_arr = NULL;
	}

	for (i = 0, j = 0, k = 0; i < arr_size; ++i) {
		if (hltests_is_pdma_eid(arr[i].queue_index)) {
			if (*pqm_arr && j < *pqm_arr_size)
				(*pqm_arr)[j++] = arr[i];
		} else {
			if (*arc_arr && k < *arc_arr_size)
				(*arc_arr)[k++] = arr[i];
		}
	}

	return 0;
}

static int gaudi3_submit_array(int fd, struct hltests_cs_chunk *arr,
		uint32_t arr_size, uint32_t flags, uint32_t timeout,
		uint64_t *seq)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;
	struct hltests_cs_chunk *arc_arr, *pqm_arr;
	struct gaudi3_submission_ctx sctx = {0};
	uint32_t arc_arr_size, pqm_arr_size;
	khint64_t k;
	int rc;

	rc = gaudi3_split_array(arr, arr_size, &arc_arr, &arc_arr_size, &pqm_arr,
			&pqm_arr_size);
	if (rc)
		return rc;

	if (arc_arr_size) {
		/* Meantime submit only to ARC0 scheduler */
		rc = hltests_sched_arc_submit_cs(fd, arc_arr, arc_arr_size,
				CPU_ID_SCHED_ARC0, &sctx.arc_flow_seq);
		if (rc)
			goto out;
	}

	if (pqm_arr_size) {
		rc = gaudi3_pqm_submit_cs(fd, pqm_arr, pqm_arr_size,
				&sctx.pqm_flow_seq);
		if (rc)
			goto out;
	}

	pthread_mutex_lock(&gaudi3->inflight_submissions_lock);
	*seq = gaudi3->next_seq++;
	k = kh_put(sctx, gaudi3->inflight_submissions, *seq, &rc);
	if (rc == -1) {
		rc = -ENOMEM;
	} else {
		rc = 0;
		kh_val(gaudi3->inflight_submissions, k) = sctx;
	}
	pthread_mutex_unlock(&gaudi3->inflight_submissions_lock);

out:
	hlthunk_free(arc_arr);
	hlthunk_free(pqm_arr);

	return rc;
}

static int gaudi3_submit_cs(int fd, struct hltests_cs_chunk *restore_arr,
		uint32_t restore_arr_size, struct hltests_cs_chunk *execute_arr,
		uint32_t execute_arr_size, uint32_t flags, uint32_t timeout,
		uint64_t *seq)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	int rc;

	if (hltests_is_pdma_eid(execute_arr[0].queue_index)) {
		if (!hdev->completion_db.cq_ready)
			return gaudi3_pqm_submit_cs_no_cq(fd, execute_arr,
					execute_arr_size, seq);
	}

	rc = gaudi3_submit_array(fd, restore_arr, restore_arr_size, flags, timeout, seq);
	if (rc || !execute_arr_size)
		return rc;
	rc = hltests_wait_for_cs(fd, *seq, timeout);
	if (rc)
		return rc;

	return gaudi3_submit_array(fd, execute_arr, execute_arr_size, flags, timeout, seq);
}

static int gaudi3_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;
	struct gaudi3_submission_ctx sctx;
	khint64_t k;
	int rc = 0;

	assert_true(timeout_us <= INT64_MAX);

	if (!hdev->completion_db.cq_ready)
		/* If CQ wasn't initialized, we can't expect to use it */
		return gaudi3_wait_for_cs_no_cq(fd, seq);

	pthread_mutex_lock(&gaudi3->inflight_submissions_lock);
	k = kh_get(sctx, gaudi3->inflight_submissions, seq);
	if (k == kh_end(gaudi3->inflight_submissions)) {
		printf("can't wait on seq %lu - does not exist\n", seq);
		pthread_mutex_unlock(&gaudi3->inflight_submissions_lock);
		return HL_WAIT_CS_STATUS_ABORTED;
	}
	sctx = kh_val(gaudi3->inflight_submissions, k);
	pthread_mutex_unlock(&gaudi3->inflight_submissions_lock);

	if (sctx.pqm_flow_seq) {
		rc = hltests_wait_for_job(fd, sctx.pqm_flow_seq, (int64_t)timeout_us);
		if (rc)
			return rc;
	}

	if (sctx.arc_flow_seq)
		return hltests_wait_for_job(fd, sctx.arc_flow_seq, (int64_t)timeout_us);

	return HL_WAIT_CS_STATUS_COMPLETED;
}

static int gaudi3_wait_for_cs_until_not_busy(int fd, uint64_t seq)
{
	return gaudi3_wait_for_cs(fd, seq, WAIT_FOR_CS_DEFAULT_TIMEOUT_NON_LEGACY);
}

static int gaudi3_get_max_pll_idx(void)
{
	return HL_GAUDI3_PLL_MAX;
}

static const char *gaudi3_stringify_pll_idx(uint32_t pll_idx)
{
	switch (pll_idx) {
	case HL_GAUDI3_CPU_PLL: return "HL_GAUDI3_CPU_PLL";
	case HL_GAUDI3_PCI_PLL: return "HL_GAUDI3_PCI_PLL";
	case HL_GAUDI3_HBM_PLL: return "HL_GAUDI3_HBM_PLL";
	case HL_GAUDI3_NIC_PLL: return "HL_GAUDI3_NIC_PLL";
	case HL_GAUDI3_DMA_PLL: return "HL_GAUDI3_DMA_PLL";
	case HL_GAUDI3_MESH_PLL: return "HL_GAUDI3_MESH_PLL";
	case HL_GAUDI3_MME_PLL: return "HL_GAUDI3_MME_PLL";
	case HL_GAUDI3_TPC_PLL: return "HL_GAUDI3_TPC_PLL";
	case HL_GAUDI3_VID_PLL: return "HL_GAUDI3_VID_PLL";
	case HL_GAUDI3_D2D_PLL: return "HL_GAUDI3_D2D_PLL";
	case HL_GAUDI3_CS_PLL: return "HL_GAUDI3_CS_PLL";
	case HL_GAUDI3_C2C_PLL: return "HL_GAUDI3_C2C_PLL";
	case HL_GAUDI3_NCH_PLL: return "HL_GAUDI3_NCH_PLL";
	case HL_GAUDI3_C2M_PLL: return "HL_GAUDI3_C2M_PLL";
	default: return "INVALID_PLL_INDEX";
	}
}

static const char *gaudi3_stringify_pll_type(uint32_t pll_idx, uint8_t type_idx)
{
	switch (pll_idx) {
	case HL_GAUDI3_CPU_PLL:
		switch (type_idx) {
		case 0: return "PSOC_HBW|PSOC_TRACE|CPU CLK";
		case 1: return "PSOC_LBW|CPU_LBW CLK";
		case 2: return "PSOC_CFG|PSOC_DBG CLK";
		case 3: return "CPU_TS|PSOC_UART|PSOC_SPI|PSOC_I2C CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI3_PCI_PLL:
		switch (type_idx) {
		case 0: return "PCI_LBW|PCI_TRACE|PMMU_LBW|PMMU_TRACE CLK";
		case 1: return "N/A";
		case 2: return "PCI_DBG|PCI_PHY|PRT_CFG|PCI_AUX|PMMU_DBG CLK";
		case 3: return "N/A";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI3_HBM_PLL:
		switch (type_idx) {
		case 0: return "HBM_HBW CLK";
		case 1: return "HBM CLK";
		case 2: return "HBM_TRACE CLK";
		case 3: return "HBM_DBG|HBM_LBW CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI3_NIC_PLL:
		switch (type_idx) {
		case 0: return "PRT_HBW CLK";
		case 1: return "NIC|NIC_EARC CLK";
		case 2: return "PRT_TRACE|PRT_LBW CLK";
		case 3: return "PRT_ANLT CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI3_DMA_PLL:
		switch (type_idx) {
		case 0: return "EDMA_HBW CLK";
		case 1: return "EDMA_LBW|EDMA_EARC CLK";
		case 2: return "EDMA_TRACE CLK";
		case 3: return "EDMA_DBG CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI3_MESH_PLL:
		switch (type_idx) {
		case 0: return "MESH_HBW CLK";
		case 1: return "MESH_LBW|STLB_HBW CLK";
		case 2: return "MESH_TRACE CLK";
		case 3: return "MESH_DBG CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI3_MME_PLL:
		switch (type_idx) {
		case 0: return "MME_HBW CLK";
		case 1: return "MME_LBW|MME_EARC CLK";
		case 2: return "MME_TRACE CLK";
		case 3: return "MME_DBG|TS CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI3_TPC_PLL:
		switch (type_idx) {
		case 0: return "TPC_HBW CLK";
		case 1: return "TPC_LBW|TPC_EARC CLK";
		case 2: return "TPC_TRACE CLK";
		case 3: return "TPC_DBG CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI3_VID_PLL:
		switch (type_idx) {
		case 0: return "ROT_HBW CLK";
		case 1: return "VIDOE_HBW|ROT_EARC|VIDEO_LBW|ROT_LBW CLK";
		case 2: return "VIDEO_TRACE|ROT_TRACE CLK";
		case 3: return "VIDEO_DBG|ROT_DBG CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI3_D2D_PLL:
		switch (type_idx) {
		case 0: return "D2D_HBW CLK";
		case 1: return "D2D_LBW CLK";
		case 2: return "D2D_TRACE CLK";
		case 3: return "D2D_DBG|GLINK_CFG CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI3_CS_PLL:
		switch (type_idx) {
		case 0: return "CS_HBW|ARC_FARM|PDMA_HBW CLK";
		case 1: return "CS_LBW|PDMA_LBW CLK";
		case 2: return "CS_TRACE|PDMA_TRACE CLK";
		case 3: return "CS_DBG|PDMA_DBG CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI3_C2C_PLL:
		switch (type_idx) {
		case 0: return "C2C_HBW CLK";
		case 1: return "C2C_LBW CLK";
		case 2: return "C2C_TRACE CLK";
		case 3: return "C2C_DBG CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI3_NCH_PLL:
		switch (type_idx) {
		case 0: return "NC_HBW CLK";
		case 1: return "NC_LBW|TTT_EARC CLK";
		case 2: return "NC_TRACE CLK";
		case 3: return "NC_DBG CLK";
		default: return "INVALID_REQ";
		}
	case HL_GAUDI3_C2M_PLL:
		switch (type_idx) {
		case 0: return "C2M_HBW CLK";
		case 1: return "C2M_LBW|TTT_EARC CLK";
		case 2: return "C2M_TRACE CLK";
		case 3: return "C2M_DBG CLK";
		default: return "INVALID_REQ";
		}
	default: return "INVALID_PLL_INDEX";
	}
}

static int gaudi3_arc_get_cpu_id_eng_group(int fd, uint32_t queue_idx,
					uint32_t *cpu_id, uint32_t *eng_group)
{
	if (queue_idx >= GAUDI3_ENGINE_ID_SIZE)
		return -EINVAL;

	*cpu_id = gaudi3_arc_eng_id_to_cpu_id[queue_idx];
	*eng_group = gaudi3_engine_arc_cpu_id_to_eng_group[*cpu_id];

	return 0;
}

static int gaudi3_arc_set_regions(int fd, uint32_t cpu_id,
					struct hltests_arc_db *arc_db)
{
	uint64_t base = gaudi3_arc_blocks_bases[cpu_id];
	uint32_t cb_size = 0, dram_device_va, dma_qid;
	struct hltests_pkt_info pkt_info;
	void *cb;

	cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	if (!cb)
		return -ENOMEM;

	dram_device_va = lower_32_bits(arc_db->dram_device_va);
	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + mmQMAN_ARC_AUX_VIR_MEM0_LSB_ADDR;
	pkt_info.msg_long.value = dram_device_va >> 28;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + mmQMAN_ARC_AUX_VIR_MEM0_MSB_ADDR;
	pkt_info.msg_long.value = upper_32_bits(arc_db->dram_device_va);
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + mmQMAN_ARC_AUX_VIR_MEM0_OFFSET;
	pkt_info.msg_long.value = arc_db->fw_info[cpu_id].hbm_offset;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + mmQMAN_ARC_AUX_PCIE_LOWER_LSB_ADDR;
	pkt_info.msg_long.value = lower_32_bits(arc_db->host_device_va);
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + mmQMAN_ARC_AUX_PCIE_LOWER_MSB_ADDR;
	pkt_info.msg_long.value = upper_32_bits(arc_db->host_device_va);
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	return hltests_submit_and_wait_cs(fd, cb, cb_size, dma_qid,
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

static uint32_t gaudi3_cause_page_fault_from_arc(int fd, uint64_t long_addr, uint32_t qid, void *cb)
{
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size = 0;
	uint32_t cpu_id = CPU_ID_SCHED_ARC0;
	uint64_t base = gaudi3_arc_blocks_bases[cpu_id];
	int rc;

	memset(&pkt_info, 0, sizeof(pkt_info));

	rc = hlthunk_memory_unmap(fd, long_addr);
	if (rc) {
		printf("Failed to unmap memory at address 0x%lx, rc = %d\n", long_addr, rc);
		fail_ret_val(UINT32_MAX);
	}

	pkt_info.qid = qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + SCHED_NEG_TEST_ARC_PAGE_FAULT_OFFSET;
	pkt_info.msg_long.value = ARC_BUILD_ADDR((uint64_t)ARC_REGION9_PCIE, long_addr);
	return hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);
}

static inline int gaudi3_arc_add_config_engine(int fd, uint32_t cpu_id,
						struct hltests_arc_db *arc_db, void *cb,
						uint32_t cb_size, uint32_t qid)
{
	struct engine_config_t eng_config;

	memset(&eng_config, 0, sizeof(struct engine_config_t));

	eng_config.qm_base = u32_safe(gaudi3_arc_blocks_bases[cpu_id] - mmHD0_TPC0_QM_ARC_AUX_BASE +
					mmHD0_TPC0_QM_BASE - CFG_BAR_BASE);

	return hltests_arc_add_arc_config(fd, arc_db, &eng_config, sizeof(eng_config), cb,
						cb_size, cpu_id, gaudi3_arc_blocks_bases[cpu_id],
						SCHED_FW_CONFIG_ADDR_OFFSET,
						SCHED_FW_CONFIG_SIZE_OFFSET, ARC_REGION9_PCIE, qid);
}

static inline int gaudi3_arc_add_config_scheduler(int fd, uint32_t cpu_id,
						struct hltests_arc_db *arc_db, void *cb,
						uint32_t cb_size, uint32_t qid)
{
	struct scheduler_config_t sched_config;
	int i;

	memset(&sched_config, 0, sizeof(struct scheduler_config_t));

	sched_config.common_cfg.version = ARC_FW_INIT_CONFIG_VER;

	for (i = 0 ; i < ARRAY_SIZE(gaudi3_engine_arc_cpu_id_to_eng_group) ; ++i) {
		sched_config.eng_arc_cfg[i].enabled = arc_db->fw_info[i].enabled;
		sched_config.eng_arc_cfg[i].arc_aux_base =
				u32_safe(gaudi3_arc_blocks_bases[i] - CFG_BAR_BASE);
		sched_config.eng_arc_cfg[i].engine_group_type =
				gaudi3_engine_arc_cpu_id_to_eng_group[i];
	}

	return hltests_arc_add_arc_config(fd, arc_db, &sched_config, sizeof(sched_config), cb,
						cb_size, cpu_id, gaudi3_arc_blocks_bases[cpu_id],
						SCHED_FW_CONFIG_ADDR_OFFSET,
						SCHED_FW_CONFIG_SIZE_OFFSET, ARC_REGION9_PCIE, qid);
}

static int gaudi3_arc_set_config(int fd, uint32_t cpu_id, struct hltests_arc_db *arc_db,
					uint16_t run_arc_done_sob)
{
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size = 0, dma_qid;
	uint64_t base;
	void *cb;
	int rc;

	base = gaudi3_arc_blocks_bases[cpu_id];
	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	if (!cb) {
		printf("Failed to set config for ARC %d\n", cpu_id);
		return -ENOMEM;
	}

	/* clear SOB with msg_long since clear_sob doesn't work here */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.value = 0;
	pkt_info.msg_long.address = hltests_get_sob_base_addr(fd) + (run_arc_done_sob * 0x4);
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);
	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, dma_qid,
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
	if (rc) {
		hltests_destroy_cb(fd, cb);
		return rc;
	}

	cb_size = 0;

	if (cpu_id < NUM_OF_SCHEDULER_ARC)
		rc = gaudi3_arc_add_config_scheduler(fd, cpu_id, arc_db, cb, cb_size, dma_qid);
	else
		rc = gaudi3_arc_add_config_engine(fd, cpu_id, arc_db, cb, cb_size, dma_qid);

	assert_true(rc >= 0);
	cb_size = (uint32_t)rc;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + mmQMAN_ARC_AUX_ARC_NUM;
	pkt_info.msg_long.value = cpu_id;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + SCHED_SOB_LBU_ADDR_OFFSET;
	pkt_info.msg_long.value = ARC_BUILD_ADDR((uint64_t)(ARC_REGION15_LBU),
					hltests_get_sob_base_addr(fd) + (run_arc_done_sob * 0x4));
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + SCHED_SOB_LBU_VALUE_OFFSET;
	pkt_info.msg_long.value = SOB_OBJS_SOB_OBJ_0_INC_M | 0x1;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	return hltests_submit_and_wait_cs(fd, cb, cb_size, dma_qid,
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

static uint16_t gaudi3_get_first_avail_sob(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hlthunk_sync_manager_info info = {0};

	hlthunk_get_sync_manager_info(fd, 0, &info);

	return u16_safe_ret_val(info.first_available_sync_object + hdev->counters.reserved_sobs,
				(uint16_t)-1);
}

static uint16_t gaudi3_get_first_avail_mon(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hlthunk_sync_manager_info info = {0};

	hlthunk_get_sync_manager_info(fd, 0, &info);

	return u16_safe_ret_val(info.first_available_monitor + hdev->counters.reserved_mons,
				(uint16_t)-1);
}

static uint16_t gaudi3_get_first_avail_cq(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hlthunk_sync_manager_info info = {0};

	hlthunk_get_sync_manager_info(fd, 0, &info);

	return u16_safe_ret_val(info.first_available_cq + hdev->counters.reserved_cqs,
				(uint16_t)-1);
}

static uint64_t gaudi3_get_sob_base_addr(int fd)
{
	return mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_SOB_OBJ_0_0;
}

static uint64_t gaudi3_get_lbw_base_addr(int fd)
{
	return LBW_BASE;
}

static uint64_t gaudi3_get_sob_lbw_offset(int fd, uint32_t sob_idx)
{
	return gaudi3_get_sob_base_addr(fd) - gaudi3_get_lbw_base_addr(fd) + (sob_idx * 4);
}

static uint64_t gaudi3_get_any_mappable_hw_block_base_addr(int fd)
{
	return mmHD1_SYNC_MNGR_OBJS_BASE;
}

static uint16_t gaudi3_get_cache_line_size(void)
{
	return NIC_CACHE_LINE_SIZE;
}

static uint32_t gaudi3_get_arcs_num(void)
{
	return NUM_ACTIVE_ARCS;
}

static uint64_t gaudi3_get_arc_va_range_host_start(void)
{
	return RESERVED_VA_RANGE_FOR_ARC_ON_HOST_START;
}

static uint64_t gaudi3_get_arc_va_range_dram_start(void)
{
	return RESERVED_VA_RANGE_FOR_ARC_ON_HBM_START;
}

static uint32_t gaudi3_get_num_scheduler_arcs(void)
{
	return NUM_OF_SCHEDULER_ARC;
}

static int gaudi3_wait_arc_run_done(int fd, struct hltests_arc_db *arc_db,
					uint16_t arc_run_done_sob)
{
	struct hltests_monitor_and_fence mon_and_fence_info;
	struct hltests_pkt_info pkt_info;
	uint32_t dma_qid, cb_size;
	uint16_t mon0;
	void *cb;
	int rc;

	mon0 = hltests_get_first_avail_mon(fd);
	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	if (!cb)
		return -ENOMEM;

	cb_size = 0;
	/* wait for sync from ARC */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = u8_safe(dma_qid);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = arc_run_done_sob;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = arc_db->arc_count;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	mon_and_fence_info.mon_mode = SOB_EQUAL;
	cb_size = hltests_add_monitor_and_fence(fd, cb, cb_size, &mon_and_fence_info);

	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, dma_qid, DESTROY_CB_FALSE,
						HL_WAIT_CS_STATUS_COMPLETED);
	if (rc) {
		hltests_destroy_cb(fd, cb);
		return rc;
	}

	cb_size = 0;

	/* clear SOB with msg_long since clear_sob doesn't work here */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.value = 0;
	pkt_info.msg_long.address = hltests_get_sob_base_addr(fd) + (arc_run_done_sob * 0x4);
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);
	return hltests_submit_and_wait_cs(fd, cb, cb_size, dma_qid,
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

static int gaudi3_arc_set_enabled_cores(int fd, struct hltests_arc_db *arc_db)
{
	uint64_t capabilities_mask = hltests_get_capabilities_mask();
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hlthunk_hw_ip_info hw_ip;
	uint32_t engine_id, i;
	int rc;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	if (rc)
		return rc;

	/* We dont have PDMA ARC in Gaudi3, hence we should skip ARC loading */
	if (capabilities_mask == (capabilities_mask & CAP_ARC_FW_LOAD_PDMA_ONLY))
		return 0;

	for (i = 0 ; i < NUM_ACTIVE_ARCS ; i++) {
		if (i >= CPU_ID_SCHED_ARC1 && i < CPU_ID_SCHED_MAX)
			continue;

		if (i >= CPU_ID_TPC_QMAN_ARC0 && i <= CPU_ID_TPC_QMAN_ARC63) {
			engine_id = i - CPU_ID_TPC_QMAN_ARC0;
			if (!((hw_ip.tpc_enabled_mask_ext & (0x1ULL << engine_id)) &&
					!!(capabilities_mask & CAP_ARC_FW_LOAD_TPC_MASK)))
				continue;
		}

		if (i >= CPU_ID_TPC_QMAN_ARC64 && i <= CPU_ID_TPC_QMAN_ARC67)
			continue;

		if (i >= CPU_ID_MME_QMAN_ARC0 && i <= CPU_ID_MME_QMAN_ARC7) {
			engine_id = i - CPU_ID_MME_QMAN_ARC0;

			if (!hdev->module_params.mme_enable ||
				!(capabilities_mask & CAP_ARC_FW_LOAD_MME_MASK))
				continue;

			if (!(hw_ip.mme_enabled_mask & (0x1ULL << engine_id)))
				continue;
		}

		if (i >= CPU_ID_EDMA_QMAN_ARC0 && i <= CPU_ID_EDMA_QMAN_ARC7) {
			engine_id = i - CPU_ID_EDMA_QMAN_ARC0;
			if (!((hw_ip.edma_enabled_mask & (0x1 << engine_id)) &&
					!!(capabilities_mask & CAP_ARC_FW_LOAD_EDMA_MASK)))
				continue;
		}

		if (i >= CPU_ID_ROT_QMAN_ARC0 && i <= CPU_ID_ROT_QMAN_ARC7) {
			engine_id = i - CPU_ID_ROT_QMAN_ARC0;
			if (!((hdev->module_params.rotator_mask & (0x1 << engine_id)) &&
					!!(capabilities_mask & CAP_ARC_FW_LOAD_ROT_MASK)))
				continue;
		}

		arc_db->fw_info[i].enabled = true;
		arc_db->fw_info[i].arc_id = i;
		arc_db->arc_count++;
	}

	return 0;
}

static int gaudi3_arc_configure_scheduler_streams(int fd, struct hltests_arc_db *arc_db)
{
	struct arc_fw_info *fw_info = &arc_db->fw_info[CPU_ID_SCHED_ARC0];

	fw_info->ccb_size = SCHED_QUEUE_SIZE;

	return 0;
}

static void gaudi3_arc_get_sched_cpuid_range(int *sched_first, int *sched_last)
{
	*sched_first = CPU_ID_SCHED_ARC0;
	*sched_last = CPU_ID_SCHED_ARC15;
}

static void gaudi3_arc_get_engine_cpuid_range(int *engine_first, int *engine_last)
{
	*engine_first = CPU_ID_TPC_QMAN_ARC0;
	*engine_last = CPU_ID_ROT_QMAN_ARC7;
}

struct gaudi3_arc_load_data {
	struct arc_load_data *arc_load_data;
	struct hltests_pkt_info *pkt_info;
	void *cb;
	uint32_t dma_down_qid;
	uint32_t cb_alloc_size;
	uint32_t cb_size;
	bool verbose;
	bool dccm_load;
};

static void gaudi3_get_fw_load_dma_props(struct iterate_arcs_ctx *ctx, uint64_t *src_va,
						uint64_t *dst_va, uint32_t *size, uint32_t cpu_id)
{
	struct gaudi3_arc_load_data *private_load_data;
	struct arc_load_data *arc_load_data;
	uint64_t base;
	unsigned long parsed_size;

	private_load_data = ctx->data;
	arc_load_data = private_load_data->arc_load_data;

	*src_va = (cpu_id < NUM_OF_SCHEDULER_ARC) ?
			arc_load_data->sched_img_data.img_host_va :
			arc_load_data->eng_img_data.img_host_va;

	if (!private_load_data->dccm_load) {
		/* HBM load params */
		*src_va += (cpu_id < NUM_OF_SCHEDULER_ARC) ?
				SCHED_ARC_IMAGE_DCCM_SIZE : ENGINE_ARC_IMAGE_DCCM_SIZE;
		*dst_va = ctx->arc_db->dram_device_va + ctx->arc_db->fw_info[cpu_id].hbm_offset;
		*size = ARC_IMAGE_HBM_SIZE;

		return;
	}

	/* DCCM load params */
	base = gaudi3_arc_blocks_bases[cpu_id];

	/*
	 * Loading the image to the DCCM part is very slow (LBW), so we try to reduce the time by
	 * minimizing the image size to the minimum necessary.
	 * The exact image size value is calculated during build time by parsing the elf.map file
	 * sections and passing as definition.
	 * If this definition doesn't exist, e.g. when building the tests and the ARC binaries
	 * separately, fall back to max possible value.
	 */
	if (cpu_id < NUM_OF_SCHEDULER_ARC) {
		parsed_size = strtoul(HLTESTS_ENG_ARC_IMG_DCCM_SIZE, NULL, 16);
		*dst_va = base + mmHD0_ARC_FARM_ARC0_DCCM0_BASE -
			mmHD0_ARC_FARM_ARC0_AUX_BASE;
		*size = ALIGN_UP((uint32_t)parsed_size, 4);
		if (*size == 0 || *size == UINT_MAX)
			*size = SCHED_ARC_IMAGE_DCCM_SIZE;
	} else {
		parsed_size = strtoul(HLTESTS_ENG_ARC_IMG_DCCM_SIZE, NULL, 16);
		*dst_va = base + mmHD0_TPC0_QM_DCCM_BASE - mmHD0_TPC0_QM_ARC_AUX_BASE;
		*size = ALIGN_UP((uint32_t)parsed_size, 4);
		if (*size == 0 || *size == UINT_MAX)
			*size = ENGINE_ARC_IMAGE_DCCM_SIZE;
	}
}

static void gaudi3_asic_build_arcs_image_dma(struct iterate_arcs_ctx *ctx, uint32_t cpu_id)
{
	struct gaudi3_arc_load_data *private_load_data = ctx->data;
	struct hltests_pkt_info *pkt_info;
	uint32_t image_size;
	uint64_t dst_va, src_va;
	int fd;

	fd = private_load_data->arc_load_data->fd;

	gaudi3_get_fw_load_dma_props(ctx, &src_va, &dst_va, &image_size, cpu_id);

	/* modify DMA packet params */
	pkt_info = private_load_data->pkt_info;
	pkt_info->dma.src_addr = src_va;
	pkt_info->dma.dst_addr = dst_va;
	pkt_info->dma.size = image_size;

	private_load_data->cb_size = hltests_add_dma_pkt(fd, private_load_data->cb,
								private_load_data->cb_size,
								pkt_info);
}

static int gaudi3_asic_dma_fw_to_device(struct gaudi3_arc_load_data *private_load_data)
{
	struct hltests_cs_chunk execute_arr;
	uint32_t timeout_sec;
	uint64_t seq;
	int fd, rc;

	fd = private_load_data->arc_load_data->fd;

	execute_arr.cb_ptr = private_load_data->cb;
	execute_arr.cb_size = private_load_data->cb_size;
	execute_arr.queue_index = private_load_data->dma_down_qid;

	timeout_sec = 500;
	rc = hltests_submit_cs_timeout(fd, NULL, 0, &execute_arr, 1, 0, timeout_sec, &seq);
	if (rc)
		return rc;

	return hltests_wait_for_cs(fd, seq, timeout_sec * 1000000);
}

static int gaudi3_asic_load_fw_to_arcs(struct iterate_arcs_ctx *ctx)
{
	struct gaudi3_arc_load_data private_load_data = {0};
	struct arc_load_data *arc_load_data;
	struct hltests_pkt_info pkt_info;
	void *cb;
	int fd, rc = 0;
	uint32_t cb_size, qid;

	arc_load_data = ctx->data;
	fd = arc_load_data->fd;

	private_load_data.verbose = !!hltests_get_verbose_enabled();
	private_load_data.arc_load_data = arc_load_data;
	private_load_data.cb_alloc_size = SZ_4K;
	private_load_data.pkt_info = &pkt_info;

	cb = hltests_create_cb(fd, private_load_data.cb_alloc_size, EXTERNAL, 0);
	if (!cb)
		return -ENOMEM;

	private_load_data.cb = cb;

	qid = hltests_get_dma_down_qid(fd, STREAM0);
	private_load_data.dma_down_qid = qid;

	/* Set PDMA channel as LBW */
	cb_size = hltests_add_pdma_ch_bw_config_pkt(fd, cb, 0, uint_to_int_safe(qid), true);
	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, qid,
			DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
	if (rc)
		goto free_cb;

	/* template for DMA packet */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_DRAM;

	/* send DMA to ARCs DCCMs */
	private_load_data.cb_size = 0;
	private_load_data.dccm_load = true;
	ctx->data = &private_load_data;
	ctx->fn = gaudi3_asic_build_arcs_image_dma;
	rc = hltests_asic_iterate_arcs(ctx, ARC_TYPE_ALL_MASK);
	if (rc)
		goto free_cb;

	rc = gaudi3_asic_dma_fw_to_device(&private_load_data);
	if (rc)
		goto free_cb;

	/* Set PDMA channel back as HBW */
	memset(cb, 0, private_load_data.cb_alloc_size);
	cb_size = hltests_add_pdma_ch_bw_config_pkt(fd, cb, 0, uint_to_int_safe(qid), false);
	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, qid,
			DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
	if (rc)
		goto free_cb;

	/* send DMA to HBM */
	private_load_data.cb_size = 0;
	private_load_data.dccm_load = false;
	ctx->fn = gaudi3_asic_build_arcs_image_dma;
	rc = hltests_asic_iterate_arcs(ctx, ARC_TYPE_ALL_MASK);
	if (rc)
		goto free_cb;

	rc = gaudi3_asic_dma_fw_to_device(&private_load_data);
	if (rc)
		goto free_cb;

free_cb:
	hltests_destroy_cb(fd, private_load_data.cb);
	return rc;
}

static void gaudi3_set_arc_asic_fw_load_params(struct arc_asic_fw_load_params *load_param)
{
	load_param->sched_arc_image_size = SCHED_ARC_IMAGE_SIZE;
	load_param->eng_arc_image_size = ENGINE_ARC_IMAGE_SIZE;
	load_param->sched_arc_first_idx = CPU_ID_SCHED_ARC0;
	load_param->sched_arc_last_idx = CPU_ID_SCHED_ARC15;
	load_param->eng_arc_first_idx = CPU_ID_TPC_QMAN_ARC0;
	load_param->eng_arc_last_idx = NUM_ACTIVE_ARCS - 1;
	load_param->arc_image_hbm_size = ARC_IMAGE_HBM_SIZE;
}

static int gaudi3_arc_map_lbw_blocks(int fd, uint32_t cpu_id,
					struct hltests_arc_db *arc_db)
{
	uint64_t block_addr, base = gaudi3_arc_blocks_bases[cpu_id];
	struct arc_fw_info *fw_info = &arc_db->fw_info[cpu_id];

	/* Map DCCM block.
	 * For ARC farm scheduler ARCs it maps both DCCM0 and DCCM1.
	 */
	if (cpu_id < NUM_OF_SCHEDULER_ARC)
		block_addr = base + mmHD0_ARC_FARM_ARC0_DCCM0_BASE - mmHD0_ARC_FARM_ARC0_AUX_BASE;
	else
		block_addr = base + mmHD0_TPC0_QM_DCCM_BASE - mmHD0_TPC0_QM_ARC_AUX_BASE;

	fw_info->dccm_host_addr = hltests_map_hw_block(fd, block_addr,
			&fw_info->dccm_size);
	if (!fw_info->dccm_host_addr) {
		printf("Failed to map DCCM block of ARC %d\n", cpu_id);
		return -ENOMEM;
	}

	/* Map ACP block for scheduler ARCs */
	if (cpu_id >= NUM_OF_SCHEDULER_ARC)
		return 0;

	block_addr = base + mmHD0_ARC_FARM_ARC0_ACP_ENG_BASE - mmHD0_ARC_FARM_ARC0_AUX_BASE;

	fw_info->acp_host_addr = hltests_map_hw_block(fd, block_addr,
			&fw_info->acp_size);
	if (!fw_info->acp_host_addr) {
		printf("Failed to map ACP block of ARC %d\n", cpu_id);
		hltests_unmap_hw_block(fd, fw_info->dccm_host_addr,
				fw_info->dccm_size);
		return -ENOMEM;
	}

	return 0;
}

static void gaudi3_arc_unmap_lbw_blocks(int fd, uint32_t cpu_id,
					struct hltests_arc_db *arc_db)
{
	struct arc_fw_info *fw_info = &arc_db->fw_info[cpu_id];

	if (cpu_id < NUM_OF_SCHEDULER_ARC)
		hltests_unmap_hw_block(fd, fw_info->acp_host_addr, fw_info->acp_size);

	hltests_unmap_hw_block(fd, fw_info->dccm_host_addr, fw_info->dccm_size);
}

static uint32_t gaudi3_arc_get_cb_suffix_size(void)
{
	return SZ_4K; /* TODO: 4K is overkill, calculate more precise size */
}

static int gaudi3_arc_set_asic_model(int fd, uint32_t cpu_id,
				struct hltests_arc_db *arc_db)
{
	void *addr;

	addr = hltests_arc_get_asic_model_addr(cpu_id, arc_db);
	return hltests_write_lbw_reg(fd, addr, ARC_ASIC_MODEL_GAUDI3);
}

static int gaudi3_arc_activate(int fd, uint32_t cpu_id,
				struct hltests_arc_db *arc_db)
{
	void *addr;

	/* Write SCAL_INIT_COMPLETED to the canary register */
	addr = hltests_arc_get_canary_addr(cpu_id, arc_db);
	return hltests_write_lbw_reg(fd, addr, SCAL_INIT_COMPLETED);
}

static uint32_t gaudi3_add_cq_config_pkt(void *buffer, uint32_t buf_off,
					struct hltests_cq_config *cq_config)
{
	struct hltests_pkt_info pkt_info = {};
	uint64_t offset, msix_db_reg = mmD0_PCIE_MSIX_BASE;

	pkt_info.qid = cq_config->qid;
	/* CQ in hdcore 0 */
	if (cq_config->cq_id  < NUM_OF_CQS_IN_SM)
		offset = cq_config->cq_id * 4;
	/* CQ in hdcore 1 */
	else
		offset = HDCORE_OFFSET + ((cq_config->cq_id  - NUM_OF_CQS_IN_SM) * 4U);

	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;

	/* Configure CQ Address */
	pkt_info.msg_long.value = lower_32_bits(cq_config->cq_address);
	pkt_info.msg_long.address =
		mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_CQ_BASE_ADDR_L_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = upper_32_bits(cq_config->cq_address);
	pkt_info.msg_long.address =
		mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_CQ_BASE_ADDR_H_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = cq_config->cq_size_log2;
	pkt_info.msg_long.address =
		mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_CQ_SIZE_LOG2_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	/* Configure CQ LBW Address */
	pkt_info.msg_long.value = lower_32_bits(msix_db_reg);
	pkt_info.msg_long.address =
		mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_LBW_ADDR_L_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = upper_32_bits(msix_db_reg);
	pkt_info.msg_long.address =
		mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_LBW_ADDR_H_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = cq_config->interrupt_id;
	pkt_info.msg_long.address =
		mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_LBW_DATA_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	/* Configure CQ mode - “0”: 32 bits, “1”: 64 bits with data increment */
	pkt_info.msg_long.value = !!cq_config->inc_mode ? 0x1 : 0x0;
	pkt_info.msg_long.address =
		mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_CQ_INC_MODE_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	return buf_off;
}

static uint64_t gaudi3_pdma_get_ch_reg_base(int fd, uint32_t qid)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	uint32_t ch_grp, ch_id = PDMA_CH_ID(qid);

	ch_grp = ch_id / hdev->pdma_db.pdma_grp_ch_max;

	return (gaudi3_pdma_grp_blocks_bases[ch_grp] + ch_id * PDMA_CH_OFFSET);
}

static uint32_t gaudi3_add_pdma_ch_bw_config_pkt(int fd, void *buffer,
		uint32_t buf_off, int qid, bool set_lbw)
{
	struct hltests_pkt_info pkt_info = {};
	uint32_t u_qid = int_to_uint_safe_ret_val(qid, buf_off);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = u_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = gaudi3_pdma_get_ch_reg_base(fd, u_qid) +
			PDMA_CH_B_CH_LBW_OFFSET;
	pkt_info.msg_long.value = !!set_lbw;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	return buf_off;
}

static uint32_t gaudi3_add_pqm_write_msg_short_sob_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct pqm_packet_msg_short packet;
	uint32_t buf_off_org = buf_off;
	int rc;

	rc = !hltests_is_pdma_eid(pkt_info->qid) && pkt_info->eb;
	assert_int_equal_ret_val(rc, 0, buf_off_org);

	buf_off = gaudi3_pqm_mb_eb_handler(buffer, buf_off, pkt_info);

	memset(&packet, 0, sizeof(packet));

	/* set control data */
	packet.opcode = PQM_PACKET_MSG_SHORT;
	if (pkt_info->write_to_sob.sob_id < NUM_OF_SOBS_IN_BATCH) {
		packet.base = 1; /* Sync object base */
		packet.msg_addr_offset = pkt_info->write_to_sob.sob_id * 4;
	} else {
		packet.base = 3; /* Sync object base of second batch */
		packet.msg_addr_offset =
			u16_safe_ret_val(
				int_to_uint_safe_ret_val(
					(pkt_info->write_to_sob.sob_id - NUM_OF_SOBS_IN_BATCH) * 4,
					buf_off_org),
				buf_off_org);
	}

	/* set sob value */
	packet.so_upd.mode = pkt_info->write_to_sob.mode;
	packet.so_upd.sync_value =
		bitfield_safe_ret_val(pkt_info->write_to_sob.value, 15, buf_off_org);
	packet.so_upd.long_mode =
		bitfield_safe_ret_val(pkt_info->write_to_sob.long_mode, 1, buf_off_org);
	packet.so_upd.zero_sob_cntr =
		bitfield_safe_ret_val(pkt_info->write_to_sob.zero_sob_counter, 1, buf_off_org);

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet, sizeof(packet));
}

static uint32_t gaudi3_add_qman_write_msg_short_sob_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_short packet;

	memset(&packet, 0, sizeof(packet));

	/* set control data */
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.opcode = PACKET_MSG_SHORT;
	if (pkt_info->write_to_sob.sob_id < NUM_OF_SOBS_IN_BATCH) {
		packet.base_lsb = 1; /* Sync object base[1:0] */
		packet.base_msb = 0; /* Sync object base[2] */
		packet.msg_addr_offset = pkt_info->write_to_sob.sob_id * 4;
	} else {
		packet.base_lsb = 3; /* Sync object base[1:0] */
		packet.base_msb = 0; /* Sync object base[2] */
		packet.msg_addr_offset =
			u16_safe_ret_val(
				int_to_uint_safe_ret_val(
					(pkt_info->write_to_sob.sob_id - NUM_OF_SOBS_IN_BATCH) * 4,
					buf_off),
				buf_off);
	}
	/* set sob value */
	packet.so_upd.mode = pkt_info->write_to_sob.mode;
	packet.so_upd.sync_value =
			bitfield_safe_ret_val(pkt_info->write_to_sob.value, 15, buf_off);
	packet.so_upd.long_mode =
			bitfield_safe_ret_val(pkt_info->write_to_sob.long_mode, 1, buf_off);
	packet.so_upd.zero_sob_cntr =
			bitfield_safe_ret_val(pkt_info->write_to_sob.zero_sob_counter, 1, buf_off);

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
								sizeof(packet));
}

static uint32_t gaudi3_add_write_msg_short_sob_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	if (hltests_is_pdma_eid(pkt_info->qid))
		return gaudi3_add_pqm_write_msg_short_sob_pkt(buffer, buf_off, pkt_info);
	else if (hltests_is_sched_arc_eid(pkt_info->qid))
		return gaudi3_add_qman_write_msg_short_sob_pkt(buffer, buf_off, pkt_info);
	else
		printf("[%s] Error, QID %u isn't listed!\n", __func__, pkt_info->qid);

	return buf_off;
}

static uint32_t gaudi3_add_write_to_sob_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct hltests_pkt_info mod_pkt_info;
	uint32_t pkt_size = buf_off;
	uint8_t i;

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
			pkt_size = gaudi3_add_write_msg_short_sob_pkt(buffer, pkt_size,
						&mod_pkt_info);
		}
		return pkt_size;
	} else {
		return gaudi3_add_write_msg_short_sob_pkt(buffer, buf_off, pkt_info);
	}
}

static uint32_t gaudi3_add_pqm_fence_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct pqm_packet_fence packet;
	int rc;

	rc = !hltests_is_pdma_eid(pkt_info->qid) && pkt_info->eb;
	assert_int_equal_ret_val(rc, 0, buf_off);

	buf_off = gaudi3_pqm_mb_eb_handler(buffer, buf_off, pkt_info);

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PQM_PACKET_FENCE;
	packet.dec_val = bitfield_safe_ret_val(pkt_info->fence.dec_val, 4, buf_off);
	packet.target_val = pkt_info->fence.gate_val;
	packet.id = bitfield_safe_ret_val(pkt_info->fence.fence_id, 2, buf_off);
	packet.pred = bitfield_safe_ret_val(pkt_info->pred, 5, buf_off);

	packet.ctl = htole32(packet.ctl);
	packet.cfg = htole32(packet.cfg);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet, sizeof(packet));
}

static uint32_t gaudi3_add_qman_fence_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_fence packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_FENCE;
	packet.dec_val = bitfield_safe_ret_val(pkt_info->fence.dec_val, 4, buf_off);
	packet.target_val = pkt_info->fence.gate_val;
	packet.id = bitfield_safe_ret_val(pkt_info->fence.fence_id, 2, buf_off);
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.pred = bitfield_safe_ret_val(pkt_info->pred, 5, buf_off);

	packet.ctl = htole32(packet.ctl);
	packet.cfg = htole32(packet.cfg);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
						sizeof(packet));
}

static uint32_t gaudi3_add_fence_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	if (hltests_is_pdma_eid(pkt_info->qid))
		return gaudi3_add_pqm_fence_pkt(buffer, buf_off, pkt_info);
	else if (hltests_is_sched_arc_eid(pkt_info->qid))
		return gaudi3_add_qman_fence_pkt(buffer, buf_off, pkt_info);
	else
		printf("[%s] Error, QID %u isn't listed!\n", __func__, pkt_info->qid);

	return buf_off;
}

static uint32_t gaudi3_add_pqm_arm_monitor_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct pqm_packet_msg_short packet;
	uint32_t buf_off_org = buf_off;
	uint8_t mask_val;
	int rc;

	rc = !hltests_is_pdma_eid(pkt_info->qid) && pkt_info->eb;
	assert_int_equal_ret_val(rc, 0, buf_off_org);

	buf_off = gaudi3_pqm_mb_eb_handler(buffer, buf_off, pkt_info);

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PQM_PACKET_MSG_SHORT;
	packet.msg_addr_offset = pkt_info->arm_monitor.address;
	packet.base = bitfield_safe_ret_val(pkt_info->arm_monitor.base, 3, buf_off_org);
	packet.mon_arm_register.mode = pkt_info->arm_monitor.mon_mode;
	packet.mon_arm_register.sync_value =
			bitfield_safe_ret_val(pkt_info->arm_monitor.sob_val, 15, buf_off_org);
	packet.mon_arm_register.sync_group_id =
			u8_safe_ret_val(pkt_info->arm_monitor.sob_id / 8, buf_off_org);
	mask_val = (uint8_t)~(1U << (pkt_info->arm_monitor.sob_id & 0x7U));
	packet.mon_arm_register.mask = mask_val;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet, sizeof(packet));
}

static uint32_t gaudi3_add_qman_arm_monitor_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_short packet;
	uint8_t mask_val;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_MSG_SHORT;
	packet.msg_addr_offset = pkt_info->arm_monitor.address;
	packet.base_lsb = pkt_info->arm_monitor.base & (BIT(0) | BIT(1)); /* base[1:0] */
	packet.base_msb =
		bitfield_safe_ret_val((pkt_info->arm_monitor.base & BIT(2)) >> 2, /* base[2] */
				       1, buf_off);
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;

	/* TODO - decide on true values of weakly_ordered/no_snoop */
	packet.weakly_ordered = 0;
	packet.no_snoop = 0;

	packet.mon_arm_register.mode = pkt_info->arm_monitor.mon_mode;
	packet.mon_arm_register.sync_value =
				bitfield_safe_ret_val(pkt_info->arm_monitor.sob_val, 15, buf_off);
	packet.mon_arm_register.sync_group_id =
				u8_safe_ret_val(pkt_info->arm_monitor.sob_id / 8U, buf_off);
	mask_val = (uint8_t)~(1U << (pkt_info->arm_monitor.sob_id & 0x7U));
	packet.mon_arm_register.mask = mask_val;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet, sizeof(packet));
}

static uint32_t gaudi3_add_arm_monitor_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	if (hltests_is_pdma_eid(pkt_info->qid))
		return gaudi3_add_pqm_arm_monitor_pkt(buffer, buf_off, pkt_info);
	else if (hltests_is_sched_arc_eid(pkt_info->qid))
		return gaudi3_add_qman_arm_monitor_pkt(buffer, buf_off, pkt_info);
	else
		printf("[%s] Error, QID %u isn't listed!\n", __func__, pkt_info->qid);

	return buf_off;
}

static uint32_t gaudi3_add_pqm_config_monitor_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct pqm_packet_msg_short packet;
	int rc;

	rc = !hltests_is_pdma_eid(pkt_info->qid) && pkt_info->eb;
	assert_int_equal_ret_val(rc, 0, buf_off);

	buf_off = gaudi3_pqm_mb_eb_handler(buffer, buf_off, pkt_info);

	memset(&packet, 0, sizeof(packet));
	/* Set control data */
	packet.opcode = PQM_PACKET_MSG_SHORT;
	packet.msg_addr_offset = pkt_info->config_monitor.address;
	packet.base = bitfield_safe_ret_val(pkt_info->config_monitor.base, 3, buf_off);

	/* Set values */
	packet.mon_config_register.wr_num =
			bitfield_safe_ret_val(pkt_info->config_monitor.wr_num, 4, buf_off);
	packet.mon_config_register.msb_sid =
			bitfield_safe_ret_val(pkt_info->config_monitor.msb_sob_id, 4, buf_off);
	packet.mon_config_register.sm_data_config =
			bitfield_safe_ret_val(pkt_info->config_monitor.sm_data_config, 1, buf_off);
	packet.mon_config_register.long_sob = !!pkt_info->config_monitor.long_mode;
	packet.mon_config_register.cq_en = !!pkt_info->config_monitor.cq_enable;
	packet.mon_config_register.lbw_en = !!pkt_info->config_monitor.lbw_enable;
	packet.mon_config_register.long_high_group = !!pkt_info->config_monitor.long_high_group;
	packet.mon_config_register.auto_zero = !!pkt_info->config_monitor.auto_zero;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet, sizeof(packet));
}

static uint32_t gaudi3_add_qman_config_monitor_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_msg_short packet;

	memset(&packet, 0, sizeof(packet));
	/* Set control data */
	packet.opcode = PACKET_MSG_SHORT;
	packet.msg_addr_offset = pkt_info->config_monitor.address;
	packet.eng_barrier = pkt_info->eb;
	packet.msg_barrier = pkt_info->mb;
	packet.base_lsb = pkt_info->config_monitor.base & (BIT(0) | BIT(1)); /* base[1:0] */
	packet.base_msb =
		bitfield_safe_ret_val((pkt_info->config_monitor.base & BIT(2)) >> 2, /* base[2] */
				      1, buf_off);

	/* TODO - decide on true values of weakly_ordered/no_snoop */
	packet.weakly_ordered = 0;
	packet.no_snoop = 0;

	/* Set values */
	packet.mon_config_register.wr_num =
			bitfield_safe_ret_val(pkt_info->config_monitor.wr_num, 2, buf_off);
	packet.mon_config_register.msb_sid =
			bitfield_safe_ret_val(pkt_info->config_monitor.msb_sob_id, 4, buf_off);
	packet.mon_config_register.sm_data_config =
			bitfield_safe_ret_val(pkt_info->config_monitor.sm_data_config, 1, buf_off);
	packet.mon_config_register.long_sob = !!pkt_info->config_monitor.long_mode;
	packet.mon_config_register.cq_en = !!pkt_info->config_monitor.cq_enable;
	packet.mon_config_register.lbw_en = !!pkt_info->config_monitor.lbw_enable;
	packet.mon_config_register.long_high_group = !!pkt_info->config_monitor.long_high_group;
	packet.mon_config_register.auto_zero = !!pkt_info->config_monitor.auto_zero;

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet, sizeof(packet));
}

static uint32_t gaudi3_add_config_monitor_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	if (hltests_is_pdma_eid(pkt_info->qid))
		return gaudi3_add_pqm_config_monitor_pkt(buffer, buf_off, pkt_info);
	else if (hltests_is_sched_arc_eid(pkt_info->qid))
		return gaudi3_add_qman_config_monitor_pkt(buffer, buf_off, pkt_info);
	else
		printf("[%s] Error, QID %u isn't listed!\n", __func__, pkt_info->qid);

	return buf_off;
}

static uint32_t gaudi3_add_monitor(void *buffer, uint32_t buf_off,
			struct hltests_monitor *mon_info)
{
	uint64_t address, monitor_base;
	uint16_t msg_addr_offset, mon_id = mon_info->mon_id, sob_id = mon_info->sob_id;
	uint16_t cq_id = mon_info->cq_id;
	uint8_t base = 0; /* monitor base address */
	struct hltests_pkt_info pkt_info;
	uint32_t fence_gate_val = mon_info->mon_payload, buf_off_org = buf_off;
	int i;

	/* Only the first 1K monitors can trigger CQ and from hltests perspective we can't use
	 * the second batch, thus base 2 holding the offset to the first 1K monitors in hdcore1.
	 */
	if (mon_id >= NUM_OF_MONITORS_IN_BATCH) {
		mon_id -= NUM_OF_MONITORS_IN_BATCH;
		if (sob_id < NUM_OF_SOBS_IN_BATCH) {
			printf("SOB %u is not in the same sync manager as monitor %u\n",
					sob_id, mon_id);

			/* Since we lack of possibility to return error code, and returning
			 * unsigned value, best posibility is to return 0 and print and error.
			 */
			return 0;
		}
		if (cq_id < NUM_OF_CQS_IN_SM) {
			printf("CQ %u is not in the same sync manager as monitor %u\n",
					sob_id, mon_id);

			/* Since we lack of possibility to return error code, and returning
			 * unsigned value, best posibility is to return 0 and print and error.
			 */
			return 0;
		}
		sob_id -= NUM_OF_SOBS_IN_BATCH;
		cq_id -= NUM_OF_CQS_IN_SM;
		base = 2;
	}

	if (mon_info->cq_enable)
		address = cq_id;
	else
		address = mon_info->mon_address;

	/* monitor_base should be the content of the base0 address registers,
	 * so it will be added to the msg short offsets
	 */
	monitor_base = mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_MON_PAY_ADDRL_0_0;

	/* First monitor config packet: set long mode and CQ properties */
	msg_addr_offset = u16_safe_ret_val((mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_MON_CONFIG_0_0 +
				mon_id * 4) - monitor_base, buf_off_org);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = mon_info->qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.config_monitor.address = msg_addr_offset;
	pkt_info.config_monitor.wr_num = mon_info->num_writes;
	pkt_info.config_monitor.sm_data_config = mon_info->sm_data_config;
	pkt_info.config_monitor.auto_zero = mon_info->auto_zero;
	pkt_info.config_monitor.long_mode = mon_info->long_mode;
	pkt_info.config_monitor.cq_enable = mon_info->cq_enable;
	pkt_info.config_monitor.lbw_enable = mon_info->cq_enable;
	pkt_info.config_monitor.msb_sob_id = u8_safe_ret_val((sob_id / 8) >> 8, buf_off);
	pkt_info.config_monitor.base = base;
	buf_off = gaudi3_add_config_monitor_pkt(buffer, buf_off, &pkt_info);

	/* Second monitor config packet: low address of the sync */
	msg_addr_offset =
		u16_safe_ret_val((mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_MON_PAY_ADDRL_0_0 +
				mon_id * 4) - monitor_base, buf_off_org);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = mon_info->qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_short.base = base;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = lower_32_bits(address);
	buf_off = gaudi3_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	/* Third config packet: high address of the sync */
	msg_addr_offset =
		u16_safe_ret_val((mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_MON_PAY_ADDRH_0_0 +
				mon_id * 4) - monitor_base, buf_off_org);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = mon_info->qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_short.base = base;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = upper_32_bits(address);
	buf_off = gaudi3_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	/* Fourth config packet: the payload, i.e. what to write when the sync
	 * triggers
	 */
	msg_addr_offset =
		u16_safe_ret_val((mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_MON_PAY_DATA_0_0 +
				mon_id * 4) - monitor_base, buf_off_org);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = mon_info->qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_short.base = base;
	pkt_info.msg_short.address = msg_addr_offset;
	pkt_info.msg_short.value = fence_gate_val;
	buf_off = gaudi3_add_msg_short_pkt(buffer, buf_off, &pkt_info);

	if (mon_info->avoid_arm_mon)
		goto out;

	/* Fifth config packets: bind the monitor to a sync object */
	if (mon_info->long_mode) {
		for (i = 3 ; i >= 0 ; i--) {
			msg_addr_offset =
				u16_safe_ret_val((mmHD0_SYNC_MNGR_OBJS_BASE +
						  mmSOB_OBJS_MON_ARM_0_0 +
						  (mon_id + (unsigned int)i) * 4) - monitor_base,
						buf_off_org);
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.qid = mon_info->qid;
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_TRUE;
			pkt_info.arm_monitor.address = msg_addr_offset;
			pkt_info.arm_monitor.mon_mode = mon_info->mon_mode;
			pkt_info.arm_monitor.sob_val =
				(mon_info->sob_val >> (15 * i)) &
							SOB_VAL_LONG_MODE_MASK;
			pkt_info.arm_monitor.sob_id = i ? 0 : sob_id;
			pkt_info.arm_monitor.base = base;
			buf_off = gaudi3_add_arm_monitor_pkt(buffer, buf_off, &pkt_info);
		}
	} else {
		msg_addr_offset =
			u16_safe_ret_val((mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_MON_ARM_0_0 +
					mon_id * 4) - monitor_base, buf_off_org);
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = mon_info->qid;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.arm_monitor.address = msg_addr_offset;
		pkt_info.arm_monitor.mon_mode = mon_info->mon_mode;
		pkt_info.arm_monitor.sob_val = u16_safe_ret_val(mon_info->sob_val, buf_off_org);
		pkt_info.arm_monitor.sob_id = sob_id;
		pkt_info.arm_monitor.base = base;
		buf_off = gaudi3_add_arm_monitor_pkt(buffer, buf_off, &pkt_info);
	}
out:
	return buf_off;
}

static uint32_t gaudi3_add_monitor_and_fence(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			void *buffer, uint32_t buf_off,
			struct hltests_monitor_and_fence *mon_and_fence_info)
{
	uint8_t fence_gate_val = u8_safe_ret_val(mon_and_fence_info->mon_payload, buf_off);
	bool cmdq_fence = mon_and_fence_info->cmdq_fence;
	uint32_t qid = mon_and_fence_info->queue_id;
	struct hltests_monitor mon_info = {0};
	struct hltests_pkt_info pkt_info;
	uint64_t address;

	if (mon_and_fence_info->mon_address)
		address = mon_and_fence_info->mon_address;
	else
		address = gaudi3_get_fence_addr(0, qid, cmdq_fence);

	mon_info.qid = qid;
	mon_info.mon_address = address;
	mon_info.sob_val = mon_and_fence_info->sob_val;
	mon_info.mon_payload = mon_and_fence_info->mon_payload;
	mon_info.sob_id = mon_and_fence_info->sob_id;
	mon_info.mon_id = mon_and_fence_info->mon_id;
	mon_info.num_writes = mon_and_fence_info->num_writes;
	mon_info.long_mode = mon_and_fence_info->long_mode;
	mon_info.mon_mode = mon_and_fence_info->mon_mode;
	buf_off = gaudi3_add_monitor(buffer, buf_off, &mon_info);

	/* Fence packet */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.fence.dec_val = mon_and_fence_info->dec_fence ? fence_gate_val : 0;
	pkt_info.fence.gate_val = fence_gate_val;
	pkt_info.fence.fence_id = 0;
	buf_off = gaudi3_add_fence_pkt(buffer, buf_off, &pkt_info);

	return buf_off;
}

static uint8_t gaudi3_get_edma_cnt(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode)
{
	struct hlthunk_hw_ip_info hw_ip;
	int rc;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal_ret_val(rc, 0, 0);

	return u8_safe_ret_val((unsigned int)__builtin_popcountll(hw_ip.edma_enabled_mask), 0);
}

static uint32_t gaudi3_get_edma_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			int edma_ch,
			enum hltests_stream_id stream)
{
	uint16_t edma_max_cnt = MAX_NUM_OF_DIES * NUM_OF_HDCORES_PER_DIE * NUM_OF_EDMA_PER_HDCORE,
			edma_cnt = gaudi3_get_edma_cnt(fd, DCORE_MODE_FULL_CHIP);
	uint32_t lut_valid_edma_qid[edma_cnt], qid = UINT32_MAX, i;
	struct hlthunk_hw_ip_info hw_ip;
	int rc, j;

	assert_in_range_ret_val(edma_ch, 0, edma_cnt - 1, (uint32_t)-1);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal_ret_val(rc, 0, (uint32_t)-1);

	for (i = 0, j = 0 ; i < edma_max_cnt ; i++) {
		if (!(hw_ip.edma_enabled_mask & BIT_ULL(i)))
			continue;

		lut_valid_edma_qid[j] = GAUDI3_HDCORE1_ENGINE_ID_EDMA_0 + i;
		if (j == edma_ch) {
			qid = lut_valid_edma_qid[edma_ch];
			break;
		}

		j++;
	}

	return qid;
}

static uint8_t gaudi3_get_pdma_ch_cnt(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode)
{
	struct hlthunk_hw_ip_info hw_ip;
	int rc;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal_ret_val(rc, 0, 0);

	return u8_safe_ret_val((unsigned int)__builtin_popcountll(hw_ip.pdma_user_owned_ch_mask),
				0);
}

static uint32_t gaudi3_get_pdma_qid(int fd, uint16_t idx)
{
	uint8_t ch_num = gaudi3_get_pdma_ch_cnt(fd, DCORE_MODE_FULL_CHIP);
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	assert_in_range_ret_val(idx, 0, ch_num - 1, (uint32_t)-1);
	return hdev->pdma_db.ch_qid_lut[idx];
}

static uint32_t gaudi3_get_tpc_qid(int fd,
			enum hltests_dcore_separation_mode dcore_sep_mode,
			uint8_t tpc_id, enum hltests_stream_id stream)
{
	return GAUDI3_HDCORE0_ENGINE_ID_TPC_0 + tpc_id;
}

static uint8_t gaudi3_get_tpc_cnt(int fd, enum hltests_dcore_separation_mode dcore_sep_mode)
{
	return MAX_NUM_OF_DIES * NUM_OF_HDCORES_PER_DIE * NUM_OF_TPC_PER_HDCORE;
}

static uint32_t gaudi3_get_mme_id(int fd, uint32_t qid)
{
	return qid - GAUDI3_HDCORE0_ENGINE_ID_MME_0;
}

static uint32_t gaudi3_get_mme_qid(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			uint8_t mme_id,	enum hltests_stream_id stream)
{
	return GAUDI3_HDCORE0_ENGINE_ID_MME_0 + mme_id;
}

static uint8_t gaudi3_get_mme_cnt(int fd,
				enum hltests_dcore_separation_mode dcore_sep_mode,
				bool master_slave_mode)
{
	return MAX_NUM_OF_DIES * NUM_OF_HDCORES_PER_DIE * NUM_OF_MME_PER_HDCORE;
}

uint64_t gaudi3_get_dram_va_hint_mask(void)
{
	return DRAM_VA_HINT_MASK;
}

uint64_t gaudi3_get_dram_va_reserved_addr_start(void)
{
	return RESERVED_VA_RANGE_FOR_ARC_ON_HBM_START;
}

static uint32_t gaudi3_nic_get_wq_offset(int fd, int port, uint32_t conn_id)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;
	uint32_t scale_out_coll_offset, coll_offset;

	scale_out_coll_offset = gaudi3->base_scale_out_coll_qp_idx[port] +
					gaudi3->coll_qps_offset[port];
	coll_offset = gaudi3->base_coll_qp_idx[port] + gaudi3->coll_qps_offset[port];

	if (conn_id >= scale_out_coll_offset)
		return scale_out_coll_offset;
	else if (conn_id >= coll_offset)
		return coll_offset;
	else
		return gaudi3->qp_idx_offset[port];
}

static int8_t get_hw_completion_type(enum hltests_nic_cmpl sw_cmpl_type)
{
	switch (sw_cmpl_type) {
	case NONE:
		return 0;
	case SOB:
		return 1;
	case CQ_USR:
		return 2;
	default:
		printf("Invalid completion type %d\n", sw_cmpl_type);
		assert_true(false);
	}

	return -EINVAL;
}

static int gaudi3_nic_fill_wqe(int fd, void *p_in)
{
	struct hltests_nic_wqe_params *in_params = (struct hltests_nic_wqe_params *) p_in;
	struct sq_wqe *swq = (struct sq_wqe *) in_params->sq_wqe;
	struct rq_wqe *rwq = (struct rq_wqe *) in_params->rq_wqe;
	uint32_t remote_sob_id, local_sob_id, remote_sm_id, local_sm_id;
	struct hlthunk_hw_ip_info hw_ip;
	enum hltests_nic_test_opcode test_op = in_params->test_opcode;
	struct sq_rdv_read_wqe *rdv_swq = (struct sq_rdv_read_wqe *) swq;
	uint8_t hw_cmpl_type;
	int rc = 0;

	assert_true((in_params->local_sob_id >= 0) && (in_params->remote_sob_id >= 0));

	/* normalize SOBJs */
	local_sob_id = (uint32_t)((in_params->local_sob_id + LOCAL_SOB_ID) % NUM_OF_SOBJS_PER_SM);
	local_sm_id = (uint32_t)((in_params->local_sob_id + LOCAL_SOB_ID) / NUM_OF_SOBJS_PER_SM);

	remote_sob_id = (uint32_t)((in_params->remote_sob_id + REMOTE_SOB_ID) %
			 NUM_OF_SOBJS_PER_SM);
	remote_sm_id = (uint32_t)((in_params->remote_sob_id + REMOTE_SOB_ID) / NUM_OF_SOBJS_PER_SM);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	hw_cmpl_type = u8_safe(int_to_uint_safe(get_hw_completion_type(in_params->cmpl)));

	memset(swq, 0, sizeof(*swq));
	memset(rwq, 0, sizeof(*rwq));

	/* Send WQ global cfg */
	swq->opcode = WQE_LINEAR;
	swq->local_class = 0;		/* Lowest class/priority */
	swq->local_mcid = 0;		/* TODO: what class ID to put here ? */
	swq->reduction_opcode = bitfield_safe(in_params->reduction_cfg, 12);
	swq->rc = 0;			/* No atomic fetch and clear */
	swq->se_or_compress = in_params->compression_en;
	swq->in_line = 0;
	swq->ackreq = !!in_params->ackreq;
	swq->size = u32_safe(in_params->size);
	swq->local_address_31_0 = lower_32_bits(in_params->local_address);
	swq->local_address_63_32 = upper_32_bits(in_params->local_address);
	swq->remote_address_31_0 = lower_32_bits(in_params->remote_address);
	swq->remote_address_63_32 = upper_32_bits(in_params->remote_address);
	swq->tag = (in_params->cmpl & CQ_USR) ? int_to_uint_safe(in_params->tag) :
						((uint32_t) SOB_ADD << 31) | 1;
	swq->remote_sob_id = bitfield_safe(remote_sob_id, 13);
	swq->remote_sm_id = bitfield_safe(remote_sm_id, 3);
	swq->long_sync_object = 0;
	swq->sob_command = (in_params->cmpl & CQ_USR) ? 0 : SOB_INC;
	swq->completion_type = bitfield_safe(hw_cmpl_type, 2);

	/* Receive WQ global cfg */
	rwq->opcode = WQE_LINEAR;
	rwq->wqe_index = u8_safe(int_to_uint_safe(in_params->wqe_index));
	rwq->local_sob_id = bitfield_safe(local_sob_id, 13);
	rwq->local_sm_id = bitfield_safe(local_sm_id, 3);
	rwq->sob_command = (in_params->cmpl & CQ_USR) ? 0 : SOB_INC;
	rwq->sob_fifo = 0;

	/* In Gaudi3 a cache block is introduced. For the NIC it is configured
	 * such that the user can request allocation of lines on the local and
	 * remote side. Hence, we should always enable both allocation to force
	 * continuous testing of the cache.
	 */
	if (in_params->cache_en) {
		swq->local_alloch = 1;
		swq->remote_alloch = 1;
	}

	if (in_params->downscale_en)
		rwq->size = u32_safe(in_params->size / 2);
	else
		rwq->size = u32_safe(in_params->size);

	rwq->long_sync_object = 0;
	rwq->completion_type = bitfield_safe(hw_cmpl_type, 2);
	/* Per opcode configuration overrides for SWQ & RWQ */
	switch (test_op) {
	case TEST_OPCODE_RENDEZVOUS_WRITE:
		if (in_params->is_wr_rdv_send) {
			swq->remote_address_31_0 = 0;
			swq->remote_address_63_32 = 0;
			swq->tag = 0;
			swq->remote_sob_id = 0;
			swq->remote_sm_id = 0;
			swq->remote_mcid = 0;
			swq->remote_class = 0;
			swq->long_sync_object = 0;
			swq->sob_command = 0;
			swq->completion_type = 0;
		} else {
			/* we are overloading the existing send wqe structure with this inline WQE
			 * instead of creating a separate structure.
			 * Local Address of Send WQE = Remote Address field of Inline WQE
			 * Remote Address of Send WQE = Inline Data field of Inline WQE
			 * In Gaudi2, the remote pi would be automatically incremented by the hw.
			 * But in Gaudi3, the remote pi needs to be sent as part of the WQE itself.
			 * So we overload the local_address with the remote pi (wqe_index)
			 */
			swq->opcode = WQE_RENDEZVOUS_WRITE;
			swq->in_line = 1;
			swq->size = NIC_SEND_WQE_SIZE >> 1;
			/* reuse Local address [31:0] to update Remote_PI[21:0] in case of RDV */
			swq->local_address_31_0 = in_params->rdv_remote_pi & 0x3FFFFF;
			swq->local_address_63_32 = 0;
			swq->reduction_opcode = 0;

			rwq->opcode = WQE_RENDEZVOUS_WRITE;
			rwq->size = NIC_SEND_WQE_SIZE >> 1;
			/* From the receive side perspective, the remote_sob is the local sob */
			rwq->local_sob_id = bitfield_safe(remote_sob_id, 13);
			rwq->local_sm_id = bitfield_safe(remote_sm_id, 3);
		}
		break;

	case TEST_OPCODE_RENDEZVOUS_READ:
		rdv_swq->opcode = WQE_RENDEZVOUS_READ;
		/* For the Read RDV, since both local and remote address fields are being used,
		 * we cannot use the local address field for sending the remote pi. Hence the
		 * following fields are being used for it. Please refer Nic Arch spec 5.4.8.6
		 */
		rdv_swq->remote_pi_0_10 = (in_params->rdv_remote_pi) & 0x7FF;
		rdv_swq->remote_pi_11_21 = (in_params->rdv_remote_pi >> 11) & 0x7FF;
		rdv_swq->reduction_opcode = 0;

		rwq->opcode = WQE_RENDEZVOUS_READ;
		rwq->local_sob_id = bitfield_safe(remote_sob_id, 13);
		rwq->local_sm_id = bitfield_safe(remote_sm_id, 3);
		rwq->size = NIC_SEND_WQE_SIZE;

		break;

	case TEST_OPCODE_ATOMIC_FETCH_ADD:
		if (!in_params->wqe_index) {
			swq->in_line = 0;
			swq->ackreq = 1;
			swq->size = 0;
			swq->remote_alloch = 1;
			swq->opcode = WQE_ATOMIC_FETCH_ADD;
			swq->tag = AFA_SWQ_TAG;
			swq->remote_address_31_0 = lower_32_bits(in_params->fna_op_addr);
			swq->remote_address_63_32 = upper_32_bits(in_params->fna_op_addr);
			rwq->opcode = WQE_ATOMIC_FETCH_ADD;
			if (in_params->fna_cmpl == AFA_REG_CMPL) {
				if (in_params->qp & 1)
					rwq->sob_fifo = AFA_CMPL_REG_1;
				else
					rwq->sob_fifo = AFA_CMPL_REG_2;
			} else if (in_params->fna_cmpl == AFA_CQ_USR_CMPL) {
				/* For the FnA WQE with user_cq completion, we change the
				 * completion type to user_cq in the WQE even though the completion
				 * for other WQEs would be SOB. This is because, we get the F&A
				 * value via the CQ object.
				 */
				swq->completion_type =
						bitfield_safe(get_hw_completion_type(CQ_USR), 2);
				swq->sob_command = 0;
				rwq->completion_type =
						bitfield_safe(get_hw_completion_type(CQ_USR), 2);
				rwq->sob_command = 0;
			}

			rwq->tag = 0xCAFE;
		}

		break;

	default:
		break;
	}

	return rc;
}

static void *gaudi3_nic_get_swqe(void *swq, uint32_t offset)
{
	return ((struct sq_wqe *) swq) + offset;
}

static void *gaudi3_nic_get_rwqe(void *rwq, uint32_t offset)
{
	return ((struct rq_wqe *) rwq) + offset;
}

static uint8_t gaudi3_nic_get_swqe_size(void)
{
	return sizeof(struct sq_wqe);
}

static uint8_t gaudi3_nic_get_rwqe_size(void)
{
	return sizeof(struct rq_wqe);
}

static uint32_t gaudi3_nic_get_max_pi(struct hltests_nic_qp *qp_p)
{
	return WQ_HW_INDICES_SIZE;
}

static uint64_t gaudi3_nic_get_db_fifo_umr(int fd, uint32_t port, uint32_t db_fifo_id)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;
	uint64_t die_offset, macro_offset, umr_offset;
	uint32_t macro;

	/* In 400Gbps mode there is one port per macro. In 200Gbps mode there are two. */
	if (gaudi3->speed[port] == SPEED_200000)
		macro = port >> 1;
	else
		macro = port;

	die_offset = (macro >= NIC_NUM_MACROS_PER_DIE) ?
			(mmD1_NIC0_UMR_0_BASE - mmD0_NIC0_UMR_0_BASE) : 0;
	macro_offset = (macro % NIC_NUM_MACROS_PER_DIE) *
			(mmD0_NIC1_UMR_0_BASE - mmD0_NIC0_UMR_0_BASE);
	umr_offset = db_fifo_id * (mmD0_NIC0_UMR_1_BASE - mmD0_NIC0_UMR_0_BASE);

	return die_offset + macro_offset + umr_offset + mmD0_NIC0_UMR_0_BASE;
}

static uint64_t gaudi3_nic_get_db_fifo_dup(int fd, uint32_t port, uint32_t db_fifo_id)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;
	uint64_t die_offset, macro_offset, dup_offset;
	uint32_t macro;

	/* In 400Gbps mode there is one port per macro. In 200Gbps mode there are two. */
	if (gaudi3->speed[port] == SPEED_200000)
		macro = port >> 1;
	else
		macro = port;

	die_offset = (macro >= NIC_NUM_MACROS_PER_DIE) ?
			(mmD1_NIC0_QPC_BASE - mmD0_NIC0_QPC_BASE) : 0;
	macro_offset = (macro % NIC_NUM_MACROS_PER_DIE) *
			(mmD0_NIC1_QPC_BASE - mmD0_NIC0_QPC_BASE);
	dup_offset = mmD0_NIC0_QPC_BASE + mmNIC_QPC_DUP_DB_FIFO_0;

	return die_offset + macro_offset + dup_offset + (db_fifo_id * 4);
}

static int gaudi3_nic_get_default_cfg(void *cfg, enum hltests_nic_id id)
{
	struct hltests_nic_lpbk_cfg *lpbk_cfg;
	struct hltests_nic_gen_test_cfg *gen_test_cfg;
	uint32_t port;

	switch (id) {
	case HLTESTS_NIC_E2E_LPBK:
		lpbk_cfg = cfg;

		for (port = 0 ; port < MAX_NIC_NUMBER_OF_PORTS ; port++) {
			lpbk_cfg->ports[port] = port;
			lpbk_cfg->qps_per_port[port] = 1;
		}

		lpbk_cfg->ports_num = MAX_NIC_NUMBER_OF_PORTS;
		lpbk_cfg->qps_per_port_num_elements = MAX_NIC_NUMBER_OF_PORTS;
		lpbk_cfg->iterations_mem = 1;
		lpbk_cfg->iterations_db = 1;
		lpbk_cfg->cq_buf_len_shift = 12;
		lpbk_cfg->user_cq_buf_len_shift = 12;
		lpbk_cfg->user_cq_idx = 0;
		lpbk_cfg->data_loc = DATA_LOC_HOST;
		lpbk_cfg->wq_loc = WQ_LOC_HOST;
		lpbk_cfg->cmpl = CQ_USR;
		lpbk_cfg->data_size_shift = 16;
		lpbk_cfg->wqe_size_shift = 12;
		lpbk_cfg->data_cmp = true;
		lpbk_cfg->single_alloc = false;
		lpbk_cfg->cleanup = true;
		lpbk_cfg->wait_for_cleanup = false;
		lpbk_cfg->verbose = true;
		lpbk_cfg->db_qman = true;
		lpbk_cfg->wtd_en = false;
		lpbk_cfg->eq_poll = false;
		lpbk_cfg->user_db = true;
		/* driver decides MTU value */
		lpbk_cfg->mtu = 0;
		lpbk_cfg->qp_loopback = QP_LPBK_DISABLED;
		lpbk_cfg->cc_cq = CC_MODE_DISABLED;
		lpbk_cfg->rdv_type = HLTESTS_NIC_RDV_SND_RCV;
		lpbk_cfg->force_wq_with_pmmu = false;

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

static uint64_t gaudi3_get_user_cq_umr(int fd, uint32_t port, uint32_t cq_id)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;
	uint64_t die_offset, macro_offset, umr_offset;
	uint32_t macro;

	/* In 400Gbps mode there is one port per macro. In 200Gbps mode there are two. */
	macro =  (gaudi3->speed[port] == SPEED_200000) ? (port >> 1) : port;

	die_offset = (macro >= NIC_NUM_MACROS_PER_DIE) ?
			(mmD1_NIC0_CQ_UMR_0_BASE - mmD0_NIC0_CQ_UMR_0_BASE) : 0;
	macro_offset = (macro % NIC_NUM_MACROS_PER_DIE) *
			(mmD0_NIC1_CQ_UMR_0_BASE - mmD0_NIC0_CQ_UMR_0_BASE);
	umr_offset = cq_id * (mmD0_NIC0_CQ_UMR_1_BASE - mmD0_NIC0_CQ_UMR_0_BASE);

	return die_offset + macro_offset + umr_offset + mmD0_NIC0_CQ_UMR_0_BASE;
}

static uint32_t gaudi3_nic_get_user_cqe(int fd, struct hl_nic_cqe *cqe_sw,
					struct hltests_nic_port_cq *port_cq, uint32_t hw_ci)
{
	struct nic_cqe_raw *cq_hw_arr = port_cq->cq_buf, *cqe_hw;
	struct hltests_nic_cq *cq = port_cq->thread_params.cq;
	struct hltests_state *tests_state = cq->tests_state;
	uint64_t reg_addr;
	uint32_t user_cq_buf_len = (uint32_t)port_cq->cq_buf_len,
		 port = int_to_uint_safe_ret_val(port_cq->thread_params.port, hw_ci),
		 *ptr, id = port_cq->id;

	/* Read CQE from port CQ buffer at index CI. */
	cqe_hw = &cq_hw_arr[hw_ci & (user_cq_buf_len - 1)];

	if (!(CQE_IS_VALID(cqe_hw))) {
		printf("Invalid CQE, port %d, hw_ci: 0x%x\n", port, hw_ci);
		return hw_ci;
	}

	/* Memory barrier. Make sure we read CQE contents after valid bit check */
	__sync_synchronize();

	/* Found a valid CQE. Populate corresponding SW CQE. */
	memset(cqe_sw, 0, sizeof(*cqe_sw));
	cqe_sw->port = port;
	cqe_sw->qp_number = CQE_QPN(cqe_hw);

	if (CQE_IS_REQ(cqe_hw)) {
		cqe_sw->type = HL_NIC_CQE_TYPE_REQ;
		cqe_sw->requester.wqe_index = CQE_WQE_IDX(cqe_hw);
		/* Since the cqe_sw structure does not have provision to read the CQE F&A data,
		 * we are overloading the wqe_index variable with that. Since the F&A WQE is
		 * always WQE '0', there is no harm in overloading that
		 */
		if (cq->fna)
			cqe_sw->requester.wqe_index = CQE_RAW_PKT_SIZE(cqe_hw);
	} else {
		cqe_sw->type = HL_NIC_CQE_TYPE_RES;
		cqe_sw->responder.msg_id = CQE_TAG(cqe_hw);
	}

	CQE_SET_INVALID(cqe_hw);

	/* Increment CI. H/W CI wraps every 32 bits */
	hw_ci++;

	/* Config user CQ HW with updated CI. */
	if (hltests_is_simulator(fd)) {
		reg_addr = gaudi3_get_user_cq_umr(fd, port, id) + port_cq->regs_offset;
		WRITE32(reg_addr, hw_ci);
	} else {
		ptr = (uint32_t *) ((char *) port_cq->regs_ptr + port_cq->regs_offset);
		*ptr = hw_ci;
	}

	return hw_ci;
}

static int gaudi3_nic_user_cq_create(int fd, struct hltests_nic_cq *cq)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;
	int rc;

	assert_int_equal(cq->type, HLTESTS_NIC_CQ_TYPE_PORT);

	cq->user_cq.raw_cqe_size = sizeof(struct nic_cqe_raw);
	cq->user_cq.user_cq_port_poll = hltests_nic_user_cq_port_poll;

	rc = hltests_nic_user_cq_create(fd, cq);
	assert_int_equal(rc, 0);

	gaudi3->cq = cq;

	return 0;
}

static int gaudi3_nic_user_cq_destroy(int fd, struct hltests_nic_cq *cq)
{
	return hltests_nic_user_cq_destroy(fd, cq);
}

static void gaudi3_nic_pre_setup_ctx(int fd, struct hltests_nic_requester_conn_ctx *req)
{
	req->wq_type = hltests_nic_is_ibdev(fd) ? HBLDV_WQ_WRITE : WQ_WRITE;
}

static void gaudi3_nic_setup_ctx_defaults(int fd, int port,
						struct hltests_nic_requester_conn_ctx *req,
						struct hltests_nic_responder_conn_ctx *res)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;
	struct hltests_nic_cq *cq = gaudi3->cq;
	uint8_t cq_number = u8_safe_ret(cq ? cq->user_cq.port_cq[port].id : 0);

	req->cq_number = cq_number;

	res->cq_number = cq_number;
}

static int gaudi3_nic_setup_ctx_lpbk(int fd, int port,
				     struct hltests_nic_requester_conn_ctx *req_ctx,
				     struct hltests_nic_responder_conn_ctx *res_ctx,
				     uint32_t conn, struct hltests_nic_lpbk_cfg *cfg)
{
	uint8_t qp_loopback;
	uint32_t port_idx;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++)
		if (cfg->ports[port_idx] == port)
			break;

	if (cfg->qp_loopback == QP_LPBK_DISABLED)
		qp_loopback = 0;
	else
		qp_loopback = (cfg->qp_loopback == QP_LPBK_ENABLED) ? 1 :
				(conn > (cfg->qps_per_port[port_idx] / 2 - 1)) ? 0 : 1;

	gaudi3_nic_setup_ctx_defaults(fd, port, req_ctx, res_ctx);
	req_ctx->loopback = qp_loopback;
	res_ctx->loopback = qp_loopback;

	return 0;
}

static int gaudi3_nic_setup_ctx_e2e(int fd, int port,
				    struct hltests_nic_requester_conn_ctx *req_ctx,
				    struct hltests_nic_responder_conn_ctx *res_ctx,
				    struct hltests_nic_e2e_cfg *cfg)
{
	gaudi3_nic_setup_ctx_defaults(fd, port, req_ctx, res_ctx);

	return 0;
}

/* For WRITE_RDV transfer,
 * 1. The send side QP/WQ type should be RENDEZVOUS_WRITE
 * 2. The receive side QP/WQ type should be WRITE.
 * 3. The receive side should be programmed with the max QP size of the send side in the
 *    wq_remote_log_size field.
 * For READ_RDV transfer,
 * 1. The send side QP/WQ type should be RENDEZVOUS_READ
 * 2. The receive side QP/WQ type should be WRITE.
 */
static void gaudi3_nic_pre_setup_default_ctx_rdv(int fd,
						 struct hltests_nic_requester_conn_ctx *req_ctx,
						 enum hltests_nic_test_opcode test_opcode,
						 bool is_rdv_send, bool swq_granularity)
{
	/* 0 equates to 32B, 1 equates to 64B */
	req_ctx->swq_granularity = swq_granularity ? HBLDV_SWQE_GRAN_64B : HBLDV_SWQE_GRAN_32B;

	if (is_rdv_send) {
		/* In case of Send side, wq/qp type is RDV */
		if (test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
			req_ctx->wq_type = hltests_nic_is_ibdev(fd) ?
						HBLDV_WQ_SEND_RDV : WQ_RENDEZVOUS_WRITE;
		else
			req_ctx->wq_type = hltests_nic_is_ibdev(fd) ?
						HBLDV_WQ_READ_RDV_ENDP : WQ_RENDEZVOUS_READ;
	} else {
		/* In case of receive side, wq/qp type is normal write */
		req_ctx->wq_type = hltests_nic_is_ibdev(fd) ? HBLDV_WQ_RECV_RDV : WQ_WRITE;
	}
}

/* For WRITE_RDV transfer,
 * 1. The send side QP/WQ type should be RENDEZVOUS_WRITE
 * 2. The receive side QP/WQ type should be WRITE.
 * 3. The receive side should be programmed with the max QP size of the send side in the
 *    wq_remote_log_size field.
 * For READ_RDV transfer,
 * 1. The send side QP/WQ type should be RENDEZVOUS_READ
 * 2. The receive side QP/WQ type should be WRITE.
 */
static void gaudi3_nic_setup_default_ctx_rdv(int fd, int port,
					     struct hltests_nic_requester_conn_ctx *req_ctx,
					     struct hltests_nic_responder_conn_ctx *res_ctx,
					     bool is_rdv_send, uint32_t conn_id,
					     bool swq_granularity)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;
	struct hltests_nic_cq *cq = gaudi3->cq;
	uint8_t cq_number = u8_safe_ret(cq ? cq->user_cq.port_cq[port].id : 0);

	req_ctx->cq_number = cq_number;

	res_ctx->conn_peer = conn_id;
	res_ctx->wq_peer_granularity = swq_granularity;
	res_ctx->cq_number = cq_number;
	res_ctx->rdv = is_rdv_send;
}

static enum gaudi3_red_op gaudi3_map_red_op(enum hltests_nic_reduction_operation red_op)
{
	switch (red_op) {
	case HLTESTS_NIC_REDUCTION_OP_ADDITION:
		return GAUDI3_NIC_REDUCTION_OP_ADDITION;

	case HLTESTS_NIC_REDUCTION_OP_SUBTRACTION:
		return GAUDI3_NIC_REDUCTION_OP_SUBTRACTION;

	case HLTESTS_NIC_REDUCTION_OP_MINIMUM:
		return GAUDI3_NIC_REDUCTION_OP_MINIMUM;

	case HLTESTS_NIC_REDUCTION_OP_MAXIMUM:
		return GAUDI3_NIC_REDUCTION_OP_MAXIMUM;

	default:
		return GAUDI3_NIC_REDUCTION_OP_INVALID;
	}
}

static enum gaudi3_red_datatype gaudi3_map_red_dt(enum hltests_nic_reduction_datatype red_dt)
{
	switch (red_dt) {
	case HLTESTS_NIC_REDUCTION_INT8:
		return GAUDI3_NIC_REDUCTION_INT8;

	case HLTESTS_NIC_REDUCTION_BF16:
		return GAUDI3_NIC_REDUCTION_BF16;

	case HLTESTS_NIC_REDUCTION_FP32:
		return GAUDI3_NIC_REDUCTION_FP32;

	case HLTESTS_NIC_REDUCTION_UPSCALING_BF16:
	case HLTESTS_NIC_REDUCTION_BF16_DOWN_AND_UP:
		return GAUDI3_NIC_REDUCTION_UPSCALING_BF16;

	case HLTESTS_NIC_REDUCTION_DOWNSCALING_TO_BF16:
		return GAUDI3_NIC_REDUCTION_BF16;

	default:
		return GAUDI3_NIC_REDUCTION_DT_INVALID;
	}
}

static enum gaudi3_downscale_dt gaudi3_map_red_ds_dt(enum hltests_nic_reduction_datatype red_dt)
{
	switch (red_dt) {
	case HLTESTS_NIC_REDUCTION_DOWNSCALING_TO_BF16:
	case HLTESTS_NIC_REDUCTION_BF16_DOWN_AND_UP:
		return GAUDI3_NIC_REDUCTION_DS_TO_BF16;

	case HLTESTS_NIC_REDUCTION_INT8:
	case HLTESTS_NIC_REDUCTION_BF16:
	case HLTESTS_NIC_REDUCTION_FP32:
	case HLTESTS_NIC_REDUCTION_UPSCALING_BF16:
		return GAUDI3_NIC_REDUCTION_DS_NONE;

	default:
		return GAUDI3_NIC_REDUCTION_DS_INVALID;
	}
}

static bool gaudi3_nic_reduction_is_down_and_up(const struct hltests_nic_wqe_params *wqe_params)
{
	enum gaudi3_downscale_dt red_ds_dt =
		(wqe_params->reduction_cfg >> REDUCTION_DOWN_CONV_SHIFT) & REDUCTION_DOWN_CONV_MSK;

	enum gaudi3_red_datatype red_dt = (wqe_params->reduction_cfg >> REDUCTION_DATA_TYPE_SHIFT) &
					REDUCTION_DATA_TYPE_MSK;

	return (((red_ds_dt == GAUDI3_NIC_REDUCTION_DS_TO_FP16) ||
			(red_ds_dt == GAUDI3_NIC_REDUCTION_DS_TO_BF16)) &&
		((red_dt == GAUDI3_NIC_REDUCTION_UPSCALING_FP16) ||
			(red_dt == GAUDI3_NIC_REDUCTION_UPSCALING_BF16)));
}

static uint64_t gaudi3_get_tc_base_addr(uint32_t core_id)
{
	uint64_t gaudi3_vdec_cmd_blocks_bases[] = {
		mmHD0_VDEC0_CMD_BASE, mmHD0_VDEC1_CMD_BASE,
		mmHD1_VDEC0_CMD_BASE, mmHD1_VDEC1_CMD_BASE,
		mmHD2_VDEC0_CMD_BASE, mmHD2_VDEC1_CMD_BASE,
		mmHD3_VDEC0_CMD_BASE, mmHD3_VDEC1_CMD_BASE,
		mmHD4_VDEC0_CMD_BASE, mmHD4_VDEC1_CMD_BASE,
		mmHD5_VDEC0_CMD_BASE, mmHD5_VDEC1_CMD_BASE,
		mmHD6_VDEC0_CMD_BASE, mmHD6_VDEC1_CMD_BASE,
		mmHD7_VDEC0_CMD_BASE, mmHD7_VDEC1_CMD_BASE
	};

	if (core_id >= ARRAY_SIZE(gaudi3_vdec_cmd_blocks_bases))
		return 0x0;

	return gaudi3_vdec_cmd_blocks_bases[core_id];
}

static int gaudi3_nic_config_reduction(int fd, enum hltests_nic_reduction_operation red_op,
					enum hltests_nic_reduction_datatype red_data_type,
					uint64_t *reduction)
{
	enum gaudi3_red_op gaudi3_red_op;
	enum gaudi3_red_datatype gaudi3_red_dt = 0;
	enum gaudi3_downscale_dt gaudi3_ds_dt = 0;

	gaudi3_red_op = gaudi3_map_red_op(red_op);

	gaudi3_ds_dt = gaudi3_map_red_ds_dt(red_data_type);

	gaudi3_red_dt = gaudi3_map_red_dt(red_data_type);

	if ((gaudi3_red_op == GAUDI3_NIC_REDUCTION_OP_INVALID) ||
		(gaudi3_red_dt == GAUDI3_NIC_REDUCTION_DT_INVALID) ||
			(gaudi3_ds_dt == GAUDI3_NIC_REDUCTION_DS_INVALID))
		return -ENOTSUP;

	*reduction = (REDUCTION_ENABLE_MSK |
			(gaudi3_red_dt & REDUCTION_DATA_TYPE_MSK) << REDUCTION_DATA_TYPE_SHIFT |
			(gaudi3_red_op & REDUCTION_OPERATION_MSK) << REDUCTION_OPERATION_SHIFT |
			(gaudi3_ds_dt & REDUCTION_DOWN_CONV_MSK) << REDUCTION_DOWN_CONV_SHIFT);

	return 0;
}

static uint32_t gaudi3_get_cq_patch_size(uint32_t qid)
{
	/* Calculation below is based on hltests_cq_patch_cb() functionality,
	 * which patches an outgoing CB to enable SM CQ for the entire CS.
	 * Patching means eventually the addition of x7 msg_short pkts.
	 * Note that PQM-type patching means additional MB pkt/s (nop pkts where
	 * MB is true), and EB pkt/s (fence + lpdma pkts where EB is true):
	 * 2 x write_to_sob_pkt + monitor_pkt (+ 2 * msg_barrier_pkt + eb_pkt)
	 * == 7 x msg_short_pkt (+ 2 * nop_pkt + fence_pkt + lin_pdma_pkt).
	 */
	if (hltests_is_pdma_eid(qid))
		return (7 * sizeof(struct pqm_packet_msg_short) +
				2 * sizeof(struct pqm_packet_nop) +
				sizeof(struct pqm_packet_fence) +
				sizeof(struct pqm_packet_lin_pdma) +
				3 * sizeof(uint64_t) /* LPDMA comp_wr ext */);
	else
		return (7 * sizeof(struct packet_msg_short));
}

static int gaudi3_nic_create_dwq_packet(struct hltests_nic_db_fifo_packet *wtd, void *swqe,
					void *rwqe, int qp_id)
{
	struct wtd_static *wqe_to_wtd;

	wqe_to_wtd = (struct wtd_static *) malloc(sizeof(struct wtd_static));
	assert_non_null(wqe_to_wtd);

	memset(wqe_to_wtd, 0, sizeof(struct wtd_static));
	memcpy(&wqe_to_wtd->rwqe, rwqe, sizeof(struct rq_wqe));
	memcpy(&wqe_to_wtd->swqe, swqe, sizeof(struct sq_wqe));
	wqe_to_wtd->qpn = int_to_uint_safe(qp_id);

	wtd->packet = wqe_to_wtd;
	wtd->size = sizeof(struct wtd_static);

	return 0;
}

static uint64_t gaudi3_add_direct_write_cq_pkt(int fd, void *buffer, uint32_t buf_off,
						struct hltests_direct_cq_write *direct_cq_write)
{
	struct hltests_pkt_info pkt_info;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = direct_cq_write->qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_CQ_DIRECT_0 +
					(direct_cq_write->cq_id * sizeof(uint32_t));
	pkt_info.msg_long.value = u32_safe_ret_val(direct_cq_write->value, buf_off);
	return hltests_add_msg_long_pkt(fd, buffer, buf_off, &pkt_info);
}

uint32_t gaudi3_get_max_pkt_size(int fd, bool mb, bool eb, uint32_t qid)
{
	uint32_t pkt_size = 0;

	if (hltests_is_pdma_eid(qid)) {
		if (eb)
			pkt_size += sizeof(struct pqm_packet_fence) +
				sizeof(struct pqm_packet_lin_pdma) +
				3 * sizeof(uint64_t) /* LPDMA comp_wr ext */;

		if (mb)
			pkt_size += sizeof(struct pqm_packet_nop);

		pkt_size += sizeof(struct pqm_packet_lin_pdma) +
				3 * sizeof(uint64_t) /* LPDMA comp_wr ext */;
	} else {
		pkt_size = sizeof(struct packet_lin_dma) +
				sizeof(uint64_t) /* LDMA src/dst 32b-high addr ext */;
	}

	return pkt_size;
}

/*
 * Calculate the PI value to provide the HW before pushing to the DB packet.
 * In 4 cycle DBs mechanism each WQ is sent in quarters, and will
 * run in 4 iterations, i.e. for WQ size of 16, instead of providing PI = 16
 * and ring one doorbell, now we provide PI = PI + 4 for each iteration and
 * ring 4 doorbells.
 * Returned result is wrapped around WQ size.
 * In case the completion type is not SOB, means that we are not running in
 * iterations hance no need to divide the WQ to quraters.
 */
static uint32_t gaudi3_nic_get_hw_wq_pi(uint32_t nwqs, uint32_t wq_size, uint32_t iteration,
					uint32_t cmpl, bool is_bp_offs)
{
	return ((cmpl != SOB || is_bp_offs) ? nwqs : (uint32_t)
			(((++iteration) * (nwqs >> HL_LOG2((uint32_t)DB_ITER_PER_CYCLE))) &
			 WQ_HW_INDICES_SIZE_MASK));
}

static uint8_t gaudi3_nic_get_db_fifo_element_size(void)
{
	return DB_FIFO_ELEMENT_SIZE;
}

/* NIC Patcher */
#define SOB_WAIT_TOUT_USEC     100000

struct coll_size_params {
	uint32_t stride_between_ranks;
	uint32_t nic_size;
	uint32_t nic_residue;
	uint32_t rank_size;
	uint32_t rank_residue;
};

static int gaudi3_nic_coll_op_comm_group_size(const struct hltests_nic_coll_comm_group *group);
static int
gaudi3_nic_coll_op_comm_group_size_new(const struct hltests_nic_coll_comm_group_new *group);

static int gaudi3_nic_coll_op_format_msg_execute(uint32_t id,
						 struct hltests_nic_db_fifo_packet *msg)
{
	struct coll_desc_exec exec = {};

	assert_non_null(msg);

	exec.ctrl.cmd = COLL_CMD_EXECUTE;
	exec.ctrl.context_id = u8_safe(id);
	exec.ctrl.lane_select = 0x5;
	exec.ctrl.update_bitmask = 0;

	msg->size = sizeof(exec);
	memcpy(msg->packet, &exec, msg->size);
	return 0;
}

static int gaudi3_nic_coll_group_prepare_wqe_params(
						const struct hltests_nic_coll_comm_group *group,
						unsigned int nic, unsigned int conn_id,
						struct hltests_nic_wqe_params *wqe_params)
{
	struct hltests_nic_in_params *p_in;
	struct sq_wqe *swqe;
	struct rq_wqe *rwqe;
	uint64_t local_buf_va, rem_buf_va;
	uint32_t rand = 0, n_wqe, __n_wqe, offset;
	int fd;
	uint16_t first_sob;

	assert_non_null(group);
	assert_non_null(wqe_params);

	fd = group->tests_state->fd;
	p_in = group->in_params;

	/* assert (current) test limitations */
	assert_true(p_in->test == LPBK);
	assert_true(p_in->test_opcode == TEST_OPCODE_LINEAR_WRITE ||
			p_in->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE ||
			p_in->test_opcode == TEST_OPCODE_RENDEZVOUS_READ);

	memset(wqe_params, 0, sizeof(*wqe_params));

	first_sob = hltests_get_first_avail_sob(fd);

	__n_wqe = u32_safe(p_in->data_size / p_in->wqe_size);
	n_wqe = (__n_wqe < WQES_MIN) ? WQES_MIN : __n_wqe;
	offset = n_wqe * (conn_id - gaudi3_nic_get_wq_offset(fd, uint_to_int_safe(nic), conn_id));
	swqe = gaudi3_nic_get_swqe(p_in->swqe_arr[nic], offset);
	rwqe = gaudi3_nic_get_rwqe(p_in->rwqe_arr[nic], offset);

	local_buf_va = ((uint64_t) (swqe->local_address_63_32) << 32) |
			swqe->local_address_31_0;
	rem_buf_va = ((uint64_t) (swqe->remote_address_63_32) << 32) |
			swqe->remote_address_31_0;

	wqe_params->sq_wqe = swqe;
	wqe_params->rq_wqe = rwqe;
	wqe_params->size = p_in->data_size;
	wqe_params->ackreq = 1;
	wqe_params->tag = uint_to_int_safe(rand);
	wqe_params->cmpl = p_in->cmpl;
	wqe_params->test_opcode = p_in->test_opcode;
	wqe_params->local_address = local_buf_va;
	wqe_params->remote_address = rem_buf_va;
	wqe_params->reduction_cfg = p_in->reduction_cfg;
	wqe_params->compression_en = p_in->compression_en;
	wqe_params->downscale_en = p_in->downscale_en;
	wqe_params->upscale_en = p_in->upscale_en;

	return 0;
}

static int
gaudi3_nic_coll_group_prepare_wqe_params_new(const struct hltests_nic_coll_comm_group_new *group,
					     unsigned int nic, unsigned int conn_id,
					     struct hltests_nic_wqe_params *wqe_params)
{
	const struct hltests_nic_test_params *params;
	struct sq_wqe *swqe;
	struct rq_wqe *rwqe;
	uint64_t local_buf_va, rem_buf_va;
	uint32_t rand = 0, n_wqe, __n_wqe, offset;
	int fd;
	uint16_t first_sob;
	bool upscale_en = false, downscale_en = false;

	assert_non_null(group);
	assert_non_null(wqe_params);

	fd = group->tests_state->fd;
	params = group->params;

	/* assert (current) test limitations */
	assert_true(params->cfg->test_opcode == TEST_OPCODE_LINEAR_WRITE ||
		    params->cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE ||
		    params->cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ);

	if (params->cfg->reduction_en) {
		upscale_en = params->cfg->red_dt == HLTESTS_NIC_REDUCTION_UPSCALING_BF16;
		downscale_en = params->cfg->red_dt == HLTESTS_NIC_REDUCTION_DOWNSCALING_TO_BF16;
	}

	memset(wqe_params, 0, sizeof(*wqe_params));

	first_sob = hltests_get_first_avail_sob(fd);

	__n_wqe = u32_safe(params->data_size / params->wqe_size);
	n_wqe = (__n_wqe < WQES_MIN) ? WQES_MIN : __n_wqe;
	offset = n_wqe * (conn_id - gaudi3_nic_get_wq_offset(fd, uint_to_int_safe(nic), conn_id));
	swqe = gaudi3_nic_get_swqe(params->swqe_arr[nic], offset);
	rwqe = gaudi3_nic_get_rwqe(params->rwqe_arr[nic], offset);

	local_buf_va = ((uint64_t)(swqe->local_address_63_32) << 32) | swqe->local_address_31_0;
	rem_buf_va = ((uint64_t)(swqe->remote_address_63_32) << 32) | swqe->remote_address_31_0;

	wqe_params->sq_wqe = swqe;
	wqe_params->rq_wqe = rwqe;
	wqe_params->size = params->data_size;
	wqe_params->ackreq = 1;
	wqe_params->tag = uint_to_int_safe(rand);
	wqe_params->cmpl = params->cfg->cmpl;
	wqe_params->test_opcode = params->cfg->test_opcode;
	wqe_params->local_address = local_buf_va;
	wqe_params->remote_address = rem_buf_va;
	wqe_params->reduction_cfg = params->reduction_cfg;
	wqe_params->compression_en = params->cfg->compression_en;
	wqe_params->downscale_en = downscale_en;
	wqe_params->upscale_en = upscale_en;

	return 0;
}

static int get_reduction_element_size(uint32_t reduction_cfg)
{
	enum gaudi3_red_datatype red_datatype =
			(reduction_cfg >> REDUCTION_DATA_TYPE_SHIFT) & REDUCTION_DATA_TYPE_MSK;

	switch (red_datatype) {
	case GAUDI3_NIC_REDUCTION_INT8:
	case GAUDI3_NIC_REDUCTION_UINT8:
		return 1;

	case GAUDI3_NIC_REDUCTION_INT16:
	case GAUDI3_NIC_REDUCTION_UINT16:
	case GAUDI3_NIC_REDUCTION_BF16:
	case GAUDI3_NIC_REDUCTION_FP16:
	case GAUDI3_NIC_REDUCTION_UPSCALING_FP16:
	case GAUDI3_NIC_REDUCTION_UPSCALING_BF16:
		return 2;

	case GAUDI3_NIC_REDUCTION_INT32:
	case GAUDI3_NIC_REDUCTION_UINT32:
	case GAUDI3_NIC_REDUCTION_FP32:
		return 4;

	default:
		/* Unsupported data type */
		return -1;
	}

	return 0;
}

static int get_coll_op_data_size(enum coll_desc_data_type data_type, uint32_t reduction_cfg)
{
	switch (data_type) {
	case COLL_DESC_DATA_TYPE_REDUCTION:
		return get_reduction_element_size(reduction_cfg);
	case COLL_DESC_DATA_TYPE_128_BYTE:
		return 128;
	case COLL_DESC_DATA_TYPE_256_BYTE:
		return 256;
	default:
		/* Unsupported data type */
		return -1;
	}

	return 0;
}

static enum coll_desc_data_type gaudi3_map_coll_data_type(enum hltests_nic_coll_data_type data_type)
{
	switch (data_type) {
	case HLTESTS_NIC_COLL_DATA_TYPE_REDUCTION:
		return COLL_DESC_DATA_TYPE_REDUCTION;

	case HLTESTS_NIC_COLL_DATA_TYPE_128_BYTE:
		return COLL_DESC_DATA_TYPE_128_BYTE;

	case HLTESTS_NIC_COLL_DATA_TYPE_256_BYTE:
		return COLL_DESC_DATA_TYPE_256_BYTE;

	default:
		return COLL_DESC_DATA_TYPE_INVALID;
	}
}

static int gaudi3_nic_coll_group_get_size_params(const struct hltests_nic_coll_comm_group *group,
						const struct hltests_nic_wqe_params *wqe_params,
						uint32_t num_of_data_chunks,
						struct coll_size_params *size_params)
{
	uint32_t group_size, data_size, elem_size, num_ranks, rank_size, rank_residue, nic_size,
		nic_residue;
	enum coll_desc_data_type coll_data_type;

	coll_data_type = gaudi3_map_coll_data_type(group->in_params->coll_dt);
	assert_true(coll_data_type != COLL_DESC_DATA_TYPE_INVALID);

	elem_size = int_to_uint_safe(get_coll_op_data_size(coll_data_type,
							   u32_safe(wqe_params->reduction_cfg)));
	assert_true(elem_size > 0);

	data_size = u32_safe(wqe_params->size);
	/* normalize data size to chunk size, used for multi-stride */
	assert_false(data_size % num_of_data_chunks);
	data_size = data_size / num_of_data_chunks;
	/* normalize data size to units of elem size */
	assert_false(data_size % elem_size);
	data_size = data_size / elem_size;

	/* calculate sizes and residues
	 * currently we support a single write desc per group which means that all the ranks
	 * must have an equal amount of NICs
	 */
	group_size = int_to_uint_safe(gaudi3_nic_coll_op_comm_group_size(group));
	assert_true(group_size > 0);

	num_ranks = group->in_params->disregard_rank ? 1 : group->n_ranks;
	rank_size = data_size / num_ranks;
	assert_in_range(rank_size, 0, BIT_ULL(24) - 1);
	rank_residue = data_size - rank_size * num_ranks;
	assert_in_range(rank_residue, 0, BIT_ULL(8) - 1);
	nic_size = rank_size / group->nodes_per_rank;
	assert_in_range(nic_size, 0, BIT_ULL(24) - 1);
	nic_residue = rank_size - nic_size * group->nodes_per_rank;
	assert_in_range(nic_residue, 0, BIT_ULL(8) - 1);

	size_params->rank_size = rank_size;
	size_params->rank_residue = rank_residue;
	size_params->nic_size = nic_size;
	size_params->nic_residue = nic_residue;
	size_params->stride_between_ranks = rank_size;

	return 0;
}

static int
gaudi3_nic_coll_group_get_size_params_new(const struct hltests_nic_coll_comm_group_new *group,
					  const struct hltests_nic_wqe_params *wqe_params,
					  uint32_t num_of_data_chunks,
					  struct coll_size_params *size_params)
{
	uint32_t group_size, data_size, elem_size, num_ranks, rank_size, rank_residue, nic_size,
		 nic_residue;
	enum coll_desc_data_type coll_data_type;

	coll_data_type = gaudi3_map_coll_data_type(group->params->cfg->coll_data_type);
	assert_true(coll_data_type != COLL_DESC_DATA_TYPE_INVALID);

	elem_size = int_to_uint_safe(get_coll_op_data_size(coll_data_type,
							   u32_safe(wqe_params->reduction_cfg)));
	assert_true(elem_size > 0);

	data_size = u32_safe(wqe_params->size);
	/* normalize data size to chunk size, used for multi-stride */
	assert_false(data_size % num_of_data_chunks);
	data_size = data_size / num_of_data_chunks;
	/* normalize data size to units of elem size */
	assert_false(data_size % elem_size);
	data_size = data_size / elem_size;

	/* calculate sizes and residues
	 * currently we support a single write desc per group which means that all the ranks
	 * must have an equal amount of NICs
	 */
	group_size = int_to_uint_safe(gaudi3_nic_coll_op_comm_group_size_new(group));
	assert_true(group_size > 0);

	num_ranks = group->params->cfg->disregard_rank ? 1 : group->n_ranks;
	rank_size = data_size / num_ranks;
	assert_in_range(rank_size, 0, BIT_ULL(24) - 1);
	rank_residue = data_size - rank_size * num_ranks;
	assert_in_range(rank_residue, 0, BIT_ULL(8) - 1);
	nic_size = rank_size / group->nodes_per_rank;
	assert_in_range(nic_size, 0, BIT_ULL(24) - 1);
	nic_residue = rank_size - nic_size * group->nodes_per_rank;
	assert_in_range(nic_residue, 0, BIT_ULL(8) - 1);

	size_params->rank_size = rank_size;
	size_params->rank_residue = rank_residue;
	size_params->nic_size = nic_size;
	size_params->nic_residue = nic_residue;
	size_params->stride_between_ranks = rank_size;

	return 0;
}

static uint32_t gaudi3_nic_coll_get_reduction_opcode(
					const struct hltests_nic_wqe_params *wqe_params, bool send)
{
	bool is_down_and_up = gaudi3_nic_reduction_is_down_and_up(wqe_params);

	if (send)
		return lower_32_bits(wqe_params->reduction_cfg);
	else if (wqe_params->upscale_en || is_down_and_up)
		/* reduction data type should be set to UINT32 as the remote element size is 4B */
		return GAUDI3_NIC_REDUCTION_UINT32 << REDUCTION_DATA_TYPE_SHIFT;
	else
		return (wqe_params->reduction_cfg &
				(REDUCTION_DATA_TYPE_MSK << REDUCTION_DATA_TYPE_SHIFT));

}

static void gaudi3_nic_direct_coll_group_fill_oper(const struct hltests_nic_wqe_params *wqe_params,
						enum wqe_opcode opcode,
						uint8_t rank_residue, bool send,
						struct direct_coll_desc_ent_oper *oper)
{
	oper->reduction_opcode =
		bitfield_safe_ret(gaudi3_nic_coll_get_reduction_opcode(wqe_params, send), 12);
	oper->compression = wqe_params->compression_en;
	oper->read_clear = 0;
	oper->ack_req = !!wqe_params->ackreq;
	oper->opcode = opcode;
	oper->rank_residue_sz = rank_residue;
}

static int gaudi3_nic_coll_group_fill_oper(const struct hltests_nic_wqe_params *wqe_params,
						enum wqe_opcode opcode,
						uint8_t rank_residue,
						struct coll_desc_ent_oper *oper,
						bool send, enum hltests_nic_coll_data_type coll_dt)
{
	enum coll_desc_data_type coll_data_type;

	coll_data_type = gaudi3_map_coll_data_type(coll_dt);
	assert_true(coll_data_type != COLL_DESC_DATA_TYPE_INVALID);

	oper->reduction_opcode =
			bitfield_safe(gaudi3_nic_coll_get_reduction_opcode(wqe_params, send), 12);

	/* coll data type should be changed for remote data type when:
	 * - downscale is set and data type is 256 - remote side has the granularity of 128 bytes
	 * - upscale is set and data type is 128 - remote side has the granularity of 256 bytes
	 */
	if (send || (coll_data_type == COLL_DESC_DATA_TYPE_REDUCTION) ||
		(!wqe_params->downscale_en && !wqe_params->upscale_en))
		oper->data_type = coll_data_type;
	else if (wqe_params->downscale_en)
		oper->data_type = COLL_DESC_DATA_TYPE_128_BYTE;
	else /* wqe_params->upscale_en */
		oper->data_type = COLL_DESC_DATA_TYPE_256_BYTE;

	oper->compression = wqe_params->compression_en;
	oper->strategy = COLL_DESC_SPREAD_RESIDUE_LAST;
	oper->opcode = opcode;
	oper->rc = 0;		/* No atomic fetch and clear */
	oper->ack_req = !!wqe_params->ackreq;
	oper->reset_pipeline = 1;
	oper->rank_residue_sz = rank_residue;

	return 0;
}


static void gaudi3_nic_coll_group_fill_comp(const struct hltests_nic_wqe_params *wqe_params,
						bool local, struct coll_desc_ent_comp *comp)
{
	struct sq_wqe *swqe = wqe_params->sq_wqe;
	struct rq_wqe *rwqe = wqe_params->rq_wqe;
	uint32_t sob_id, sm_id;

	if (local) {
		sob_id = rwqe->local_sob_id;
		sm_id = rwqe->local_sm_id;
	} else {
		sob_id = swqe->remote_sob_id;
		sm_id = swqe->remote_sm_id;
	}

	comp->sob_id = bitfield_safe_ret(sob_id, 13);
	/* if sob_id > SOB_OBJ_0_8191 then sub sync manager id is 1 */
	comp->sub_sm = ((sob_id + 1) > (NUM_OF_SOBJS_PER_SM / 2)) ? 1 : 0;
	comp->sm = bitfield_safe_ret(sm_id, 3);
	comp->mcid = 0;
	comp->cache_class = 0;
	comp->lso = 0;
	comp->so_cmd = SOB_INC;
	comp->completion_type = bitfield_safe_ret(get_hw_completion_type(wqe_params->cmpl), 2);
	comp->alloc_h = 1;
}

static int gaudi3_nic_direct_coll_group_fill_misc_params(bool send,
					struct direct_coll_desc_misc_params *misc,
					const struct hltests_nic_coll_comm_group *group)
{
	uint32_t max_n_ports, port, macro, lane_offset;
	bool is_200_gbps;

	enum coll_desc_data_type coll_data_type;

	coll_data_type = gaudi3_map_coll_data_type(group->in_params->coll_dt);
	assert_true(coll_data_type != COLL_DESC_DATA_TYPE_INVALID);

	/* coll data type should be changed for remote data type when:
	 * - downscale is set and data type is 256 - remote side has the granularity of 128 bytes
	 * - upscale is set and data type is 128 - remote side has the granularity of 256 bytes
	 */
	if (send || (coll_data_type == COLL_DESC_DATA_TYPE_REDUCTION) ||
		(!group->in_params->downscale_en && !group->in_params->upscale_en))
		misc->data_type = coll_data_type;
	else if (group->in_params->downscale_en)
		misc->data_type = COLL_DESC_DATA_TYPE_128_BYTE;
	else /* group->in_params->upscale_en */
		misc->data_type = COLL_DESC_DATA_TYPE_256_BYTE;

	max_n_ports = gaudi3_nic_get_max_num_of_ports();
	is_200_gbps = NIC_IS_200_GBPS_MODE(group->tests_state->fd, group->nodes_mask);

	misc->strategy = 0;
	misc->disregard_rank = bitfield_safe(group->in_params->disregard_rank, 1);
	misc->disregard_lag = 0;

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		macro = port >> (is_200_gbps ? 1 : 0);
		lane_offset = is_200_gbps ? port % 2 : 0;

		/* In direct patcher, we support only 400Gbps and 200Gbps mode, hence only 2 bits
		 * are needed for each port, so multiply the macro by 2
		 */
		misc->ports_en |= bitfield_safe(BIT(macro * 2 + lane_offset), 24);
	}

	return 0;
}

static int gaudi3_nic_direct_coll_group_fill_misc_params_new(
	bool send, struct direct_coll_desc_misc_params *misc,
	const struct hltests_nic_coll_comm_group_new *group)
{
	uint32_t max_n_ports, port, macro, lane_offset;
	bool is_200_gbps;

	enum coll_desc_data_type coll_data_type;
	bool upscale_en = false, downscale_en = false;

	coll_data_type = gaudi3_map_coll_data_type(group->params->cfg->coll_data_type);
	assert_true(coll_data_type != COLL_DESC_DATA_TYPE_INVALID);

	if (group->params->cfg->reduction_en) {
		upscale_en = group->params->cfg->red_dt == HLTESTS_NIC_REDUCTION_UPSCALING_BF16;
		downscale_en = group->params->cfg->red_dt ==
			       HLTESTS_NIC_REDUCTION_DOWNSCALING_TO_BF16;
	}

	/* coll data type should be changed for remote data type when:
	 * - downscale is set and data type is 256 - remote side has the granularity of 128 bytes
	 * - upscale is set and data type is 128 - remote side has the granularity of 256 bytes
	 */
	if (send || (coll_data_type == COLL_DESC_DATA_TYPE_REDUCTION) ||
	    (!downscale_en && !upscale_en))
		misc->data_type = coll_data_type;
	else if (downscale_en)
		misc->data_type = COLL_DESC_DATA_TYPE_128_BYTE;
	else /* group->in_params->upscale_en */
		misc->data_type = COLL_DESC_DATA_TYPE_256_BYTE;

	max_n_ports = gaudi3_nic_get_max_num_of_ports();
	is_200_gbps = NIC_IS_200_GBPS_MODE(group->tests_state->fd, group->nodes_mask);

	misc->strategy = 0;
	misc->disregard_rank = group->params->cfg->disregard_rank;
	misc->disregard_lag = 0;

	for (port = 0; port < max_n_ports; port++) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		macro = port >> (is_200_gbps ? 1 : 0);
		lane_offset = is_200_gbps ? port % 2 : 0;

		/* In direct patcher, we support only 400Gbps and 200Gbps mode, hence only 2 bits
		 * are needed for each port, so multiply the macro by 2
		 */
		misc->ports_en |= bitfield_safe(BIT(macro * 2 + lane_offset), 24);
	}

	return 0;
}

static uint32_t get_collective_qp_id(const struct hltests_nic_coll_comm_group *group)
{
	struct hltests_device *hdev;
	struct gaudi3_priv *gaudi3;
	uint32_t first_en_port;
	int fd;

	fd = group->tests_state->fd;
	hdev = get_hdev_from_fd(fd);
	gaudi3 = hdev->priv;
	first_en_port = int_to_uint_safe_ret_val(__builtin_ffsll((int64_t)group->nodes_mask) - 1,
						 (uint32_t)-1);
	assert_in_range_ret_val(first_en_port, 0, MAX_NIC_NUMBER_OF_PORTS - 1, (uint32_t)-1);

	return group->nodes[first_en_port].conn_id - gaudi3->coll_qps_offset[first_en_port];
}

static uint32_t get_collective_qp_id_new(const struct hltests_nic_coll_comm_group_new *group)
{
	struct hltests_device *hdev;
	struct gaudi3_priv *gaudi3;
	uint32_t first_en_port;
	int fd;

	fd = group->tests_state->fd;
	hdev = get_hdev_from_fd(fd);
	gaudi3 = hdev->priv;
	first_en_port = int_to_uint_safe_ret_val(__builtin_ffsll((int64_t)group->nodes_mask) - 1,
						 (uint32_t)-1);
	assert_in_range_ret_val(first_en_port, 0, MAX_NIC_NUMBER_OF_PORTS - 1, (uint32_t)-1);

	return group->nodes[first_en_port].conn_id - gaudi3->coll_qps_offset[first_en_port];
}

static int gaudi3_nic_direct_coll_group_fill_write_desc(
					const struct hltests_nic_coll_comm_group *group,
					const struct hltests_nic_wqe_params *wqe_params,
					struct direct_coll_desc_write *wdesc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;

	assert_non_null(group);
	assert_non_null(wqe_params);
	assert_non_null(wdesc);
	assert_true(wqe_params->tag >= 0);

	gaudi3_nic_coll_group_get_size_params(group, wqe_params, 1, &size_params);

	wdesc->ctrl.cmd = COLL_CMD_DESCRIPTOR_WRITE;
	wdesc->ctrl.qp = bitfield_safe(get_collective_qp_id(group), 24);

	opcode =  (group->in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) ?
			WQE_RENDEZVOUS_READ : WQE_LINEAR;

	gaudi3_nic_direct_coll_group_fill_oper(wqe_params, opcode,
						u8_safe(size_params.rank_residue), true,
						&wdesc->oper);

	wdesc->stride_between_ranks = size_params.stride_between_ranks;
	wdesc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
	wdesc->nic.nic_residue = u8_safe(size_params.nic_residue);
	wdesc->local_base_addr = wqe_params->local_address;
	wdesc->rem_base_addr = wqe_params->remote_address;
	wdesc->rem_tag = (__u32)wqe_params->tag;

	gaudi3_nic_direct_coll_group_fill_misc_params(true, &wdesc->misc, group);

	gaudi3_nic_coll_group_fill_comp(wqe_params, true, &wdesc->local_comp);

	gaudi3_nic_coll_group_fill_comp(wqe_params, false, &wdesc->rem_comp);

	return 0;
}

static int gaudi3_nic_direct_coll_group_fill_write_desc_new(
	const struct hltests_nic_coll_comm_group_new *group,
	const struct hltests_nic_wqe_params *wqe_params, struct direct_coll_desc_write *wdesc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;

	assert_non_null(group);
	assert_non_null(wqe_params);
	assert_non_null(wdesc);
	assert_true(wqe_params->tag >= 0);

	gaudi3_nic_coll_group_get_size_params_new(group, wqe_params, 1, &size_params);

	wdesc->ctrl.cmd = COLL_CMD_DESCRIPTOR_WRITE;
	wdesc->ctrl.qp = bitfield_safe(get_collective_qp_id_new(group), 24);
	opcode = (group->params->cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) ?
			 WQE_RENDEZVOUS_READ :
			 WQE_LINEAR;

	gaudi3_nic_direct_coll_group_fill_oper(wqe_params, opcode,
					       u8_safe(size_params.rank_residue), true,
					       &wdesc->oper);

	wdesc->stride_between_ranks = size_params.stride_between_ranks;
	wdesc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
	wdesc->nic.nic_residue = u8_safe(size_params.nic_residue);
	wdesc->local_base_addr = wqe_params->local_address;
	wdesc->rem_base_addr = wqe_params->remote_address;
	wdesc->rem_tag = (__u32)wqe_params->tag;

	gaudi3_nic_direct_coll_group_fill_misc_params_new(true, &wdesc->misc, group);

	gaudi3_nic_coll_group_fill_comp(wqe_params, true, &wdesc->local_comp);

	gaudi3_nic_coll_group_fill_comp(wqe_params, false, &wdesc->rem_comp);

	return 0;
}

static int gaudi3_nic_coll_group_fill_write_desc(const struct hltests_nic_coll_comm_group *group,
						const struct hltests_nic_wqe_params *wqe_params,
						struct coll_desc_write *wdesc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;

	assert_non_null(group);
	assert_non_null(wqe_params);
	assert_non_null(wdesc);
	assert_true(wqe_params->tag >= 0);

	gaudi3_nic_coll_group_get_size_params(group, wqe_params, 1, &size_params);

	wdesc->ctrl.update_bitmask = 0x7ff;
	wdesc->ctrl.lane_select = 0x5;
	wdesc->ctrl.cmd = COLL_CMD_DESCRIPTOR_WRITE;
	wdesc->ctrl.context_id = u8_safe(group->id);

	opcode =  (group->in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) ?
			WQE_RENDEZVOUS_READ : WQE_LINEAR;
	gaudi3_nic_coll_group_fill_oper(wqe_params, opcode, u8_safe(size_params.rank_residue),
					&wdesc->oper, true, group->in_params->coll_dt);

	wdesc->stride_between_ranks = size_params.stride_between_ranks;
	wdesc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
	wdesc->nic.nic_residue = u8_safe(size_params.nic_residue);

	wdesc->local_base_addr = wqe_params->local_address;
	wdesc->local_tag = (__u32)wqe_params->tag;

	wdesc->rem_base_addr = wqe_params->remote_address;
	wdesc->rem_tag = (__u32)wqe_params->tag;

	gaudi3_nic_coll_group_fill_comp(wqe_params, true, &wdesc->local_comp);

	gaudi3_nic_coll_group_fill_comp(wqe_params, false, &wdesc->rem_comp);

	return 0;
}

static int
gaudi3_nic_coll_group_fill_write_desc_new(const struct hltests_nic_coll_comm_group_new *group,
					  const struct hltests_nic_wqe_params *wqe_params,
					  struct coll_desc_write *wdesc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;

	assert_non_null(group);
	assert_non_null(wqe_params);
	assert_non_null(wdesc);
	assert_true(wqe_params->tag >= 0);

	gaudi3_nic_coll_group_get_size_params_new(group, wqe_params, 1, &size_params);

	wdesc->ctrl.update_bitmask = 0x7ff;
	wdesc->ctrl.lane_select = 0x5;
	wdesc->ctrl.cmd = COLL_CMD_DESCRIPTOR_WRITE;
	wdesc->ctrl.context_id = u8_safe(group->id);

	opcode = (group->params->cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) ?
			 WQE_RENDEZVOUS_READ :
			 WQE_LINEAR;
	gaudi3_nic_coll_group_fill_oper(wqe_params, opcode, u8_safe(size_params.rank_residue),
					&wdesc->oper, true, group->params->cfg->coll_data_type);

	wdesc->stride_between_ranks = size_params.stride_between_ranks;
	wdesc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
	wdesc->nic.nic_residue = u8_safe(size_params.nic_residue);

	wdesc->local_base_addr = wqe_params->local_address;
	wdesc->local_tag = (__u32)wqe_params->tag;

	wdesc->rem_base_addr = wqe_params->remote_address;
	wdesc->rem_tag = (__u32)wqe_params->tag;

	gaudi3_nic_coll_group_fill_comp(wqe_params, true, &wdesc->local_comp);

	gaudi3_nic_coll_group_fill_comp(wqe_params, false, &wdesc->rem_comp);

	return 0;
}

static int gaudi3_nic_direct_coll_group_fill_send_recv_desc(bool send,
					const struct hltests_nic_coll_comm_group *group,
					const struct hltests_nic_wqe_params *wqe_params,
					struct direct_coll_desc_send_receive *sr_desc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;
	uint64_t first_node_mask, nodes_with_ports_mask;
	uint32_t node_idx, first_node_bit;

	gaudi3_nic_coll_group_get_size_params(group, wqe_params, 1, &size_params);

	sr_desc->ctrl.cmd = COLL_CMD_DESCRIPTOR_SND_RCV;
	sr_desc->ctrl.qp = bitfield_safe(get_collective_qp_id(group), 24);

	opcode = send ? WQE_LINEAR : WQE_RENDEZVOUS_WRITE;

	gaudi3_nic_direct_coll_group_fill_oper(wqe_params, opcode,
					       u8_safe(size_params.rank_residue),
					       send, &sr_desc->oper);

	sr_desc->stride_between_ranks = size_params.stride_between_ranks;
	sr_desc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
	sr_desc->nic.nic_residue = u8_safe(size_params.nic_residue);

	if (send) {
		sr_desc->local_base_addr = wqe_params->local_address;
	} else {
		/* Sent by the receive side, meaning the local_base_addr field is the remote address
		 * for the sender.
		 */
		sr_desc->local_base_addr = wqe_params->remote_address;
		/* in v_op, there's no LAG. Therefore, the full remote address should be set */
		if (group->in_params->rdv_type == HLTESTS_NIC_RDV_V_OP) {
			/* Find the index of the current node within the selected ports */
			first_node_bit = (uint32_t)__builtin_ffsll((int64_t)group->nodes_mask) - 1;
			assert_in_range(first_node_bit, 0, MAX_NIC_NUMBER_OF_PORTS - 1);
			first_node_mask = (((uint64_t)1 << (first_node_bit + 1)) - 1);
			nodes_with_ports_mask = group->in_params->port_mask & first_node_mask;
			node_idx =
				int_to_uint_safe(__builtin_popcountll(nodes_with_ports_mask) - 1);

			sr_desc->local_base_addr += sr_desc->nic.nic_size * node_idx;
		}
	}
	gaudi3_nic_direct_coll_group_fill_misc_params(send, &sr_desc->misc, group);
	gaudi3_nic_coll_group_fill_comp(wqe_params, send, &sr_desc->local_comp);

	return 0;
}

static int gaudi3_nic_direct_coll_group_fill_send_recv_desc_new(
	bool send, const struct hltests_nic_coll_comm_group_new *group,
	const struct hltests_nic_wqe_params *wqe_params,
	struct direct_coll_desc_send_receive *sr_desc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;
	uint64_t first_node_mask, nodes_with_ports_mask;
	uint32_t node_idx, first_node_bit;

	assert_true(group->nodes_mask);

	gaudi3_nic_coll_group_get_size_params_new(group, wqe_params, 1, &size_params);

	sr_desc->ctrl.cmd = COLL_CMD_DESCRIPTOR_SND_RCV;
	sr_desc->ctrl.qp = bitfield_safe(get_collective_qp_id_new(group), 24);

	opcode = send ? WQE_LINEAR : WQE_RENDEZVOUS_WRITE;

	gaudi3_nic_direct_coll_group_fill_oper(wqe_params, opcode,
					       u8_safe(size_params.rank_residue), send,
					       &sr_desc->oper);

	sr_desc->stride_between_ranks = size_params.stride_between_ranks;
	sr_desc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
	sr_desc->nic.nic_residue = u8_safe(size_params.nic_residue);

	if (send) {
		sr_desc->local_base_addr = wqe_params->local_address;
	} else {
		/* Sent by the receive side, meaning the local_base_addr field is the remote address
		 * for the sender.
		 */
		sr_desc->local_base_addr = wqe_params->remote_address;
		/* in v_op, there's no LAG. Therefore, the full remote address should be set */
		if (group->params->cfg->rdv_type == HLTESTS_NIC_RDV_V_OP) {
			/* Find the index of the current node within the selected ports */
			first_node_bit = (uint32_t)__builtin_ffsll((int64_t)group->nodes_mask) - 1;
			assert_in_range(first_node_bit, 0, MAX_NIC_NUMBER_OF_PORTS - 1);
			first_node_mask = (((uint64_t)1 << (first_node_bit + 1)) - 1);
			nodes_with_ports_mask = group->params->cfg->ports_mask & first_node_mask;
			node_idx = (uint32_t)__builtin_popcount((uint32_t)nodes_with_ports_mask) -
				   1;

			assert_in_range(node_idx, 0, MAX_NIC_NUMBER_OF_PORTS - 1);
			sr_desc->local_base_addr += sr_desc->nic.nic_size * (unsigned int)node_idx;
		}
	}
	gaudi3_nic_direct_coll_group_fill_misc_params_new(send, &sr_desc->misc, group);
	gaudi3_nic_coll_group_fill_comp(wqe_params, send, &sr_desc->local_comp);

	return 0;
}

static int gaudi3_nic_coll_group_fill_send_recv_desc(bool send,
					const struct hltests_nic_coll_comm_group *group,
					const struct hltests_nic_wqe_params *wqe_params,
					struct coll_desc_send_receive *sr_desc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;

	assert_non_null(group);
	assert_non_null(group->in_params);
	assert_non_null(wqe_params);
	assert_non_null(sr_desc);
	assert_true(group->in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE);
	assert_true(group->nodes_mask);

	gaudi3_nic_coll_group_get_size_params(group, wqe_params, 1, &size_params);

	sr_desc->ctrl.update_bitmask = 0x7f;
	sr_desc->ctrl.lane_select = 0x5;
	sr_desc->ctrl.cmd = COLL_CMD_DESCRIPTOR_SND_RCV;
	sr_desc->ctrl.context_id = u8_safe(group->id);

	opcode = send ? WQE_LINEAR : WQE_RENDEZVOUS_WRITE;
	gaudi3_nic_coll_group_fill_oper(wqe_params, opcode, u8_safe(size_params.rank_residue),
					&sr_desc->oper, send, group->in_params->coll_dt);

	sr_desc->stride_between_ranks = size_params.stride_between_ranks;
	sr_desc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
	sr_desc->nic.nic_residue = u8_safe(size_params.nic_residue);

	if (send) {
		sr_desc->local_base_addr = wqe_params->local_address;
	} else {
		/* Sent by the receive side, meaning the local_base_addr field is the remote address
		 * for the sender.
		 */
		sr_desc->local_base_addr = wqe_params->remote_address;
		/* in v_op, there's no LAG. Therefore, the full remote address should be set */
		if (group->in_params->rdv_type == HLTESTS_NIC_RDV_V_OP)
			sr_desc->local_base_addr += (__u64)(sr_desc->nic.nic_size *
				int_to_uint_safe(__builtin_ffsll((int64_t)group->nodes_mask) - 1));
	}

	sr_desc->local_tag = int_to_uint_safe(wqe_params->tag);
	gaudi3_nic_coll_group_fill_comp(wqe_params, send, &sr_desc->comp);

	return 0;
}

static int gaudi3_nic_coll_group_fill_send_recv_desc_new(
	bool send, const struct hltests_nic_coll_comm_group_new *group,
	const struct hltests_nic_wqe_params *wqe_params, struct coll_desc_send_receive *sr_desc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;

	assert_non_null(group);
	assert_non_null(group->params);
	assert_non_null(wqe_params);
	assert_non_null(sr_desc);
	assert_true(group->params->cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE);
	assert_true(group->nodes_mask);

	gaudi3_nic_coll_group_get_size_params_new(group, wqe_params, 1, &size_params);

	sr_desc->ctrl.update_bitmask = 0x7f;
	sr_desc->ctrl.lane_select = 0x5;
	sr_desc->ctrl.cmd = COLL_CMD_DESCRIPTOR_SND_RCV;
	sr_desc->ctrl.context_id = u8_safe(group->id);

	opcode = send ? WQE_LINEAR : WQE_RENDEZVOUS_WRITE;
	gaudi3_nic_coll_group_fill_oper(wqe_params, opcode, u8_safe(size_params.rank_residue),
					&sr_desc->oper, send, group->params->cfg->coll_data_type);

	sr_desc->stride_between_ranks = size_params.stride_between_ranks;
	sr_desc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
	sr_desc->nic.nic_residue = u8_safe(size_params.nic_residue);

	if (send) {
		sr_desc->local_base_addr = wqe_params->local_address;
	} else {
		/* Sent by the receive side, meaning the local_base_addr field is the remote address
		 * for the sender.
		 */
		sr_desc->local_base_addr = wqe_params->remote_address;
		/* in v_op, there's no LAG. Therefore, the full remote address should be set */
		if (group->params->cfg->rdv_type == HLTESTS_NIC_RDV_V_OP)
			sr_desc->local_base_addr +=
				(__u64)(sr_desc->nic.nic_size *
				int_to_uint_safe((__builtin_ffsll((int64_t)group->nodes_mask) - 1)));
	}
	sr_desc->local_tag = int_to_uint_safe(wqe_params->tag);

	gaudi3_nic_coll_group_fill_comp(wqe_params, send, &sr_desc->comp);

	return 0;
}

static int gaudi3_nic_direct_coll_group_fill_multi_stride_desc(bool send,
						const struct hltests_nic_coll_comm_group *group,
						const struct hltests_nic_wqe_params *wqe_params,
						struct direct_coll_desc_ms_send_receive *ms_desc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;
	uint32_t stride_mul, n_ranks;

	ms_desc->axes.pipeline_axis = COLL_DESC_Z_AXIS;
	ms_desc->axes.rank_axis = bitfield_safe(group->in_params->axis_rank, 2);

	ms_desc->ctrl.cmd = COLL_CMD_DESCRIPTOR_MS_SND_RCV;
	ms_desc->ctrl.qp = bitfield_safe(get_collective_qp_id(group), 24);

	/* We will split the surfacce of our "tensor" according to 8 * 16 for different axis */
	ms_desc->number_of_strides_1 = 8;
	ms_desc->number_of_strides_2 = 16;

	stride_mul = ms_desc->number_of_strides_1 * ms_desc->number_of_strides_2;
	gaudi3_nic_coll_group_get_size_params(group, wqe_params, stride_mul, &size_params);
	n_ranks = group->in_params->disregard_rank ? 1 : group->n_ranks;

	opcode = send ? WQE_MULTI_STRIDE_DUAL : WQE_RENDEZVOUS_WRITE;
	gaudi3_nic_direct_coll_group_fill_oper(wqe_params, opcode,
					       u8_safe(size_params.rank_residue),
					       send, &ms_desc->oper);
	gaudi3_nic_direct_coll_group_fill_misc_params(send, &ms_desc->misc, group);

	if (send)
		ms_desc->local_base_addr = wqe_params->local_address;
	else
		/* Sent by the receive side, meaning the local_base_addr field is the remote address
		 * for the sender.
		 */
		ms_desc->local_base_addr = wqe_params->remote_address;

	gaudi3_nic_coll_group_fill_comp(wqe_params, send, &ms_desc->local_comp);

	ms_desc->stride_size = u32_safe(wqe_params->size / stride_mul);

	if (ms_desc->axes.rank_axis == COLL_DESC_Z_AXIS) {
		ms_desc->stride_offset_1 = size_params.rank_size * n_ranks +
					size_params.rank_residue;
		ms_desc->stride_offset_2 = ms_desc->stride_offset_1 * ms_desc->number_of_strides_1;
		ms_desc->stride_between_ranks = size_params.stride_between_ranks;
		ms_desc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
		ms_desc->nic.nic_residue = u8_safe(size_params.nic_residue);
	} else if (ms_desc->axes.rank_axis == COLL_DESC_X_AXIS) {
		ms_desc->stride_offset_1 = ms_desc->stride_size;
		ms_desc->stride_offset_2 = ms_desc->stride_offset_1 * ms_desc->number_of_strides_1;
		ms_desc->stride_between_ranks = ms_desc->number_of_strides_1 / n_ranks;
		ms_desc->oper.rank_residue_sz = bitfield_safe(ms_desc->number_of_strides_1
						- ms_desc->stride_between_ranks * n_ranks, 12);
		ms_desc->nic.nic_size =
				bitfield_safe(ms_desc->stride_size / group->nodes_per_rank, 24);
		ms_desc->nic.nic_residue = u8_safe(ms_desc->stride_size % group->nodes_per_rank);
	} else {
		ms_desc->stride_offset_1 = ms_desc->stride_size;
		ms_desc->stride_offset_2 = ms_desc->stride_offset_1 * ms_desc->number_of_strides_1;
		ms_desc->stride_between_ranks = ms_desc->number_of_strides_2 / n_ranks;
		ms_desc->oper.rank_residue_sz = bitfield_safe(ms_desc->number_of_strides_2
						- ms_desc->stride_between_ranks * n_ranks, 12);
		ms_desc->nic.nic_size =
				bitfield_safe(ms_desc->stride_size / group->nodes_per_rank, 24);
		ms_desc->nic.nic_residue = u8_safe(ms_desc->stride_size % group->nodes_per_rank);
	}

	return 0;
}

static int gaudi3_nic_direct_coll_group_fill_multi_stride_desc_new(
	bool send, const struct hltests_nic_coll_comm_group_new *group,
	const struct hltests_nic_wqe_params *wqe_params,
	struct direct_coll_desc_ms_send_receive *ms_desc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;
	uint32_t stride_mul, n_ranks;

	ms_desc->axes.pipeline_axis = COLL_DESC_Z_AXIS;
	ms_desc->axes.rank_axis = group->params->cfg->coll_rank_axis;

	ms_desc->ctrl.cmd = COLL_CMD_DESCRIPTOR_MS_SND_RCV;
	ms_desc->ctrl.qp = bitfield_safe(get_collective_qp_id_new(group), 24);

	/* We will split the surfacce of our "tensor" according to 8 * 16 for different axis */
	ms_desc->number_of_strides_1 = 8;
	ms_desc->number_of_strides_2 = 16;

	stride_mul = ms_desc->number_of_strides_1 * ms_desc->number_of_strides_2;
	gaudi3_nic_coll_group_get_size_params_new(group, wqe_params, stride_mul, &size_params);
	n_ranks = group->params->cfg->disregard_rank ? 1 : group->n_ranks;

	opcode = send ? WQE_MULTI_STRIDE_DUAL : WQE_RENDEZVOUS_WRITE;
	gaudi3_nic_direct_coll_group_fill_oper(wqe_params, opcode,
					       u8_safe(size_params.rank_residue), send,
					       &ms_desc->oper);
	gaudi3_nic_direct_coll_group_fill_misc_params_new(send, &ms_desc->misc, group);

	if (send)
		ms_desc->local_base_addr = wqe_params->local_address;
	else
		/* Sent by the receive side, meaning the local_base_addr field is the remote address
		 * for the sender.
		 */
		ms_desc->local_base_addr = wqe_params->remote_address;

	gaudi3_nic_coll_group_fill_comp(wqe_params, send, &ms_desc->local_comp);

	ms_desc->stride_size = u32_safe(wqe_params->size / stride_mul);

	if (ms_desc->axes.rank_axis == COLL_DESC_Z_AXIS) {
		ms_desc->stride_offset_1 =
			size_params.rank_size * n_ranks + size_params.rank_residue;
		ms_desc->stride_offset_2 = ms_desc->stride_offset_1 * ms_desc->number_of_strides_1;
		ms_desc->stride_between_ranks = size_params.stride_between_ranks;
		ms_desc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
		ms_desc->nic.nic_residue = u8_safe(size_params.nic_residue);
	} else if (ms_desc->axes.rank_axis == COLL_DESC_X_AXIS) {
		ms_desc->stride_offset_1 = ms_desc->stride_size;
		ms_desc->stride_offset_2 = ms_desc->stride_offset_1 * ms_desc->number_of_strides_1;
		ms_desc->stride_between_ranks = ms_desc->number_of_strides_1 / n_ranks;
		ms_desc->oper.rank_residue_sz = bitfield_safe(
			ms_desc->number_of_strides_1 - ms_desc->stride_between_ranks *
			n_ranks, 12);
		ms_desc->nic.nic_size =
				bitfield_safe(ms_desc->stride_size / group->nodes_per_rank, 24);
		ms_desc->nic.nic_residue = u8_safe(ms_desc->stride_size % group->nodes_per_rank);
	} else {
		ms_desc->stride_offset_1 = ms_desc->stride_size;
		ms_desc->stride_offset_2 = ms_desc->stride_offset_1 * ms_desc->number_of_strides_1;
		ms_desc->stride_between_ranks = ms_desc->number_of_strides_2 / n_ranks;
		ms_desc->oper.rank_residue_sz =
				bitfield_safe(ms_desc->number_of_strides_2 -
					      ms_desc->stride_between_ranks * n_ranks, 12);
		ms_desc->nic.nic_size =
				bitfield_safe(ms_desc->stride_size / group->nodes_per_rank, 24);
		ms_desc->nic.nic_residue = u8_safe(ms_desc->stride_size % group->nodes_per_rank);
	}

	return 0;
}

static int gaudi3_nic_coll_group_fill_multi_stride_desc(bool send,
						const struct hltests_nic_coll_comm_group *group,
						const struct hltests_nic_wqe_params *wqe_params,
						struct coll_desc_ms_send_receive *ms_desc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;
	uint32_t stride_mul;

	ms_desc->axes.pipeline_axis = COLL_DESC_Z_AXIS;
	ms_desc->axes.rank_axis = bitfield_safe(group->in_params->axis_rank, 2);

	ms_desc->ctrl.update_bitmask = 0xfff;
	ms_desc->ctrl.lane_select = 0x5;
	ms_desc->ctrl.cmd = COLL_CMD_DESCRIPTOR_MS_SND_RCV;
	ms_desc->ctrl.context_id = u8_safe(group->id);

	ms_desc->number_of_strides_1 = 8;
	ms_desc->number_of_strides_2 = 16;

	stride_mul = ms_desc->number_of_strides_1 * ms_desc->number_of_strides_2;
	gaudi3_nic_coll_group_get_size_params(group, wqe_params, stride_mul, &size_params);

	ms_desc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
	ms_desc->nic.nic_residue = u8_safe(size_params.nic_residue);
	ms_desc->stride_between_ranks = size_params.stride_between_ranks;

	opcode = send ? WQE_MULTI_STRIDE_DUAL : WQE_RENDEZVOUS_WRITE;
	gaudi3_nic_coll_group_fill_oper(wqe_params, opcode, u8_safe(size_params.rank_residue),
						&ms_desc->oper, send, group->in_params->coll_dt);

	if (send)
		ms_desc->local_base_addr = wqe_params->local_address;
	else
		/* Sent by the receive side, meaning the local_base_addr field is the remote address
		 * for the sender.
		 */
		ms_desc->local_base_addr = wqe_params->remote_address;

	ms_desc->local_tag = int_to_uint_safe(wqe_params->tag);

	gaudi3_nic_coll_group_fill_comp(wqe_params, send, &ms_desc->comp);

	ms_desc->stride_size = u32_safe(wqe_params->size / stride_mul);

	if (ms_desc->axes.rank_axis == COLL_DESC_Z_AXIS) {
		ms_desc->stride_offset_1 = size_params.rank_size * group->n_ranks +
						size_params.rank_residue;
		ms_desc->stride_offset_2 = ms_desc->stride_offset_1 * ms_desc->number_of_strides_1;
		ms_desc->stride_between_ranks = size_params.stride_between_ranks;
		ms_desc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
		ms_desc->nic.nic_residue = u8_safe(size_params.nic_residue);
	} else if (ms_desc->axes.rank_axis == COLL_DESC_X_AXIS) {
		ms_desc->stride_offset_1 = ms_desc->stride_size;
		ms_desc->stride_offset_2 = ms_desc->stride_offset_1 * ms_desc->number_of_strides_1;
		ms_desc->stride_between_ranks = ms_desc->number_of_strides_1 / group->n_ranks;
		ms_desc->oper.rank_residue_sz = u8_safe(ms_desc->number_of_strides_1
						- ms_desc->stride_between_ranks * group->n_ranks);
		ms_desc->nic.nic_size =
				bitfield_safe(ms_desc->stride_size / group->nodes_per_rank, 24);
		ms_desc->nic.nic_residue = u8_safe(ms_desc->stride_size % group->nodes_per_rank);
	} else {
		ms_desc->stride_offset_1 = ms_desc->stride_size;
		ms_desc->stride_offset_2 = ms_desc->stride_offset_1 * ms_desc->number_of_strides_1;
		ms_desc->stride_between_ranks = ms_desc->number_of_strides_2 / group->n_ranks;
		ms_desc->oper.rank_residue_sz =
				u8_safe(ms_desc->number_of_strides_2 -
					ms_desc->stride_between_ranks * group->n_ranks);
		ms_desc->nic.nic_size =
				bitfield_safe(ms_desc->stride_size / group->nodes_per_rank, 24);
		ms_desc->nic.nic_residue = u8_safe(ms_desc->stride_size % group->nodes_per_rank);
	}

	return 0;
}

static int gaudi3_nic_coll_group_fill_multi_stride_desc_new(
	bool send, const struct hltests_nic_coll_comm_group_new *group,
	const struct hltests_nic_wqe_params *wqe_params, struct coll_desc_ms_send_receive *ms_desc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;
	uint32_t stride_mul;

	ms_desc->axes.pipeline_axis = COLL_DESC_Z_AXIS;
	ms_desc->axes.rank_axis = bitfield_safe(group->params->cfg->coll_rank_axis, 2);

	ms_desc->ctrl.update_bitmask = 0xfff;
	ms_desc->ctrl.lane_select = 0x5;
	ms_desc->ctrl.cmd = COLL_CMD_DESCRIPTOR_MS_SND_RCV;
	ms_desc->ctrl.context_id = u8_safe(group->id);

	ms_desc->number_of_strides_1 = 8;
	ms_desc->number_of_strides_2 = 16;

	stride_mul = ms_desc->number_of_strides_1 * ms_desc->number_of_strides_2;
	gaudi3_nic_coll_group_get_size_params_new(group, wqe_params, stride_mul, &size_params);

	ms_desc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
	ms_desc->nic.nic_residue = u8_safe(size_params.nic_residue);
	ms_desc->stride_between_ranks = size_params.stride_between_ranks;

	opcode = send ? WQE_MULTI_STRIDE_DUAL : WQE_RENDEZVOUS_WRITE;
	gaudi3_nic_coll_group_fill_oper(wqe_params, opcode, u8_safe(size_params.rank_residue),
					&ms_desc->oper, send, group->params->cfg->coll_data_type);

	if (send)
		ms_desc->local_base_addr = wqe_params->local_address;
	else
		/* Sent by the receive side, meaning the local_base_addr field is the remote address
		 * for the sender.
		 */
		ms_desc->local_base_addr = wqe_params->remote_address;

	ms_desc->local_tag = int_to_uint_safe(wqe_params->tag);

	gaudi3_nic_coll_group_fill_comp(wqe_params, send, &ms_desc->comp);

	ms_desc->stride_size = u32_safe(wqe_params->size / stride_mul);

	if (ms_desc->axes.rank_axis == COLL_DESC_Z_AXIS) {
		ms_desc->stride_offset_1 =
			size_params.rank_size * group->n_ranks + size_params.rank_residue;
		ms_desc->stride_offset_2 = ms_desc->stride_offset_1 * ms_desc->number_of_strides_1;
		ms_desc->stride_between_ranks = size_params.stride_between_ranks;
		ms_desc->nic.nic_size = bitfield_safe(size_params.nic_size, 24);
		ms_desc->nic.nic_residue = u8_safe(size_params.nic_residue);
	} else if (ms_desc->axes.rank_axis == COLL_DESC_X_AXIS) {
		ms_desc->stride_offset_1 = ms_desc->stride_size;
		ms_desc->stride_offset_2 = ms_desc->stride_offset_1 * ms_desc->number_of_strides_1;
		ms_desc->stride_between_ranks = ms_desc->number_of_strides_1 / group->n_ranks;
		ms_desc->oper.rank_residue_sz = u8_safe(ms_desc->number_of_strides_1 -
						ms_desc->stride_between_ranks * group->n_ranks);
		ms_desc->nic.nic_size =
				bitfield_safe(ms_desc->stride_size / group->nodes_per_rank, 24);
		ms_desc->nic.nic_residue = u8_safe(ms_desc->stride_size % group->nodes_per_rank);
	} else {
		ms_desc->stride_offset_1 = ms_desc->stride_size;
		ms_desc->stride_offset_2 = ms_desc->stride_offset_1 * ms_desc->number_of_strides_1;
		ms_desc->stride_between_ranks = ms_desc->number_of_strides_2 / group->n_ranks;
		ms_desc->oper.rank_residue_sz = u8_safe(ms_desc->number_of_strides_2 -
						ms_desc->stride_between_ranks * group->n_ranks);
		ms_desc->nic.nic_size =
				bitfield_safe(ms_desc->stride_size / group->nodes_per_rank, 24);
		ms_desc->nic.nic_residue = u8_safe(ms_desc->stride_size % group->nodes_per_rank);
	}

	return 0;
}

static int gaudi3_nic_direct_coll_group_fill_v_operation_desc(
						const struct hltests_nic_coll_comm_group *group,
						const struct hltests_nic_wqe_params *wqe_params,
						struct direct_coll_desc_v_operation_send_receive
											 *v_desc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;
	uint32_t i, port, port_idx_in_group = 0;
	bool is_200_gbps;

	is_200_gbps = NIC_IS_200_GBPS_MODE(group->tests_state->fd, group->nodes_mask);

	v_desc->ctrl.cmd = COLL_CMD_DESCRIPTOR_0_VOP_SR;
	v_desc->ctrl.qp = bitfield_safe(get_collective_qp_id(group), 24);

	opcode = WQE_LINEAR;

	gaudi3_nic_direct_coll_group_fill_oper(wqe_params, opcode, 0, true, &v_desc->oper);

	v_desc->local_base_addr = wqe_params->local_address;

	gaudi3_nic_direct_coll_group_fill_misc_params(true, &v_desc->misc, group);
	v_desc->misc.disregard_rank = 1;

	gaudi3_nic_coll_group_fill_comp(wqe_params, true, &v_desc->local_comp);

	gaudi3_nic_coll_group_get_size_params(group, wqe_params, 1, &size_params);

	for (i = 0 ; i < COLL_DESC_ENT_NICS_PER_ENTRY ; i++) {
		/* Local address per group is calculated as follows:
		 * local_addr = local_base_addr + v_desc->groups[i - 1].end_addr
		 * for i = 0, v_desc->groups[i - 1].end_addr = 0
		 *
		 * The HW creates send\recv contexts from the Vop operations by associating the
		 * group id with the "enabled bit per port" field. Meaning on 400G, groups
		 * "0 + i * 2" will be taken. Whereas on 200G, all enabled ports will be taken.
		 *
		 * In order to satisfy the formulas above and send all ports with the same local
		 * address set 'v_desc->groups[i].end_addr = 0'. This way the calculation
		 * would be:
		 * local_addr = local_base_addr + 0
		 *
		 * Note that stride_between_ranks is irelevant for V-op, as only 1 rank is always
		 * used.
		 */

		/* Translate physical to logical port */
		port = i >> (1 - is_200_gbps);
		if ((BIT_ULL(i) & v_desc->misc.ports_en))
			port_idx_in_group++;

		v_desc->groups[i].end_addr = size_params.nic_size * (port_idx_in_group);
		if (!(BIT_ULL(i) & v_desc->misc.ports_en))
			continue;

		v_desc->groups[i].nic.nic_size = bitfield_safe(size_params.nic_size, 24);
		v_desc->groups[i].nic.nic_residue = 0;
		v_desc->rank_res[i] = 0;

		/* nic residue should be added to last port. Increase end_addr with nic
		 * residue as well, as stride between ranks needs to be at least as big as
		 * nic_size.
		 */
		if (port == (LBS(group->nodes_mask) - 1)) {
			v_desc->groups[i].end_addr += size_params.nic_residue;
			v_desc->groups[i].nic.nic_size +=
						bitfield_safe(size_params.nic_residue, 24);
		}
	}

	return 0;
}

static int gaudi3_nic_direct_coll_group_fill_v_operation_desc_new(
	const struct hltests_nic_coll_comm_group_new *group,
	const struct hltests_nic_wqe_params *wqe_params,
	struct direct_coll_desc_v_operation_send_receive *v_desc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;
	uint32_t i, port, port_idx_in_group = 0;
	bool is_200_gbps;

	is_200_gbps = NIC_IS_200_GBPS_MODE(group->tests_state->fd, group->nodes_mask);

	v_desc->ctrl.cmd = COLL_CMD_DESCRIPTOR_0_VOP_SR;
	v_desc->ctrl.qp = bitfield_safe(get_collective_qp_id_new(group), 24);

	opcode = WQE_LINEAR;

	gaudi3_nic_direct_coll_group_fill_oper(wqe_params, opcode, 0, true, &v_desc->oper);

	v_desc->local_base_addr = wqe_params->local_address;

	gaudi3_nic_direct_coll_group_fill_misc_params_new(true, &v_desc->misc, group);
	v_desc->misc.disregard_rank = 1;

	gaudi3_nic_coll_group_fill_comp(wqe_params, true, &v_desc->local_comp);

	gaudi3_nic_coll_group_get_size_params_new(group, wqe_params, 1, &size_params);

	for (i = 0; i < COLL_DESC_ENT_NICS_PER_ENTRY; i++) {
		/* Local address per group is calculated as follows:
		 * local_addr = local_base_addr + v_desc->groups[i - 1].end_addr
		 * for i = 0, v_desc->groups[i - 1].end_addr = 0
		 *
		 * The HW creates send\recv contexts from the Vop operations by associating the
		 * group id with the "enabled bit per port" field. Meaning on 400G, groups
		 * "0 + i * 2" will be taken. Whereas on 200G, all enabled ports will be taken.
		 *
		 * In order to satisfy the formulas above and send all ports with the same local
		 * address set 'v_desc->groups[i].end_addr = 0'. This way the calculation
		 * would be:
		 * local_addr = local_base_addr + 0
		 *
		 * Note that stride_between_ranks is irelevant for V-op, as only 1 rank is always
		 * used.
		 */

		/* Translate physical to logical port */
		port = i >> (1 - is_200_gbps);
		if ((BIT_ULL(i) & v_desc->misc.ports_en))
			port_idx_in_group++;

		v_desc->groups[i].end_addr = size_params.nic_size * (port_idx_in_group);
		if (!(BIT_ULL(i) & v_desc->misc.ports_en))
			continue;

		v_desc->groups[i].nic.nic_size = bitfield_safe(size_params.nic_size, 24);
		v_desc->groups[i].nic.nic_residue = 0;
		v_desc->rank_res[i] = 0;

		/* nic residue should be added to last port. Increase end_addr with nic
		 * residue as well, as stride between ranks needs to be at least as big as
		 * nic_size.
		 */
		if (port == (LBS(group->nodes_mask) - 1)) {
			v_desc->groups[i].end_addr += size_params.nic_residue;
			v_desc->groups[i].nic.nic_size +=
						bitfield_safe(size_params.nic_residue, 24);
		}
	}

	return 0;
}

static int gaudi3_nic_coll_group_fill_v_operation_desc(bool last_group_part,
						const struct hltests_nic_coll_comm_group *group,
						const struct hltests_nic_wqe_params *wqe_params,
						struct coll_desc_v_operation_send_receive *v_desc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;
	uint32_t i, relative_port, port, num_lanes_per_port;
	bool is_200_gbps;

	assert_non_null(group);
	assert_non_null(group->in_params);
	assert_non_null(wqe_params);
	assert_non_null(v_desc);
	assert_true(group->in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE);

	is_200_gbps = NIC_IS_200_GBPS_MODE(group->tests_state->fd, group->nodes_mask);
	num_lanes_per_port = is_200_gbps ? 2 : 4;

	v_desc->ctrl.lane_select = 0x5;
	v_desc->ctrl.cmd = last_group_part ? COLL_CMD_DESCRIPTOR_1_VOP_SR :
						COLL_CMD_DESCRIPTOR_0_VOP_SR;
	v_desc->ctrl.context_id = u8_safe(group->id);

	opcode = WQE_LINEAR;
	gaudi3_nic_coll_group_fill_oper(wqe_params, opcode, 0, &v_desc->oper, true,
					group->in_params->coll_dt);

	gaudi3_nic_coll_group_get_size_params(group, wqe_params, 1, &size_params);

	/*
	 * Upper half's local base address starts from the end offset of the last group in the
	 * lower half.
	 */
	v_desc->local_base_addr = wqe_params->local_address + (uint32_t)
					((COLL_DESC_ENT_NICS_PER_ENTRY * last_group_part) >>
						(2 - is_200_gbps)) * size_params.nic_size;
	v_desc->local_tag = int_to_uint_safe(wqe_params->tag);

	gaudi3_nic_coll_group_fill_comp(wqe_params, true, &v_desc->comp);

	for (i = 0 ; i < COLL_DESC_ENT_NICS_PER_ENTRY ; i++) {
		/* Local address per group and stride between ranks are calculated as follows:
		 * local_addr = local_base_addr + v_desc->groups[i - 1].end_addr
		 * for i = 0, v_desc->groups[i - 1].end_addr = 0
		 *
		 * The HW creates send\recv contexts from the Vop operations by associating the
		 * group id with a physical port. Meaning on 400G, groups 0 + i * 4 will be taken.
		 * Whereas on 200G, groups 0 + i * 2 will be taken.
		 *
		 * In order to satisfy the formulas above and send all port with the same local
		 * address set 'v_desc->groups[i].end_addr = 0' to odd i's. This way the calculation
		 * would be:
		 * local_addr = local_base_addr + 0
		 *
		 * Note that stride_between_ranks is irelevant for V-op, as only 1 rank is always
		 * used.
		 */

		/* Translate physical to logical port. Relative port is the port relative to the
		 * beginning of the V-op half.
		 */
		relative_port = (uint32_t)i >> (2 - is_200_gbps);
		port = ((i + COLL_DESC_ENT_NICS_PER_ENTRY * last_group_part) >> (2 - is_200_gbps));

		v_desc->groups[i].end_addr = size_params.nic_size * (relative_port + 1);

		if ((BIT_ULL(port) & group->nodes_mask) && ((i % num_lanes_per_port) == 0)) {
			v_desc->groups[i].nic.nic_size = bitfield_safe(size_params.nic_size, 24);
			v_desc->groups[i].nic.nic_residue = 0;
			v_desc->rank_res[i] = 0;

			/* nic residue should be added to last port. Increase end_addr with nic
			 * residue as well, as stride between ranks needs to be at least as big as
			 * nic_size.
			 */
			if (port == (LBS(group->nodes_mask) - 1)) {
				v_desc->groups[i].end_addr += size_params.nic_residue;
				v_desc->groups[i].nic.nic_size +=
						bitfield_safe(size_params.nic_residue, 24);
			}
		}
	}

	return 0;
}

static int
gaudi3_nic_coll_group_fill_v_operation_desc_new(bool last_group_part,
						const struct hltests_nic_coll_comm_group_new *group,
						const struct hltests_nic_wqe_params *wqe_params,
						struct coll_desc_v_operation_send_receive *v_desc)
{
	struct coll_size_params size_params = {};
	enum wqe_opcode opcode;
	uint32_t i, relative_port, port, num_lanes_per_port;
	bool is_200_gbps;

	assert_non_null(group);
	assert_non_null(group->params);
	assert_non_null(wqe_params);
	assert_non_null(v_desc);
	assert_true(group->params->cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE);

	is_200_gbps = NIC_IS_200_GBPS_MODE(group->tests_state->fd, group->nodes_mask);
	num_lanes_per_port = is_200_gbps ? 2 : 4;

	v_desc->ctrl.lane_select = 0x5;
	v_desc->ctrl.cmd = last_group_part ? COLL_CMD_DESCRIPTOR_1_VOP_SR :
					     COLL_CMD_DESCRIPTOR_0_VOP_SR;
	v_desc->ctrl.context_id = u8_safe(group->id);

	opcode = WQE_LINEAR;
	gaudi3_nic_coll_group_fill_oper(wqe_params, opcode, 0, &v_desc->oper, true,
					group->params->cfg->coll_data_type);

	gaudi3_nic_coll_group_get_size_params_new(group, wqe_params, 1, &size_params);

	/* Upper half's local base address starts from the end offset of the last group in the lower
	 * half.
	 */
	v_desc->local_base_addr =
		wqe_params->local_address + (uint32_t)
		((COLL_DESC_ENT_NICS_PER_ENTRY * last_group_part) >> (2 - is_200_gbps)) *
			size_params.nic_size;
	v_desc->local_tag = int_to_uint_safe(wqe_params->tag);

	gaudi3_nic_coll_group_fill_comp(wqe_params, true, &v_desc->comp);

	for (i = 0; i < COLL_DESC_ENT_NICS_PER_ENTRY; i++) {
		/* Local address per group and stride between ranks are calculated as follows:
		 * local_addr = local_base_addr + v_desc->groups[i - 1].end_addr
		 * for i = 0, v_desc->groups[i - 1].end_addr = 0
		 *
		 * The HW creates send\recv contexts from the Vop operations by associating the
		 * group id with a physical port. Meaning on 400G, groups 0 + i * 4 will be taken.
		 * Whereas on 200G, groups 0 + i * 2 will be taken.
		 *
		 * In order to satisfy the formulas above and send all port with the same local
		 * address set 'v_desc->groups[i].end_addr = 0' to odd i's. This way the calculation
		 * would be:
		 * local_addr = local_base_addr + 0
		 *
		 * Note that stride_between_ranks is irelevant for V-op, as only 1 rank is always
		 * used.
		 */

		/* Translate physical to logical port. Relative port is the port relative to the
		 * beginning of the V-op half.
		 */
		relative_port = (uint32_t)i >> (2 - is_200_gbps);
		port = ((i + COLL_DESC_ENT_NICS_PER_ENTRY * last_group_part) >> (2 - is_200_gbps));

		v_desc->groups[i].end_addr = size_params.nic_size * (relative_port + 1);

		if ((BIT_ULL(port) & group->nodes_mask) && ((i % num_lanes_per_port) == 0)) {
			v_desc->groups[i].nic.nic_size = bitfield_safe(size_params.nic_size, 24);
			v_desc->groups[i].nic.nic_residue = 0;
			v_desc->rank_res[i] = 0;

			/* nic residue should be added to last port. Increase end_addr with nic
			 * residue as well, as stride between ranks needs to be at least as big as
			 * nic_size.
			 */
			if (port == (LBS(group->nodes_mask) - 1)) {
				v_desc->groups[i].end_addr += size_params.nic_residue;
				v_desc->groups[i].nic.nic_size +=
							bitfield_safe(size_params.nic_residue, 24);
			}
		}
	}

	return 0;
}

static int gaudi3_nic_coll_group_fill_coll_desc(const struct hltests_nic_coll_comm_group *group,
						enum gaudi3_coll_cmd coll_cmd, uint32_t qp_idx,
						const struct hltests_nic_wqe_params *wqe_params,
						struct coll_desc *desc)
{
	bool send, is_direct_mode;
	int rc;

	is_direct_mode = group->in_params->coll_type == COLL_TYPE_DIRECT;

	/* In RDV testing, QPs are divided as follows: Odd QP - send side, even QP - receive side */
	send = qp_idx & 1;

	switch (coll_cmd) {
	case COLL_CMD_DESCRIPTOR_WRITE:
		if (is_direct_mode)
			rc = gaudi3_nic_direct_coll_group_fill_write_desc(group, wqe_params,
									 &desc->direct_write);
		else
			rc = gaudi3_nic_coll_group_fill_write_desc(group, wqe_params, &desc->write);
		break;
	case COLL_CMD_DESCRIPTOR_SND_RCV:
		if (is_direct_mode)
			rc = gaudi3_nic_direct_coll_group_fill_send_recv_desc(send, group,
									wqe_params,
									&desc->direct_sr);
		else
			rc = gaudi3_nic_coll_group_fill_send_recv_desc(send, group, wqe_params,
					&desc->send_receive);
		break;
	case COLL_CMD_DESCRIPTOR_MS_SND_RCV:
		if (is_direct_mode)
			rc = gaudi3_nic_direct_coll_group_fill_multi_stride_desc(send, group,
									wqe_params,
								&desc->direct_ms_send_receive);
		else
			rc = gaudi3_nic_coll_group_fill_multi_stride_desc(send, group, wqe_params,
									&desc->ms_send_receive);
		break;
	case COLL_CMD_DESCRIPTOR_0_VOP_SR:
		if (is_direct_mode)
			if (send)
				rc = gaudi3_nic_direct_coll_group_fill_v_operation_desc(group,
									wqe_params,
									&desc->direct_v_op);
			else
				rc = gaudi3_nic_direct_coll_group_fill_send_recv_desc(send, group,
									wqe_params,
									&desc->direct_sr);
		else
			if (send)
				rc = gaudi3_nic_coll_group_fill_v_operation_desc(false, group,
										wqe_params,
										&desc->v_operation);
			else
				rc = gaudi3_nic_coll_group_fill_send_recv_desc(send, group,
									wqe_params,
									&desc->send_receive);
		break;
	case COLL_CMD_DESCRIPTOR_1_VOP_SR:
		if (send)
			rc = gaudi3_nic_coll_group_fill_v_operation_desc(true, group,
									wqe_params,
									&desc->v_operation);
		else
			rc = gaudi3_nic_coll_group_fill_send_recv_desc(send, group,
								wqe_params,
								&desc->send_receive);
		break;
	default:
		printf("Unsupported coll_cmd to fill: %d\n", coll_cmd);
		rc = -EINVAL;
		break;
	}

	return rc;
}

static int gaudi3_nic_coll_group_fill_coll_desc_new(
	const struct hltests_nic_coll_comm_group_new *group, enum gaudi3_coll_cmd coll_cmd,
	uint32_t qp_idx, const struct hltests_nic_wqe_params *wqe_params, struct coll_desc *desc)
{
	bool send, is_direct_mode;
	int rc;

	is_direct_mode = group->params->cfg->coll_type == COLL_TYPE_DIRECT;

	/* In RDV testing, QPs are divided as follows: Odd QP - send side, even QP - receive side */
	send = qp_idx & 1;

	switch (coll_cmd) {
	case COLL_CMD_DESCRIPTOR_WRITE:
		if (is_direct_mode)
			rc = gaudi3_nic_direct_coll_group_fill_write_desc_new(group, wqe_params,
									      &desc->direct_write);
		else
			rc = gaudi3_nic_coll_group_fill_write_desc_new(group, wqe_params,
								       &desc->write);
		break;
	case COLL_CMD_DESCRIPTOR_SND_RCV:
		if (is_direct_mode)
			rc = gaudi3_nic_direct_coll_group_fill_send_recv_desc_new(
				send, group, wqe_params, &desc->direct_sr);
		else
			rc = gaudi3_nic_coll_group_fill_send_recv_desc_new(send, group, wqe_params,
									   &desc->send_receive);
		break;
	case COLL_CMD_DESCRIPTOR_MS_SND_RCV:
		if (is_direct_mode)
			rc = gaudi3_nic_direct_coll_group_fill_multi_stride_desc_new(
				send, group, wqe_params, &desc->direct_ms_send_receive);
		else
			rc = gaudi3_nic_coll_group_fill_multi_stride_desc_new(
				send, group, wqe_params, &desc->ms_send_receive);
		break;
	case COLL_CMD_DESCRIPTOR_0_VOP_SR:
		if (is_direct_mode)
			if (send)
				rc = gaudi3_nic_direct_coll_group_fill_v_operation_desc_new(
					group, wqe_params, &desc->direct_v_op);
			else
				rc = gaudi3_nic_direct_coll_group_fill_send_recv_desc_new(
					send, group, wqe_params, &desc->direct_sr);
		else if (send)
			rc = gaudi3_nic_coll_group_fill_v_operation_desc_new(
				false, group, wqe_params, &desc->v_operation);
		else
			rc = gaudi3_nic_coll_group_fill_send_recv_desc_new(send, group, wqe_params,
									   &desc->send_receive);
		break;
	case COLL_CMD_DESCRIPTOR_1_VOP_SR:
		if (send)
			rc = gaudi3_nic_coll_group_fill_v_operation_desc_new(
				true, group, wqe_params, &desc->v_operation);
		else
			rc = gaudi3_nic_coll_group_fill_send_recv_desc_new(send, group, wqe_params,
									   &desc->send_receive);
		break;
	default:
		printf("Unsupported coll_cmd to fill: %d\n", coll_cmd);
		rc = -EINVAL;
		break;
	}

	return rc;
}

static int gaudi3_nic_coll_op_format_msg_coll_desc(const struct coll_desc *coll_desc_params,
						   uint32_t desc_size,
						   struct hltests_nic_db_fifo_packet *msg)
{
	assert_non_null(coll_desc_params);
	assert_non_null(msg);

	msg->size = desc_size;
	memcpy(msg->packet, coll_desc_params, msg->size);

	return 0;
}

static int gaudi3_nic_direct_coll_op_format_msg_update_dest_rank(
						const struct hltests_nic_coll_comm_group *group,
						struct hltests_nic_db_fifo_packet *msg)
{
	struct direct_coll_desc_update_dest_rank drank = {};
	uint32_t port, max_n_ports, macro;
	bool is_200_gbps;
	int fd;

	assert_non_null(group);
	assert_non_null(msg);

	max_n_ports = gaudi3_nic_get_max_num_of_ports();
	fd = group->tests_state->fd;
	is_200_gbps = NIC_IS_200_GBPS_MODE(fd, group->nodes_mask);

	drank.ctrl.cmd = COLL_CMD_DEST_RANK_UPDATE;
	drank.ctrl.qp = bitfield_safe(get_collective_qp_id(group), 24);

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		macro = port >> (is_200_gbps ? 1 : 0);

		if (is_200_gbps && (port % 2))
			drank.nics[macro].nic_lane_2 = u16_safe(group->nodes[port].rank);
		else
			drank.nics[macro].nic_lane_0 = u16_safe(group->nodes[port].rank);

		/* H/W bug W/A for 400G mode:
		 * when the NIC H/W gets descriptors for dest/last rank update, it always updates
		 * both entries in the table (for both logical ports) even though the seconds
		 * logical port is not always functional.
		 * Therefore, in 400G mode, we need to set also the second logical ports with the
		 * correct dest rank.
		 * In 200G mode, we don't have this issue because the odd ports are active and
		 * should be set fine.
		 */
		if (!is_200_gbps)
			drank.nics[macro].nic_lane_2 = u16_safe(group->nodes[port].rank);
	}

	msg->size = sizeof(drank);
	memcpy(msg->packet, &drank, msg->size);

	return 0;
}

static int gaudi3_nic_direct_coll_op_format_msg_update_dest_rank_new(
	const struct hltests_nic_coll_comm_group_new *group, struct hltests_nic_db_fifo_packet *msg)
{
	struct direct_coll_desc_update_dest_rank drank = {};
	uint32_t port, max_n_ports, macro;
	bool is_200_gbps;
	int fd;

	assert_non_null(group);
	assert_non_null(msg);

	max_n_ports = gaudi3_nic_get_max_num_of_ports();
	fd = group->tests_state->fd;
	is_200_gbps = NIC_IS_200_GBPS_MODE(fd, group->nodes_mask);

	drank.ctrl.cmd = COLL_CMD_DEST_RANK_UPDATE;
	drank.ctrl.qp = bitfield_safe(get_collective_qp_id_new(group), 24);

	for (port = 0; port < max_n_ports; port++) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		macro = port >> (is_200_gbps ? 1 : 0);

		if (is_200_gbps && (port % 2))
			drank.nics[macro].nic_lane_2 = u16_safe(group->nodes[port].rank);
		else
			drank.nics[macro].nic_lane_0 = u16_safe(group->nodes[port].rank);

		/* H/W bug W/A for 400G mode:
		 * when the NIC H/W gets descriptors for dest/last rank update, it always updates
		 * both entries in the table (for both logical ports) even though the seconds
		 * logical port is not always functional.
		 * Therefore, in 400G mode, we need to set also the second logical ports with the
		 * correct dest rank.
		 * In 200G mode, we don't have this issue because the odd ports are active and
		 * should be set fine.
		 */
		if (!is_200_gbps)
			drank.nics[macro].nic_lane_2 = u16_safe(group->nodes[port].rank);
	}

	msg->size = sizeof(drank);
	memcpy(msg->packet, &drank, msg->size);

	return 0;
}

static int gaudi3_nic_coll_op_format_msg_update_dest_rank(
						const struct hltests_nic_coll_comm_group *group,
						struct hltests_nic_db_fifo_packet *msg)
{
	struct coll_desc_update_dest_rank drank = {};
	uint32_t port, entry = 0, max_n_ports, macro;
	bool is_200_gbps;
	int fd;

	assert_non_null(group);
	assert_non_null(msg);

	max_n_ports = gaudi3_nic_get_max_num_of_ports();
	fd = group->tests_state->fd;
	is_200_gbps = NIC_IS_200_GBPS_MODE(fd, group->nodes_mask);

	drank.ctrl.cmd = COLL_CMD_DEST_RANK_UPDATE;
	drank.ctrl.context_id = u8_safe(group->id);
	drank.ctrl.lane_select = 0x5;

	entry = 12;
	drank.ctrl.update_bitmask = 0xfff;
	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		/* In 200Gbps mode, we have 2 ports per macro. */
		macro = port >> (is_200_gbps ? 1 : 0);

		/* In 200Gbps mode, all odd ports are lane 2 of corresponding macro. */
		if (is_200_gbps && (port % 2))
			drank.nics[macro].nic_lane_2 = u8_safe(group->nodes[port].rank);
		else
			drank.nics[macro].nic_lane_0 = u8_safe(group->nodes[port].rank);
	}

	/* The actual message len depends on the amount of entries added */
	msg->size = (uint32_t)(sizeof(drank.ctrl) + entry * sizeof(drank.nics[0]));
	memcpy(msg->packet, &drank, msg->size);

	return 0;
}

static int gaudi3_nic_coll_op_format_msg_update_dest_rank_new(
	const struct hltests_nic_coll_comm_group_new *group, struct hltests_nic_db_fifo_packet *msg)
{
	struct coll_desc_update_dest_rank drank = {};
	uint32_t port, entry = 0, max_n_ports, macro;
	bool is_200_gbps;
	int fd;

	assert_non_null(group);
	assert_non_null(msg);

	max_n_ports = gaudi3_nic_get_max_num_of_ports();
	fd = group->tests_state->fd;
	is_200_gbps = NIC_IS_200_GBPS_MODE(fd, group->nodes_mask);

	drank.ctrl.cmd = COLL_CMD_DEST_RANK_UPDATE;
	drank.ctrl.context_id = u8_safe(group->id);
	drank.ctrl.lane_select = 0x5;

	entry = 12;
	drank.ctrl.update_bitmask = 0xfff;
	for (port = 0; port < max_n_ports; port++) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		/* In 200Gbps mode, we have 2 ports per macro. */
		macro = port >> (is_200_gbps ? 1 : 0);

		/* In 200Gbps mode, all odd ports are lane 2 of corresponding macro. */
		if (is_200_gbps && (port % 2))
			drank.nics[macro].nic_lane_2 = u8_safe(group->nodes[port].rank);
		else
			drank.nics[macro].nic_lane_0 = u8_safe(group->nodes[port].rank);
	}

	/* The actual message len depends on the amount of entries added */
	msg->size = (uint32_t)(sizeof(drank.ctrl) + entry * sizeof(drank.nics[0]));
	memcpy(msg->packet, &drank, msg->size);

	return 0;
}

static int gaudi3_nic_direct_coll_op_format_msg_update_last_rank(
						const struct hltests_nic_coll_comm_group *group,
						struct hltests_nic_db_fifo_packet *msg)
{
	struct direct_coll_desc_update_last_rank lrank = {};
	uint32_t port, max_n_ports, macro, lane_offset;
	bool is_200_gbps;
	int fd;

	assert_non_null(group);
	assert_non_null(msg);

	max_n_ports = gaudi3_nic_get_max_num_of_ports();
	fd = group->tests_state->fd;
	is_200_gbps = NIC_IS_200_GBPS_MODE(fd, group->nodes_mask);

	lrank.ctrl.cmd = COLL_CMD_LAST_RANK_UPDATE;
	lrank.ctrl.qp = bitfield_safe(get_collective_qp_id(group), 24);

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		macro = port >> (is_200_gbps ? 1 : 0);
		lane_offset = is_200_gbps ? port % 2 : 0;

		/* In direct patcher, we support only 400Gbps and 200Gbps mode, hence only 2 bits
		 * are needed for each port, so multiply the macro by 2
		 */
		if (group->nodes[port].is_last_rank) {
			lrank.p_0_23.ports |= bitfield_safe(BIT(macro * 2 + lane_offset), 24);

			/* H/W bug W/A for 400G mode:
			 * when the NIC H/W gets descriptors for dest/last rank update, it always
			 * updates both entries in the table (for both logical ports) even though
			 * the seconds logical port is not always functional.
			 * Therefore, in 400G mode, we need to set the correct last rank indication
			 * for the odd ports as well.
			 * In 200G mode, we don't have this issue because the odd ports are active
			 * and should be set fine.
			 */
			if (!is_200_gbps)
				lrank.p_0_23.ports |= bitfield_safe(BIT(macro * 2 + 1), 24);
		}
	}

	msg->size = sizeof(lrank);
	memcpy(msg->packet, &lrank, msg->size);

	return 0;
}

static int gaudi3_nic_direct_coll_op_format_msg_update_last_rank_new(
	const struct hltests_nic_coll_comm_group_new *group, struct hltests_nic_db_fifo_packet *msg)
{
	struct direct_coll_desc_update_last_rank lrank = {};
	uint32_t port, max_n_ports, macro, lane_offset;
	bool is_200_gbps;
	int fd;

	assert_non_null(group);
	assert_non_null(msg);

	max_n_ports = gaudi3_nic_get_max_num_of_ports();
	fd = group->tests_state->fd;
	is_200_gbps = NIC_IS_200_GBPS_MODE(fd, group->nodes_mask);

	lrank.ctrl.cmd = COLL_CMD_LAST_RANK_UPDATE;
	lrank.ctrl.qp = bitfield_safe(get_collective_qp_id_new(group), 24);

	for (port = 0; port < max_n_ports; port++) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		macro = port >> (is_200_gbps ? 1 : 0);
		lane_offset = is_200_gbps ? port % 2 : 0;

		/* In direct patcher, we support only 400Gbps and 200Gbps mode, hence only 2 bits
		 * are needed for each port, so multiply the macro by 2
		 */
		if (group->nodes[port].is_last_rank) {
			lrank.p_0_23.ports |= bitfield_safe(BIT(macro * 2 + lane_offset), 24);

			/* H/W bug W/A for 400G mode:
			 * when the NIC H/W gets descriptors for dest/last rank update, it always
			 * updates both entries in the table (for both logical ports) even though
			 * the seconds logical port is not always functional.
			 * Therefore, in 400G mode, we need to set the correct last rank indication
			 * for the odd ports as well.
			 * In 200G mode, we don't have this issue because the odd ports are active
			 * and should be set fine.
			 */
			if (!is_200_gbps)
				lrank.p_0_23.ports |= bitfield_safe(BIT(macro * 2 + 1), 24);
		}
	}

	msg->size = sizeof(lrank);
	memcpy(msg->packet, &lrank, msg->size);

	return 0;
}

static int gaudi3_nic_coll_op_format_msg_update_last_rank(
						const struct hltests_nic_coll_comm_group *group,
						struct hltests_nic_db_fifo_packet *msg)
{
	struct hltests_device *hdev;
	struct gaudi3_priv *gaudi3;
	struct coll_desc_update_last_rank lrank = {};
	uint32_t port, max_n_ports, macro, lane_offset;

	assert_non_null(group);
	assert_non_null(msg);

	hdev = get_hdev_from_fd(group->tests_state->fd);
	gaudi3 = hdev->priv;
	max_n_ports = (uint32_t)gaudi3_nic_get_max_num_of_ports();

	lrank.ctrl.cmd = COLL_CMD_LAST_RANK_UPDATE;
	lrank.ctrl.context_id = u8_safe(group->id);
	lrank.ctrl.lane_select = 0x5;
	lrank.ctrl.update_bitmask = 0x3;

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		/* 200Gbps mode:
		 * - 2 ports per macro
		 * - odd port is lane index 2
		 */
		if (gaudi3->speed[port] == SPEED_200000) {
			macro = port >> 1;
			lane_offset = (port % 2) ? 2 : 0;
		} else {
			macro = port;
			lane_offset = 0;
		}

		/* In 400Gbps, only ports from 0..11 can be enabled, so macro always remains < 12.
		 * And lane_offset only be 0. In 200Gbps, lane_offset can be 0 or 2.
		 */
		assert_true(macro < NIC_MAX_NUM_OF_MACROS);

		if (group->nodes[port].is_last_rank) {
			if ((macro * 4 + lane_offset) < (COLL_DESC_ENT_NICS_PER_ENTRY))
				lrank.p_0_23.ports |= bitfield_safe(BIT(macro * 4 + lane_offset),
								    24);
			else
				lrank.p_24_47.ports |=
						bitfield_safe(BIT(macro * 4 + lane_offset -
								  COLL_DESC_ENT_NICS_PER_ENTRY),
							      24);
		}
	}

	/* The actual message len depends on the amount of entries added */
	msg->size = sizeof(lrank);
	memcpy(msg->packet, &lrank, msg->size);

	return 0;
}

static int gaudi3_nic_coll_op_format_msg_update_last_rank_new(
	const struct hltests_nic_coll_comm_group_new *group, struct hltests_nic_db_fifo_packet *msg)
{
	struct hltests_device *hdev;
	struct gaudi3_priv *gaudi3;
	struct coll_desc_update_last_rank lrank = {};
	uint32_t port, max_n_ports, macro, lane_offset;

	assert_non_null(group);
	assert_non_null(msg);

	hdev = get_hdev_from_fd(group->tests_state->fd);
	gaudi3 = hdev->priv;
	max_n_ports = (uint32_t)gaudi3_nic_get_max_num_of_ports();

	lrank.ctrl.cmd = COLL_CMD_LAST_RANK_UPDATE;
	lrank.ctrl.context_id = u8_safe(group->id);
	lrank.ctrl.lane_select = 0x5;
	lrank.ctrl.update_bitmask = 0x3;

	for (port = 0; port < max_n_ports; port++) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		/* 200Gbps mode:
		 * - 2 ports per macro
		 * - odd port is lane index 2
		 */
		if (gaudi3->speed[port] == SPEED_200000) {
			macro = port >> 1;
			lane_offset = (port % 2) ? 2 : 0;
		} else {
			macro = port;
			lane_offset = 0;
		}

		/* In 400Gbps, only ports from 0..11 can be enabled, so macro always remains < 12.
		 * And lane_offset only be 0. In 200Gbps, lane_offset can be 0 or 2.
		 */
		assert_true(macro < NIC_MAX_NUM_OF_MACROS);

		if (group->nodes[port].is_last_rank) {
			if ((macro * 4 + lane_offset) < COLL_DESC_ENT_NICS_PER_ENTRY)
				lrank.p_0_23.ports |= bitfield_safe(BIT(macro * 4 + lane_offset),
								    24);
			else
				lrank.p_24_47.ports |=
					bitfield_safe(BIT(macro * 4 + lane_offset -
							  COLL_DESC_ENT_NICS_PER_ENTRY),
						      24);
		}
	}

	/* The actual message len depends on the amount of entries added */
	msg->size = sizeof(lrank);
	memcpy(msg->packet, &lrank, msg->size);

	return 0;
}

static int gaudi3_nic_coll_op_format_msg_qp_offset_update_lane_0_1(
						const struct hltests_nic_coll_comm_group *group,
						struct hltests_nic_db_fifo_packet *msg)
{
	struct hltests_device *hdev;
	struct gaudi3_priv *gaudi3;
	struct coll_desc_update_qpn_offset_lo qpn_offset = {};
	uint32_t port, max_n_ports, ports_per_macro, macro, entry = 0;
	bool is_200_gbps;
	int fd;

	assert_non_null(group);
	assert_non_null(msg);

	fd = group->tests_state->fd;
	hdev = get_hdev_from_fd(fd);
	gaudi3 = hdev->priv;
	max_n_ports = (uint32_t)gaudi3_nic_get_max_num_of_ports();
	is_200_gbps = NIC_IS_200_GBPS_MODE(fd, group->nodes_mask);

	/* In 200Gbps mode, we have 2 ports per macro. */
	ports_per_macro = is_200_gbps ? 2 : 1;

	qpn_offset.ctrl.cmd = COLL_CMD_QP_OFFSET_UPDATE_LANE_0_1;
	qpn_offset.ctrl.context_id = u8_safe(group->id);
	qpn_offset.ctrl.lane_select = 0x5;

	entry = 12;
	qpn_offset.ctrl.update_bitmask = 0xfff;
	for (port = 0 ; port < max_n_ports ; port += ports_per_macro) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		/* In 200Gbps mode, we have 2 ports per macro. */
		macro = port >> (is_200_gbps ? 1 : 0);

		qpn_offset.nics[macro].qpn_offset_lane_0 = (uint8_t)group->nodes[port].conn_id;
	}

	/* The actual message len depends on the amount of entries added */
	msg->size = (uint32_t)(sizeof(qpn_offset.ctrl) + entry * sizeof(qpn_offset.nics[0]));
	memcpy(msg->packet, &qpn_offset, msg->size);

	return 0;
}

static int gaudi3_nic_coll_op_format_msg_qp_offset_update_lane_0_1_new(
	const struct hltests_nic_coll_comm_group_new *group, struct hltests_nic_db_fifo_packet *msg)
{
	struct hltests_device *hdev;
	struct gaudi3_priv *gaudi3;
	struct coll_desc_update_qpn_offset_lo qpn_offset = {};
	uint32_t port, max_n_ports, ports_per_macro, macro, entry = 0;
	bool is_200_gbps;
	int fd;

	assert_non_null(group);
	assert_non_null(msg);

	fd = group->tests_state->fd;
	hdev = get_hdev_from_fd(fd);
	gaudi3 = hdev->priv;
	max_n_ports = (uint32_t)gaudi3_nic_get_max_num_of_ports();
	is_200_gbps = NIC_IS_200_GBPS_MODE(fd, group->nodes_mask);

	/* In 200Gbps mode, we have 2 ports per macro. */
	ports_per_macro = is_200_gbps ? 2 : 1;

	qpn_offset.ctrl.cmd = COLL_CMD_QP_OFFSET_UPDATE_LANE_0_1;
	qpn_offset.ctrl.context_id = u8_safe(group->id);
	qpn_offset.ctrl.lane_select = 0x5;

	entry = 12;
	qpn_offset.ctrl.update_bitmask = 0xfff;
	for (port = 0; port < max_n_ports; port += ports_per_macro) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		/* In 200Gbps mode, we have 2 ports per macro. */
		macro = port >> (is_200_gbps ? 1 : 0);

		qpn_offset.nics[macro].qpn_offset_lane_0 = (uint8_t)group->nodes[port].conn_id;
	}

	/* The actual message len depends on the amount of entries added */
	msg->size = (uint32_t)(sizeof(qpn_offset.ctrl) + entry * sizeof(qpn_offset.nics[0]));
	memcpy(msg->packet, &qpn_offset, msg->size);

	return 0;
}

static int gaudi3_nic_coll_op_format_msg_qp_offset_update_lane_2_3(
						const struct hltests_nic_coll_comm_group *group,
						struct hltests_nic_db_fifo_packet *msg)
{
	struct hltests_device *hdev;
	struct gaudi3_priv *gaudi3;
	struct coll_desc_update_qpn_offset_hi qpn_offset = {};
	uint32_t port, max_n_ports, entry = 0;
	int fd;

	assert_non_null(group);
	assert_non_null(msg);

	fd = group->tests_state->fd;
	hdev = get_hdev_from_fd(fd);
	gaudi3 = hdev->priv;
	max_n_ports = (uint32_t)gaudi3_nic_get_max_num_of_ports();

	/* QPN offset, lane 2 needs to be configured only for 200Gbps mode. */
	assert_true(NIC_IS_200_GBPS_MODE(fd, group->nodes_mask));

	qpn_offset.ctrl.cmd = COLL_CMD_QP_OFFSET_UPDATE_LANE_2_3;
	qpn_offset.ctrl.context_id = u8_safe(group->id);
	qpn_offset.ctrl.lane_select = 0x5;

	entry = 12;
	qpn_offset.ctrl.update_bitmask = 0xfff;

	/* We can assert here that we are in 200Gbps mode.
	 * Iterate over all odd ports i.e. lane 2.
	 */
	for (port = 1 ; port < max_n_ports ; port += 2) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		qpn_offset.nics[port >> 1].qpn_offset_lane_2 = (uint16_t)group->nodes[port].conn_id;
	}

	/* The actual message len depends on the amount of entries added */
	msg->size = (uint32_t)(sizeof(qpn_offset.ctrl) + entry * sizeof(qpn_offset.nics[0]));
	memcpy(msg->packet, &qpn_offset, msg->size);

	return 0;
}

static int gaudi3_nic_coll_op_format_msg_qp_offset_update_lane_2_3_new(
	const struct hltests_nic_coll_comm_group_new *group, struct hltests_nic_db_fifo_packet *msg)
{
	struct hltests_device *hdev;
	struct gaudi3_priv *gaudi3;
	struct coll_desc_update_qpn_offset_hi qpn_offset = {};
	uint32_t port, max_n_ports, entry = 0;
	int fd;

	assert_non_null(group);
	assert_non_null(msg);

	fd = group->tests_state->fd;
	hdev = get_hdev_from_fd(fd);
	gaudi3 = hdev->priv;
	max_n_ports = (uint32_t)gaudi3_nic_get_max_num_of_ports();

	/* QPN offset, lane 2 needs to be configured only for 200Gbps mode. */
	assert_true(NIC_IS_200_GBPS_MODE(fd, group->nodes_mask));

	qpn_offset.ctrl.cmd = COLL_CMD_QP_OFFSET_UPDATE_LANE_2_3;
	qpn_offset.ctrl.context_id = u8_safe(group->id);
	qpn_offset.ctrl.lane_select = 0x5;

	entry = 12;
	qpn_offset.ctrl.update_bitmask = 0xfff;

	/* We can assert here that we are in 200Gbps mode.
	 * Iterate over all odd ports i.e. lane 2.
	 */
	for (port = 1; port < max_n_ports; port += 2) {
		if (!(BIT_ULL(port) & group->nodes_mask))
			continue;

		qpn_offset.nics[port >> 1].qpn_offset_lane_2 = (uint16_t)group->nodes[port].conn_id;
	}

	/* The actual message len depends on the amount of entries added */
	msg->size = (uint32_t)(sizeof(qpn_offset.ctrl) + entry * sizeof(qpn_offset.nics[0]));
	memcpy(msg->packet, &qpn_offset, msg->size);

	return 0;
}

static int gaudi3_nic_coll_op_format_msg_update_qpn_base(struct hltests_nic_db_fifo_packet *msg)
{
	struct coll_desc_update_qpn_base qpn_base = {};

	assert_non_null(msg);

	qpn_base.ctrl.cmd = COLL_CMD_QP_BASE_UPDATE;
	qpn_base.ctrl.update_bitmask = 0x1;
	/* Other ctrl fields are not used in this commands */
	qpn_base.base = 0;

	msg->size = sizeof(qpn_base);
	memcpy(msg->packet, &qpn_base, msg->size);

	return 0;
}

static uint64_t coll_op_get_lane_mask(int fd, uint64_t port_mask)
{
	struct hltests_device *hdev;
	struct gaudi3_priv *gaudi3;
	uint64_t lane_mask = 0;
	uint32_t port, max_n_ports, macro, lane_offset;

	hdev = get_hdev_from_fd(fd);
	gaudi3 = hdev->priv;
	max_n_ports = (uint32_t)gaudi3_nic_get_max_num_of_ports();

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(BIT(port) & port_mask))
			continue;

		/* 200Gbps mode:
		 * - 2 ports per macro
		 * - odd port is lane index 2
		 */
		if (gaudi3->speed[port] == SPEED_200000) {
			macro = port >> 1;
			lane_offset = (port % 2) ? 2 : 0;
		} else {
			macro = port;
			lane_offset = 0;
		}

		lane_mask |= 1ull << (macro * 4 + lane_offset);
	}

	return lane_mask;
}

static int gaudi3_nic_coll_op_format_msg_enable_update(
						const struct hltests_nic_coll_comm_group *group,
						struct hltests_nic_db_fifo_packet *msg)
{
	struct coll_desc_update_enable update_en = {};
	uint64_t lane_mask;

	assert_non_null(group);
	assert_non_null(msg);

	lane_mask = coll_op_get_lane_mask(group->tests_state->fd, group->nodes_mask);
	assert_non_null(lane_mask);

	update_en.ctrl.cmd = COLL_CMD_ENABLE_UPDATE;
	update_en.ctrl.context_id = bitfield_safe(group->id, 8);
	update_en.ctrl.lane_select = 0x5;
	update_en.ctrl.update_bitmask = 0x3;
	update_en.p_0_23.ports =
		bitfield_safe(lower_32_bits(lane_mask) & COLL_DESC_ENT_NICS_PER_ENTRY_M, 24);
	update_en.p_24_47.ports =
		bitfield_safe((upper_32_bits(lane_mask) << (32 - COLL_DESC_ENT_NICS_PER_ENTRY)) |
			(lower_32_bits(lane_mask) >> COLL_DESC_ENT_NICS_PER_ENTRY), 24);

	msg->size = sizeof(update_en);
	memcpy(msg->packet, &update_en, msg->size);
	return 0;
}

static int
gaudi3_nic_coll_op_format_msg_enable_update_new(const struct hltests_nic_coll_comm_group_new *group,
						struct hltests_nic_db_fifo_packet *msg)
{
	struct coll_desc_update_enable update_en = {};
	uint64_t lane_mask;

	assert_non_null(group);
	assert_non_null(msg);

	lane_mask = coll_op_get_lane_mask(group->tests_state->fd, group->nodes_mask);
	assert_non_null(lane_mask);

	update_en.ctrl.cmd = COLL_CMD_ENABLE_UPDATE;
	update_en.ctrl.context_id = bitfield_safe(group->id, 8);
	update_en.ctrl.lane_select = 0x5;
	update_en.ctrl.update_bitmask = 0x3;
	update_en.p_0_23.ports =
		bitfield_safe(lower_32_bits(lane_mask) & COLL_DESC_ENT_NICS_PER_ENTRY_M, 24);
	update_en.p_24_47.ports = bitfield_safe(
		(upper_32_bits(lane_mask) << (32 - COLL_DESC_ENT_NICS_PER_ENTRY)) |
		(lower_32_bits(lane_mask) >> COLL_DESC_ENT_NICS_PER_ENTRY), 24);

	msg->size = sizeof(update_en);
	memcpy(msg->packet, &update_en, msg->size);
	return 0;
}

static int gaudi3_nic_coll_op_format_msg(const struct hltests_nic_coll_comm_group *group,
					enum gaudi3_coll_cmd cmd,
					void *cmd_params,
					struct hltests_nic_db_fifo_packet *msg)
{
	struct coll_desc *coll_desc_params = cmd_params;
	int rc;
	bool is_direct_mode = group->in_params->coll_type == COLL_TYPE_DIRECT;

	switch (cmd) {
	case COLL_CMD_EXECUTE:
		rc = gaudi3_nic_coll_op_format_msg_execute(group->id, msg);
		break;
	case COLL_CMD_DESCRIPTOR_WRITE:
		rc = gaudi3_nic_coll_op_format_msg_coll_desc(coll_desc_params,
							     sizeof(coll_desc_params->write), msg);
		break;
	case COLL_CMD_DEST_RANK_UPDATE:
		if (is_direct_mode)
			rc = gaudi3_nic_direct_coll_op_format_msg_update_dest_rank(group, msg);
		else
			rc = gaudi3_nic_coll_op_format_msg_update_dest_rank(group, msg);
		break;
	case COLL_CMD_LAST_RANK_UPDATE:
		if (is_direct_mode)
			rc = gaudi3_nic_direct_coll_op_format_msg_update_last_rank(group, msg);
		else
			rc = gaudi3_nic_coll_op_format_msg_update_last_rank(group, msg);
		break;
	case COLL_CMD_QP_OFFSET_UPDATE_LANE_0_1:
		rc = gaudi3_nic_coll_op_format_msg_qp_offset_update_lane_0_1(group, msg);
		break;
	case COLL_CMD_QP_OFFSET_UPDATE_LANE_2_3:
		rc = gaudi3_nic_coll_op_format_msg_qp_offset_update_lane_2_3(group, msg);
		break;
	case COLL_CMD_QP_BASE_UPDATE:
		rc = gaudi3_nic_coll_op_format_msg_update_qpn_base(msg);
		break;
	case COLL_CMD_ENABLE_UPDATE:
		rc = gaudi3_nic_coll_op_format_msg_enable_update(group, msg);
		break;
	case COLL_CMD_DESCRIPTOR_SND_RCV:
		rc = gaudi3_nic_coll_op_format_msg_coll_desc(
			coll_desc_params, sizeof(coll_desc_params->send_receive), msg);
		break;
	case COLL_CMD_DESCRIPTOR_0_VOP_SR:
	case COLL_CMD_DESCRIPTOR_1_VOP_SR:
		/* In RDV testing, QPs are divided as follows: Odd QP - send side, even QP -
		 * receive side
		 */
		if (group->id & 1)
			rc = gaudi3_nic_coll_op_format_msg_coll_desc(
				coll_desc_params, sizeof(coll_desc_params->v_operation), msg);
		else
			rc = gaudi3_nic_coll_op_format_msg_coll_desc(
				coll_desc_params, sizeof(coll_desc_params->send_receive), msg);

		break;
	case COLL_CMD_DESCRIPTOR_MS_SND_RCV:
		rc = gaudi3_nic_coll_op_format_msg_coll_desc(
			coll_desc_params, sizeof(coll_desc_params->ms_send_receive), msg);
		break;
	case COLL_CMD_CONSUME_DWORDS:
	case COLL_CMD_DESCRIPTOR_MS_WRITE:
	default:
		return -EOPNOTSUPP;
	}

	return rc;
}

static int gaudi3_nic_coll_op_format_msg_new(const struct hltests_nic_coll_comm_group_new *group,
					     enum gaudi3_coll_cmd cmd, void *cmd_params,
					     struct hltests_nic_db_fifo_packet *msg)
{
	struct coll_desc *coll_desc_params = cmd_params;
	int rc;
	bool is_direct_mode = group->params->cfg->coll_type == COLL_TYPE_DIRECT;

	switch (cmd) {
	case COLL_CMD_EXECUTE:
		rc = gaudi3_nic_coll_op_format_msg_execute(group->id, msg);
		break;
	case COLL_CMD_DESCRIPTOR_WRITE:
		rc = gaudi3_nic_coll_op_format_msg_coll_desc(coll_desc_params,
							     sizeof(coll_desc_params->write), msg);
		break;
	case COLL_CMD_DEST_RANK_UPDATE:
		if (is_direct_mode)
			rc = gaudi3_nic_direct_coll_op_format_msg_update_dest_rank_new(group, msg);
		else
			rc = gaudi3_nic_coll_op_format_msg_update_dest_rank_new(group, msg);
		break;
	case COLL_CMD_LAST_RANK_UPDATE:
		if (is_direct_mode)
			rc = gaudi3_nic_direct_coll_op_format_msg_update_last_rank_new(group, msg);
		else
			rc = gaudi3_nic_coll_op_format_msg_update_last_rank_new(group, msg);
		break;
	case COLL_CMD_QP_OFFSET_UPDATE_LANE_0_1:
		rc = gaudi3_nic_coll_op_format_msg_qp_offset_update_lane_0_1_new(group, msg);
		break;
	case COLL_CMD_QP_OFFSET_UPDATE_LANE_2_3:
		rc = gaudi3_nic_coll_op_format_msg_qp_offset_update_lane_2_3_new(group, msg);
		break;
	case COLL_CMD_QP_BASE_UPDATE:
		rc = gaudi3_nic_coll_op_format_msg_update_qpn_base(msg);
		break;
	case COLL_CMD_ENABLE_UPDATE:
		rc = gaudi3_nic_coll_op_format_msg_enable_update_new(group, msg);
		break;
	case COLL_CMD_DESCRIPTOR_SND_RCV:
		rc = gaudi3_nic_coll_op_format_msg_coll_desc(
			coll_desc_params, sizeof(coll_desc_params->send_receive), msg);
		break;
	case COLL_CMD_DESCRIPTOR_0_VOP_SR:
	case COLL_CMD_DESCRIPTOR_1_VOP_SR:
		/* In RDV testing, QPs are divided as follows: Odd QP - send side, even QP -
		 * receive side
		 */
		if (group->id & 1)
			rc = gaudi3_nic_coll_op_format_msg_coll_desc(
				coll_desc_params, sizeof(coll_desc_params->v_operation), msg);
		else
			rc = gaudi3_nic_coll_op_format_msg_coll_desc(
				coll_desc_params, sizeof(coll_desc_params->send_receive), msg);

		break;
	case COLL_CMD_DESCRIPTOR_MS_SND_RCV:
		rc = gaudi3_nic_coll_op_format_msg_coll_desc(
			coll_desc_params, sizeof(coll_desc_params->ms_send_receive), msg);
		break;
	case COLL_CMD_CONSUME_DWORDS:
	case COLL_CMD_DESCRIPTOR_MS_WRITE:
	default:
		return -EOPNOTSUPP;
	}

	return rc;
}

static int gaudi3_nic_coll_op_dup_engine_send_msg(struct hltests_nic_coll_comm_group *group,
						uint64_t ports_mask,
						struct hltests_nic_db_fifo_packet *msg)
{
	struct hltests_nic_coll_comm_node *node;
	struct hltests_nic_db_fifo_data *db_fifo;
	struct hltests_state *tests_state = group->tests_state;
	uint32_t sob_curr_val = 0, port;
	bool is_direct_mode = group->in_params->coll_type == COLL_TYPE_DIRECT;
	int rc;

	for (port = 0 ; port < MAX_NIC_NUMBER_OF_PORTS ; port++) {
		if (!((group->nodes_mask & BIT_ULL(port)) && (ports_mask & BIT_ULL(port))))
			continue;

		/* Write to DB fifo once per macro. In 200Gbps mode, descriptor lane
		 * select is used by HW to config all required logical ports.
		 *
		 * Skip for odd port if even port is enabled, only in 200Gbps mode.
		 *
		 * This is not applicable for direct mode as the port enable bits are embedded in
		 * the write/send_receive descriptor. This can issue in the direct patcher legacy
		 * tests as we run the test for all the available ports. If we skip sending the
		 * fifo update for odd ports, the test would fail as the patcher operation on the
		 * odd port would not be triggered.
		 */
		if (NIC_IS_200_GBPS_MODE(group->tests_state->fd, ports_mask) &&
			(port % 2) && (ports_mask & BIT(port - 1)) && !is_direct_mode)
			continue;

		node = &group->nodes[port];
		db_fifo = node->db_fifo;

		/* PI here is outstanding DB fifo data(unit bytes), yet to be consumed by HW. */
		db_fifo->pi += msg->size;

		/* We are crossing threshold. Read current CI from HW. */
		if (db_fifo->pi >= db_fifo->fifo_bp_thresh)
			sob_curr_val = hltests_nic_get_sob_value(group->tests_state,
								 db_fifo->sob_id);

		/* All collective operation descriptor size is less than fifo_bp_thresh
		 * i.e. half the DB fifo size. Hence, no need to split the descriptors
		 * based on available free space in DB fifo.
		 */
		hltests_nic_write_descriptor_to_db_fifo(group->tests_state, db_fifo,
							msg, port, db_fifo->is_dup_enabled);

		/* Since we crossed threshold, wait for HW to catch up. */
		if (db_fifo->pi >= db_fifo->fifo_bp_thresh) {
			/* All coll ops descriptor size is less than fifo_bp_thresh.
			 * i.e. half the DB fifo size. Hence, wait for increment 1.
			 */
			int sob_expected_val = uint_to_int_safe(sob_curr_val + 1);

			rc = hltests_nic_wait_on_sob(tests_state->fd, db_fifo->sob_id, tests_state,
						     (int)sob_expected_val, group->in_params->eq);
			assert_int_equal(rc, 0);

			/* HW CI is incremented by 1. This means HW consumed fifo_bp_thresh data.
			 * Update PI i.e. current outstanding accordingly.
			 */
			db_fifo->pi -= db_fifo->fifo_bp_thresh;
		}
	}

	return 0;
}

static int gaudi3_nic_coll_op_dup_engine_send_msg_new(struct hltests_nic_coll_comm_group_new *group,
						      uint64_t ports_mask,
						      struct hltests_nic_db_fifo_packet *msg)
{
	struct hltests_nic_coll_comm_node_new *node;
	struct hltests_nic_db_fifo_data *db_fifo;
	struct hltests_state *tests_state = group->tests_state;
	uint32_t sob_curr_val = 0, port;
	bool is_direct_mode = group->params->cfg->coll_type == COLL_TYPE_DIRECT;
	int rc;

	for (port = 0; port < MAX_NIC_NUMBER_OF_PORTS; port++) {
		if (!((group->nodes_mask & BIT_ULL(port)) && (ports_mask & BIT_ULL(port))))
			continue;

		/* Write to DB fifo once per macro. In 200Gbps mode, descriptor lane
		 * select is used by HW to config all required logical ports.
		 *
		 * Skip for odd port if even port is enabled, only in 200Gbps mode.
		 *
		 * This is not applicable for direct mode as the port enable bits are embedded in
		 * the write/send_receive descriptor. This can issue in the direct patcher legacy
		 * tests as we run the test for all the available ports. If we skip sending the
		 * fifo update for odd ports, the test would fail as the patcher operation on the
		 * odd port would not be triggered.
		 */
		if (NIC_IS_200_GBPS_MODE(group->tests_state->fd, ports_mask) && (port % 2) &&
		    (ports_mask & BIT(port - 1)) && !is_direct_mode)
			continue;

		node = &group->nodes[port];
		db_fifo = node->db_fifo;

		/* PI here is outstanding DB fifo data(unit bytes), yet to be consumed by HW. */
		db_fifo->pi += msg->size;

		/* We are crossing threshold. Read current CI from HW. */
		if (db_fifo->pi >= db_fifo->fifo_bp_thresh)
			sob_curr_val = hltests_nic_get_sob_value(group->tests_state,
								 db_fifo->sob_id);

		/* All collective operation descriptor size is less than fifo_bp_thresh
		 * i.e. half the DB fifo size. Hence, no need to split the descriptors
		 * based on available free space in DB fifo.
		 */
		hltests_nic_write_descriptor_to_db_fifo(group->tests_state, db_fifo, msg, port,
							db_fifo->is_dup_enabled);

		/* Since we crossed threshold, wait for HW to catch up. */
		if (db_fifo->pi >= db_fifo->fifo_bp_thresh) {
			/* All coll ops descriptor size is less than fifo_bp_thresh.
			 * i.e. half the DB fifo size. Hence, wait for increment 1.
			 */
			int sob_expected_val = uint_to_int_safe(sob_curr_val + 1);

			rc = hltests_nic_wait_on_sob(tests_state->fd, db_fifo->sob_id, tests_state,
						     (int)sob_expected_val, &group->params->eq);
			assert_int_equal(rc, 0);

			/* HW CI is incremented by 1. This means HW consumed fifo_bp_thresh data.
			 * Update PI i.e. current outstanding accordingly.
			 */
			db_fifo->pi -= db_fifo->fifo_bp_thresh;
		}
	}

	return 0;
}

static const struct hltests_nic_coll_comm_node
			*gaudi3_nic_coll_op_comm_group_get_member(
						const struct hltests_nic_coll_comm_group *group,
						unsigned int idx)
{
	uint64_t last_port_set;

	assert_non_null_ret_ptr(group);
	assert_non_null_ret_ptr(group->allocated);
	assert_true_ret_ptr(idx < MAX_NIC_NUMBER_OF_PORTS);

	last_port_set = (uint8_t)HL_LOG2(group->nodes_mask & ~(group->nodes_mask - 1));
	assert_in_range_ret_ptr(last_port_set, 0, MAX_NIC_NUMBER_OF_PORTS - 1);

	return &group->nodes[last_port_set];
}

static const struct hltests_nic_coll_comm_node_new *
gaudi3_nic_coll_op_comm_group_get_member_new(const struct hltests_nic_coll_comm_group_new *group,
					     unsigned int idx)
{
	uint64_t last_port_set;

	assert_non_null_ret_ptr(group);
	assert_non_null_ret_ptr(group->allocated);
	assert_true_ret_ptr(idx < MAX_NIC_NUMBER_OF_PORTS);

	last_port_set = (uint8_t)HL_LOG2(group->nodes_mask & ~(group->nodes_mask - 1));
	assert_in_range_ret_ptr(last_port_set, 0, MAX_NIC_NUMBER_OF_PORTS - 1);

	return &group->nodes[last_port_set];
}

static int gaudi3_nic_coll_op_comm_group_size(const struct hltests_nic_coll_comm_group *group)
{
	int i, size = 0;

	assert_non_null(group);
	assert_true(group->allocated);

	for (i = 0 ; i < MAX_NIC_NUMBER_OF_PORTS ; i++) {
		if (group->nodes_mask & BIT_ULL(i))
			size += 1;
	}

	return size;
}

static int
gaudi3_nic_coll_op_comm_group_size_new(const struct hltests_nic_coll_comm_group_new *group)
{
	int i, size = 0;

	assert_non_null(group);
	assert_true(group->allocated);

	for (i = 0; i < MAX_NIC_NUMBER_OF_PORTS; i++) {
		if (group->nodes_mask & BIT_ULL(i))
			size += 1;
	}

	return size;
}

static int gaudi3_nic_coll_op_comm_group_update(struct hltests_nic_coll_comm_group *group,
						enum gaudi3_coll_cmd cmd,
						void *cmd_params,
						uint64_t ports_mask)
{
	struct hltests_nic_db_fifo_packet msg = {};
	void *msg_data;
	int rc;

	msg_data = calloc(1, COLL_MSG_MAX_LEN);
	msg.packet = msg_data;

	rc = gaudi3_nic_coll_op_format_msg(group, cmd, cmd_params, &msg);
	if (rc)
		return rc;

	rc = gaudi3_nic_coll_op_dup_engine_send_msg(group, ports_mask, &msg);
	assert_int_equal(rc, 0);

	free(msg_data);

	return rc;
}

static int gaudi3_nic_coll_op_comm_group_update_new(struct hltests_nic_coll_comm_group_new *group,
						    enum gaudi3_coll_cmd cmd, void *cmd_params,
						    uint64_t ports_mask)
{
	struct hltests_nic_db_fifo_packet msg = {};
	void *msg_data;
	int rc;

	msg_data = calloc(1, COLL_MSG_MAX_LEN);
	msg.packet = msg_data;

	rc = gaudi3_nic_coll_op_format_msg_new(group, cmd, cmd_params, &msg);
	if (rc)
		return rc;

	rc = gaudi3_nic_coll_op_dup_engine_send_msg_new(group, ports_mask, &msg);
	assert_int_equal(rc, 0);

	free(msg_data);

	return rc;
}

static enum gaudi3_coll_cmd coll_get_cmd_desc_from_cfg(struct hltests_nic_coll_comm_group *group)
{
	enum hltests_nic_test_opcode test_opcode = group->in_params->test_opcode;
	enum hltests_nic_rdv_type rdv_type = group->in_params->rdv_type;
	enum gaudi3_coll_cmd cmd = COLL_CMD_MAX;
	uint64_t half_port_mask;

	if (test_opcode == TEST_OPCODE_LINEAR_WRITE || test_opcode == TEST_OPCODE_RENDEZVOUS_READ) {
		cmd = COLL_CMD_DESCRIPTOR_WRITE;
	} else if (test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE) {
		if (rdv_type == HLTESTS_NIC_RDV_SND_RCV)
			cmd = COLL_CMD_DESCRIPTOR_SND_RCV;
		else if (rdv_type == HLTESTS_NIC_RDV_MS)
			cmd = COLL_CMD_DESCRIPTOR_MS_SND_RCV;
		else if (rdv_type == HLTESTS_NIC_RDV_V_OP)
			cmd = COLL_CMD_DESCRIPTOR_0_VOP_SR;
		else
			printf("Unsupported rdv_type: %d\n", rdv_type);
	} else {
		printf("Unsupported test opcode: %d\n", test_opcode);
	}

	if (cmd == COLL_CMD_DESCRIPTOR_0_VOP_SR &&
		group->in_params->coll_type == COLL_TYPE_CONTEXT) {
		half_port_mask = gaudi3_nic_get_half_port_mask(group->tests_state->fd,
								group->nodes_mask, true);

		if (half_port_mask)
			cmd = COLL_CMD_DESCRIPTOR_1_VOP_SR;
	}

	return cmd;
}

static enum gaudi3_coll_cmd
coll_get_cmd_desc_from_cfg_new(struct hltests_nic_coll_comm_group_new *group)
{
	enum hltests_nic_test_opcode test_opcode = group->params->cfg->test_opcode;
	enum hltests_nic_rdv_type rdv_type = group->params->cfg->rdv_type;
	enum gaudi3_coll_cmd cmd = COLL_CMD_MAX;
	uint64_t half_port_mask;

	if (test_opcode == TEST_OPCODE_LINEAR_WRITE || test_opcode == TEST_OPCODE_RENDEZVOUS_READ) {
		cmd = COLL_CMD_DESCRIPTOR_WRITE;
	} else if (test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE) {
		if (rdv_type == HLTESTS_NIC_RDV_SND_RCV)
			cmd = COLL_CMD_DESCRIPTOR_SND_RCV;
		else if (rdv_type == HLTESTS_NIC_RDV_MS)
			cmd = COLL_CMD_DESCRIPTOR_MS_SND_RCV;
		else if (rdv_type == HLTESTS_NIC_RDV_V_OP)
			cmd = COLL_CMD_DESCRIPTOR_0_VOP_SR;
		else
			printf("Unsupported rdv_type: %d\n", rdv_type);
	} else {
		printf("Unsupported test opcode: %d\n", test_opcode);
	}

	if (cmd == COLL_CMD_DESCRIPTOR_0_VOP_SR &&
	    group->params->cfg->coll_type == COLL_TYPE_CONTEXT) {
		half_port_mask = gaudi3_nic_get_half_port_mask(group->tests_state->fd,
							       group->nodes_mask, true);

		if (half_port_mask)
			cmd = COLL_CMD_DESCRIPTOR_1_VOP_SR;
	}

	return cmd;
}

static int coll_op_update_rank(struct hltests_nic_coll_comm_group *comm_group, int rank,
				bool is_last_rank)
{
	struct hltests_nic_in_params *in_params;
	uint32_t port, max_n_ports;
	int rc;

	assert_true(rank >= 0);

	max_n_ports = gaudi3_nic_get_max_num_of_ports();
	in_params = comm_group->in_params;

	/* Update rank info for communication group nodes. */
	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(in_params->port_mask & comm_group->nodes_mask & BIT_ULL(port)))
			continue;

		comm_group->nodes[port].rank = (uint32_t)rank;
		comm_group->nodes[port].is_last_rank = is_last_rank;
	}

	/* Config rank for each port in collective communication group. */

	rc = gaudi3_nic_coll_op_comm_group_update(comm_group, COLL_CMD_LAST_RANK_UPDATE,
							NULL, comm_group->nodes_mask);
	assert_int_equal(rc, 0);

	rc = gaudi3_nic_coll_op_comm_group_update(comm_group, COLL_CMD_DEST_RANK_UPDATE,
							NULL, comm_group->nodes_mask);
	assert_int_equal(rc, 0);

	return 0;
}

static int coll_op_update_rank_new(struct hltests_nic_coll_comm_group_new *comm_group, int rank,
				   bool is_last_rank)
{
	const struct hltests_nic_test_params *params = comm_group->params;
	uint32_t port_idx;
	int rc;

	assert_true(rank >= 0);

	/* Update rank info for communication group nodes. */
	for (port_idx = 0; port_idx < params->cfg->ports_num; port_idx++) {
		uint32_t port = params->cfg->ports[port_idx];

		comm_group->nodes[port].rank = (uint32_t)rank;
		comm_group->nodes[port].is_last_rank = is_last_rank;
	}

	/* Config rank for each port in collective communication group. */

	rc = gaudi3_nic_coll_op_comm_group_update_new(comm_group, COLL_CMD_LAST_RANK_UPDATE, NULL,
						      comm_group->nodes_mask);
	assert_int_equal(rc, 0);

	rc = gaudi3_nic_coll_op_comm_group_update_new(comm_group, COLL_CMD_DEST_RANK_UPDATE, NULL,
						      comm_group->nodes_mask);
	assert_int_equal(rc, 0);

	return 0;
}

static int coll_op_fill_wqe(struct hltests_nic_coll_comm_group *comm_group,
				enum gaudi3_coll_cmd coll_cmd,
				struct hltests_nic_wqe_params *wqe_params)
{
	const struct hltests_nic_coll_comm_node *node;
	int64_t wqe_params_port;
	uint32_t wqe_param_conn_id;
	int rc;

	/* Configure descriptor.
	 * We prepare descriptor for 1st node in mask, and push the same on all ports. This works
	 * because HW calculates offset for a given port using LAG/rank index.
	 */
	node = gaudi3_nic_coll_op_comm_group_get_member(comm_group, 0);
	assert_non_null(node);

	if (comm_group->in_params->coll_op != COLL_OP_MODE_LEGACY)
		wqe_params_port =
			(uint32_t)__builtin_ffsl((int64_t)comm_group->in_params->port_mask) - 1;
	else
		wqe_params_port = node->port_id;

	assert_in_range(wqe_params_port, 0, UINT_MAX);

	/* we need the connection id of the first enabled port to be passed to the function as
	 * we calculate the wqe params based on that port's WQE.
	 */
	wqe_param_conn_id =
		 comm_group->in_params->nic_conn->conn_id[wqe_params_port][comm_group->id];

	rc = gaudi3_nic_coll_group_prepare_wqe_params(comm_group, (unsigned int)wqe_params_port,
							wqe_param_conn_id, wqe_params);
	assert_int_equal(rc, 0);

	return 0;
}

static int coll_op_fill_wqe_new(struct hltests_nic_coll_comm_group_new *comm_group,
				enum gaudi3_coll_cmd coll_cmd,
				struct hltests_nic_wqe_params *wqe_params)
{
	const struct hltests_nic_coll_comm_node_new *node;
	uint32_t wqe_param_conn_id;
	enum hltests_nic_coll_qp_type coll_qp_type;
	int64_t wqe_params_port;
	int rc;

	coll_qp_type = nic_common_get_coll_qp_type(comm_group->params);

	/* Configure descriptor.
	 * We prepare descriptor for 1st node in mask, and push the same on all ports. This works
	 * because HW calculates offset for a given port using LAG/rank index.
	 */
	node = gaudi3_nic_coll_op_comm_group_get_member_new(comm_group, 0);
	assert_non_null(node);

	if (comm_group->params->cfg->coll_op != COLL_OP_MODE_LEGACY)
		wqe_params_port = (uint32_t)__builtin_ffsll
				   ((int64_t)comm_group->params->cfg->ports_mask) - 1;
	else
		wqe_params_port = node->port_id;

	assert_in_range(wqe_params_port, 0, UINT_MAX);

	/* we need the connection id of the first enabled port to be passed to the function as
	 * we calculate the wqe params based on that port's WQE.
	 */
	wqe_param_conn_id = comm_group->params
			->coll_qps[coll_qp_type][wqe_params_port][comm_group->id]
			.conn_id;

	rc = gaudi3_nic_coll_group_prepare_wqe_params_new(comm_group,
							 (unsigned int)wqe_params_port,
							  wqe_param_conn_id, wqe_params);
	assert_int_equal(rc, 0);

	return 0;
}

static int coll_op_update_qp(struct hltests_nic_coll_comm_group *comm_group)
{
	int rc;

	rc = gaudi3_nic_coll_op_comm_group_update(comm_group, COLL_CMD_QP_BASE_UPDATE,
							NULL, comm_group->nodes_mask);
	assert_int_equal(rc, 0);

	rc = gaudi3_nic_coll_op_comm_group_update(comm_group, COLL_CMD_QP_OFFSET_UPDATE_LANE_0_1,
							NULL, comm_group->nodes_mask);
	assert_int_equal(rc, 0);

	if (NIC_IS_200_GBPS_MODE(comm_group->tests_state->fd, comm_group->nodes_mask)) {
		rc = gaudi3_nic_coll_op_comm_group_update(comm_group,
								COLL_CMD_QP_OFFSET_UPDATE_LANE_2_3,
								NULL, comm_group->nodes_mask);
		assert_int_equal(rc, 0);
	}

	return 0;
}

static int coll_op_update_qp_new(struct hltests_nic_coll_comm_group_new *comm_group)
{
	int rc;

	rc = gaudi3_nic_coll_op_comm_group_update_new(comm_group, COLL_CMD_QP_BASE_UPDATE, NULL,
						      comm_group->nodes_mask);
	assert_int_equal(rc, 0);

	rc = gaudi3_nic_coll_op_comm_group_update_new(
		comm_group, COLL_CMD_QP_OFFSET_UPDATE_LANE_0_1, NULL, comm_group->nodes_mask);
	assert_int_equal(rc, 0);

	if (NIC_IS_200_GBPS_MODE(comm_group->tests_state->fd, comm_group->nodes_mask)) {
		rc = gaudi3_nic_coll_op_comm_group_update_new(comm_group,
							      COLL_CMD_QP_OFFSET_UPDATE_LANE_2_3,
							      NULL, comm_group->nodes_mask);
		assert_int_equal(rc, 0);
	}

	return 0;
}

static int nic_run_coll_op(struct hltests_nic_coll_comm_group *comm_group)
{
	uint64_t rank0_rem_base_addr = 0;
	uint32_t rank_idx, rank_offset;
	struct coll_desc coll_desc_params = {};
	struct hltests_nic_wqe_params wqe_params = {};
	struct hltests_state *tests_state;
	struct hltests_nic_in_params *in_params;
	enum coll_desc_data_type coll_data_type;
	enum gaudi3_coll_cmd coll_cmd;
	int rc;
	bool is_direct_mode;

	tests_state = comm_group->tests_state;
	in_params = comm_group->in_params;
	is_direct_mode = in_params->coll_type == COLL_TYPE_DIRECT;

	if (!is_direct_mode) {
		/* Enable all ports of communication group. */
		rc = gaudi3_nic_coll_op_comm_group_update(comm_group, COLL_CMD_ENABLE_UPDATE, NULL,
								comm_group->nodes_mask);
		assert_int_equal(rc, 0);

		/* Set QP base and offset for each port in communication group. */
		rc = coll_op_update_qp(comm_group);
		assert_int_equal(rc, 0);
	}

	coll_cmd = coll_get_cmd_desc_from_cfg(comm_group);
	assert_true(coll_cmd < COLL_CMD_MAX);

	rc = coll_op_fill_wqe(comm_group, coll_cmd, &wqe_params);
	assert_int_equal(rc, 0);

	rc = gaudi3_nic_coll_group_fill_coll_desc(comm_group, coll_cmd, comm_group->id, &wqe_params,
							&coll_desc_params);
	assert_int_equal(rc, 0);
	assert_true(wqe_params.reduction_cfg <= UINT32_MAX);

	/* TEST_OPCODE_LINEAR_WRITE and TEST_OPCODE_RENDEZVOUS_READ use the same descriptor.
	 * This type of descriptor requires to update the remote address per rank.
	 * Here we save the remote address of the first rank and will use it as a base for the
	 * calculation per rank.
	 */
	if ((comm_group->in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) ||
				(comm_group->in_params->test_opcode == TEST_OPCODE_LINEAR_WRITE))
		rank0_rem_base_addr = coll_desc_params.write.rem_base_addr;

	assert_true(comm_group->n_ranks <= INT_MAX);
	for (rank_idx = 0 ; rank_idx < comm_group->n_ranks; rank_idx++) {
		rc = coll_op_update_rank(comm_group, (int)rank_idx,
					 rank_idx == comm_group->n_ranks - 1);
		assert_int_equal(rc, 0);

		/* Here we calculate the remote address per rank using the base address which was
		 * saved before this loop.
		 */
		if (!comm_group->in_params->disregard_rank &&
		    ((comm_group->in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) ||
		    (comm_group->in_params->test_opcode == TEST_OPCODE_LINEAR_WRITE))) {
			coll_data_type = gaudi3_map_coll_data_type(comm_group->in_params->coll_dt);

			rc = get_coll_op_data_size(coll_data_type,
						   (uint32_t)wqe_params.reduction_cfg);

			assert_false(rc < 0);

			rank_offset = coll_desc_params.write.stride_between_ranks * rank_idx *
				      (uint32_t)rc;

			coll_desc_params.write.rem_base_addr = rank0_rem_base_addr + rank_offset;
		}

		rc = gaudi3_nic_coll_op_comm_group_update(comm_group, coll_cmd,
								&coll_desc_params,
								comm_group->nodes_mask);
		assert_int_equal(rc, 0);

		if (!is_direct_mode) {
			/* Trigger collective operation. */
			rc = gaudi3_nic_coll_op_comm_group_update(comm_group, COLL_CMD_EXECUTE,
									NULL,
									comm_group->nodes_mask);
			assert_int_equal(rc, 0);
		}
	}

	return 0;
}

static int nic_run_coll_op_new(struct hltests_nic_coll_comm_group_new *comm_group)
{
	uint64_t rank0_rem_base_addr = 0;
	uint32_t rank_idx, rank_offset;
	struct coll_desc coll_desc_params = {};
	struct hltests_nic_wqe_params wqe_params = {};
	struct hltests_state *tests_state;
	const struct hltests_nic_test_params *params;
	enum coll_desc_data_type coll_data_type;
	enum gaudi3_coll_cmd coll_cmd;
	int rc;
	bool is_direct_mode;

	tests_state = comm_group->tests_state;
	params = comm_group->params;
	is_direct_mode = params->cfg->coll_type == COLL_TYPE_DIRECT;

	if (!is_direct_mode) {
		/* Enable all ports of communication group. */
		rc = gaudi3_nic_coll_op_comm_group_update_new(comm_group, COLL_CMD_ENABLE_UPDATE,
							      NULL, comm_group->nodes_mask);
		assert_int_equal(rc, 0);

		/* Set QP base and offset for each port in communication group. */
		rc = coll_op_update_qp_new(comm_group);
		assert_int_equal(rc, 0);
	}

	coll_cmd = coll_get_cmd_desc_from_cfg_new(comm_group);
	assert_true(coll_cmd < COLL_CMD_MAX);

	rc = coll_op_fill_wqe_new(comm_group, coll_cmd, &wqe_params);
	assert_int_equal(rc, 0);

	rc = gaudi3_nic_coll_group_fill_coll_desc_new(comm_group, coll_cmd, comm_group->id,
						      &wqe_params, &coll_desc_params);
	assert_int_equal(rc, 0);
	assert_true(wqe_params.reduction_cfg <= UINT32_MAX);

	/* TEST_OPCODE_LINEAR_WRITE and TEST_OPCODE_RENDEZVOUS_READ use the same descriptor.
	 * This type of descriptor requires to update the remote address per rank.
	 * Here we save the remote address of the first rank and will use it as a base for the
	 * calculation per rank.
	 */
	if ((comm_group->params->cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) ||
	    (comm_group->params->cfg->test_opcode == TEST_OPCODE_LINEAR_WRITE))
		rank0_rem_base_addr = coll_desc_params.write.rem_base_addr;

	for (rank_idx = 0; rank_idx < comm_group->n_ranks; rank_idx++) {
		rc = coll_op_update_rank_new(comm_group, uint_to_int_safe(rank_idx),
					     rank_idx == comm_group->n_ranks - 1);
		assert_int_equal(rc, 0);

		/* Here we calculate the remote address per rank using the base address which was
		 * saved before this loop.
		 */
		if (!comm_group->params->cfg->disregard_rank &&
		    ((comm_group->params->cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) ||
		     (comm_group->params->cfg->test_opcode == TEST_OPCODE_LINEAR_WRITE))) {
			coll_data_type = gaudi3_map_coll_data_type
						(comm_group->params->cfg->coll_data_type);
			rank_offset = coll_desc_params.write.stride_between_ranks * rank_idx *
				      (uint32_t)get_coll_op_data_size(coll_data_type,
								      (uint32_t)
								       wqe_params.reduction_cfg);

			coll_desc_params.write.rem_base_addr = rank0_rem_base_addr + rank_offset;
		}

		rc = gaudi3_nic_coll_op_comm_group_update_new(
			comm_group, coll_cmd, &coll_desc_params, comm_group->nodes_mask);
		assert_int_equal(rc, 0);

		if (!is_direct_mode) {
			/* Trigger collective operation. */
			rc = gaudi3_nic_coll_op_comm_group_update_new(comm_group, COLL_CMD_EXECUTE,
								      NULL, comm_group->nodes_mask);
			assert_int_equal(rc, 0);
		}
	}

	return 0;
}

static int gaudi3_nic_run_coll_op(void *comm_group)
{
	return nic_run_coll_op(comm_group);
}

static int gaudi3_nic_run_coll_op_new(struct hltests_nic_coll_comm_group_new *comm_group)
{
	return nic_run_coll_op_new(comm_group);
}

static uint32_t gaudi3_nic_get_min_coll_conn_id(int fd, bool is_scale_out)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;
	uint32_t first_en_port;

	first_en_port = (uint32_t)__builtin_ffsll((int64_t)gaudi3->nic_ports_mask) - 1;
	assert_in_range_ret_val(first_en_port, 0, NIC_MAX_NUM_OF_PORTS - 1, (uint32_t)-1);

	return is_scale_out ?
		gaudi3->base_scale_out_coll_qp_idx[first_en_port] :
		gaudi3->base_coll_qp_idx[first_en_port];
}

static uint32_t gaudi3_nic_get_max_coll_conn_id(int fd, bool is_scale_out)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;
	uint32_t first_en_port;

	first_en_port = (uint32_t)__builtin_ffsll((int64_t)gaudi3->nic_ports_mask) - 1;
	assert_in_range_ret_val(first_en_port, 0, NIC_MAX_NUM_OF_PORTS - 1, (uint32_t)-1);

	return is_scale_out ?
		gaudi3->base_scale_out_coll_qp_idx[first_en_port] +
			gaudi3->max_num_of_scale_out_coll_qps[first_en_port] - 1 :
		gaudi3->base_coll_qp_idx[first_en_port] +
			gaudi3->max_num_of_coll_qps[first_en_port] - 1;
}

static uint32_t gaudi3_nic_get_coll_qps_offset(int fd, uint32_t port)
{
	struct hltests_device *hdev;
	struct gaudi3_priv *gaudi3;

	hdev = get_hdev_from_fd(fd);
	gaudi3 = hdev->priv;

	return gaudi3->coll_qps_offset[port];
}

static uint32_t gaudi3_nic_get_max_num_of_coll_qps(int fd, bool is_scale_out)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi3_priv *gaudi3 = hdev->priv;
	uint32_t first_en_port;

	first_en_port = (uint32_t)__builtin_ffsll((int64_t)gaudi3->nic_ports_mask) - 1;
	assert_in_range_ret_val(first_en_port, 0, NIC_MAX_NUM_OF_PORTS - 1, (uint32_t)-1);

	return is_scale_out ? gaudi3->max_num_of_scale_out_coll_qps[first_en_port] :
				gaudi3->max_num_of_coll_qps[first_en_port];
}

uint32_t gaudi3_nic_get_db_fifo_entry_size(void)
{
	return GAUDI3_DB_FIFO_ENTRY_SIZE;
}

static void gaudi3_monitor_dma_test_progress(struct monitor_dma_test *params)
{
	uint64_t full_src_addr, full_dst_addr;
	uint32_t addr_lo, addr_hi, ch_idx;
	struct pdma_ch_info *ch_info;
	struct hltests_device *hdev;
	struct timespec ts;
	uint8_t *reg_addr;
	int rc, fd;

	pthread_mutex_lock(&params->mutex);

	fd = params->fd;
	hdev = get_hdev_from_fd(fd);
	ch_idx = PDMA_CH_ID(params->qid);
	ch_info = &hdev->pdma_db.ch_info[ch_idx];

	while (true) {

		reg_addr = ch_info->ch_host_addr + CTX_SRC_BASE_LO_OFFSET;
		rc = hltests_read_lbw_reg(fd, reg_addr, &addr_lo);
		if (rc) {
			print_and_flush("hltests_read_lbw_reg failed: %d (CTX_SRC_BASE_LO)\n", rc);
			break;
		}

		reg_addr = ch_info->ch_host_addr + CTX_SRC_BASE_HI_OFFSET;
		rc = hltests_read_lbw_reg(fd, reg_addr, &addr_hi);
		if (rc) {
			print_and_flush("hltests_read_lbw_reg failed: %d (CTX_SRC_BASE_HI)\n", rc);
			break;
		}

		full_src_addr = ((uint64_t)addr_hi << 32) | addr_lo;

		reg_addr = ch_info->ch_host_addr + CTX_DST_BASE_LO_OFFSET;
		rc = hltests_read_lbw_reg(fd, reg_addr, &addr_lo);
		if (rc) {
			print_and_flush("hltests_read_lbw_reg failed: %d (CTX_DST_BASE_LO)\n", rc);
			break;
		}

		reg_addr = ch_info->ch_host_addr + CTX_DST_BASE_HI_OFFSET;
		rc = hltests_read_lbw_reg(fd, reg_addr, &addr_hi);
		if (rc) {
			print_and_flush("hltests_read_lbw_reg failed: %d (CTX_DST_BASE_HI)\n", rc);
			break;
		}

		full_dst_addr = ((uint64_t)addr_hi << 32) | addr_lo;

		print_with_ts_and_flush("DMA %u TX: %#lx -> %#lx\n",
					params->qid, full_src_addr, full_dst_addr);

		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += params->poll_interval_sec;
		rc = pthread_cond_timedwait(&params->cond, &params->mutex, &ts);
		if (rc == 0) {
			break;
		} else if (rc != ETIMEDOUT) {
			print_and_flush("condition timed wait error: %d\n", rc);
			break;
		}
	}
	pthread_mutex_unlock(&params->mutex);
}

static void gaudi3_nic_vrd_wqes_data_size(void *swqe)
{
	((struct sq_wqe *) swqe)->size = 0;
}

void gaudi3_nic_parse_eqe_qp_syndrome(uint32_t port, struct hlthunk_nic_eq_poll_out *eqe)
{
	uint8_t err_src, err_qpc_src, err_cause;
	char *synd_str;

	err_cause = GAUDI3_SYNDROME_CAUSE(eqe->ev_data);
	err_qpc_src = GAUDI3_SYNDROME_TYPE(eqe->ev_data);
	/* The error source by default is QPC */
	err_src = GAUDI3_SYNDROME_ERR_SRC_QPC;
	if (GAUDI3_SYNDROM_IS_RX(err_qpc_src)) {
		/* The error source is RX. now check if it generated by RXE or QPC */
		if (!GAUDI3_SYNDROME_CAUSE_IS_QPC(err_cause))
			err_src = GAUDI3_SYNDROME_ERR_SRC_RXE;
		else
			err_cause -= GAUDI3_ERR_CAUSE_QPC_SHIFT;

	} else if (GAUDI3_SYNDROM_IS_TX(err_qpc_src)) {
		/* The error source is TX. now check if it generated by TXE or QPC */
		if (!GAUDI3_SYNDROME_CAUSE_IS_QPC(err_cause))
			err_src = GAUDI3_SYNDROME_ERR_SRC_TXE;
		else
			err_cause -= GAUDI3_ERR_CAUSE_QPC_SHIFT;

	}

	if (err_src == GAUDI3_SYNDROME_ERR_SRC_RXE)
		if (err_cause >= ARRAY_SIZE(qp_err_rxe_strs))
			synd_str = "Unknown Syndrome - Out of bounds";
		else
			synd_str = (char *)qp_err_rxe_strs[err_cause];
	else if (err_src == GAUDI3_SYNDROME_ERR_SRC_QPC)
		if (err_cause >= ARRAY_SIZE(qp_err_qpc_strs[err_qpc_src]))
			synd_str = "Unknown Syndrome - Out of bounds";
		else
			synd_str = (char *)qp_err_qpc_strs[err_qpc_src][err_cause];
	else
		synd_str = (char *)qp_err_txe_strs[err_cause];

	printf("Port: %d Got QP-error event: QP:%d, err (%d): %s: %s\n",
		port, eqe->idx, err_cause, qp_err_eng_src_strs[err_src], synd_str);
}

static uint32_t gaudi3_nic_read_mem_cmpl(int fd, uint32_t idx, uint8_t *blk)
{
	uint32_t reg_val = 0, reg_offset, *reg_ptr;
	int rc;

	reg_offset = (uint32_t)(mmSOB_OBJS_MON_PAY_ADDRL_1_0 - mmSOB_OBJS_SOB_OBJ_1_0 +
			idx * sizeof(uint32_t));

	/* Read MON_PAY_ADDR[LH] DCORE1 */
	reg_ptr = (void *) (blk + reg_offset);
	rc = hltests_read_lbw_reg(fd, reg_ptr, &reg_val);
	if (rc) {
		errno = EINVAL;
		E("Cannot read NIC memory completion register %p", (void *)reg_ptr);

		return 0;
	}

	return reg_val;
}

static uint32_t gaudi3_nic_get_mem_cmpl_addr(int fd, uint32_t idx)
{
	uint32_t reg_offset;

	reg_offset = (uint32_t)(mmSOB_OBJS_MON_PAY_ADDRL_1_0 - mmSOB_OBJS_SOB_OBJ_1_0 +
			idx * sizeof(uint32_t));

	return (mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_SOB_OBJ_1_0 + HDCORE_OFFSET + reg_offset) &
			GAUDI3_MEM_CMPL_ADDR_OFF_MASK;
}

static uint8_t *gaudi3_nic_map_lbw_block(int fd, uint32_t *sm_obj_size)
{
	return hltests_map_hw_block(fd,
			mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_SOB_OBJ_1_0 + HDCORE_OFFSET,
			sm_obj_size);
}

static int gaudi3_nic_unmap_lbw_block(int fd, void *host_addr, uint32_t block_size)
{
	return hltests_unmap_hw_block(fd, host_addr, block_size);
}

void gaudi3_mme_dma_set_tensor(int fd, uint8_t mme_idx, void *cb,
				uint32_t *cb_size, struct hltests_pkt_info *pkt,
				bool cout_tensor)
{
	uint64_t b = mme_idx * MME_OFFSET;
	uint32_t a = cout_tensor ? TEN_COUT_OFFSET : 0;

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_VALID_ELEMENTS_0 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_VALID_ELEMENTS_1 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_VALID_ELEMENTS_2 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_VALID_ELEMENTS_3 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_VALID_ELEMENTS_4 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_LOOP_STRIDE_0 + a;
	pkt->msg_long.value = 0;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_LOOP_STRIDE_1 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_LOOP_STRIDE_2 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_LOOP_STRIDE_3 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_LOOP_STRIDE_4 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_ROI_SIZE_0 + a;
	pkt->msg_long.value = MME_DMA_SIZE / 2;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_ROI_SIZE_1 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_ROI_SIZE_2 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_ROI_SIZE_3 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_SPATIAL_STRIDES_0 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_SPATIAL_STRIDES_1 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_SPATIAL_STRIDES_2 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

	pkt->msg_long.address = b + mmHD0_MME_CTRL_LO_ARCH_DMA_TEN_A_BASE +
			mmMME_CTRL_LO_ARCH_DMA_TEN_A_SPATIAL_STRIDES_3 + a;
	pkt->msg_long.value = MME_DMA_SIZE;
	*cb_size = hltests_add_msg_long_pkt(fd, cb, *cb_size, pkt);

}

int gaudi3_mme_dma_init_single_mme(int fd, uint8_t mme_idx, uint32_t sob_id)
{

	uint64_t seq, base = mme_idx * MME_OFFSET;
	struct hltests_cs_chunk execute_arr[1];
	struct hltests_pkt_info pkt_info = {};
	uint32_t cb_size = 0;
	void *cb;
	int rc;

	cb = hltests_create_cb(fd, SZ_8K, EXTERNAL, 0);
	if (!cb)
		return -ENOMEM;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = hltests_get_dma_down_qid(fd, STREAM0);
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;

	pkt_info.msg_long.address = base + mmHD0_MME_CTRL_LO_ARCH_DMA_N_TEN_ST_BASE +
			mmMME_CTRL_LO_ARCH_DMA_N_TEN_ST_BRAINS_LO;
	pkt_info.msg_long.value = 0xc00000c0;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.msg_long.address = base + mmHD0_MME_CTRL_LO_ARCH_DMA_N_TEN_ST_BASE +
			mmMME_CTRL_LO_ARCH_DMA_N_TEN_ST_BRAINS_HI;
	pkt_info.msg_long.value = 0xc000;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.msg_long.address = base + mmHD0_MME_CTRL_LO_ARCH_DMA_N_TEN_ST_BASE +
			mmMME_CTRL_LO_ARCH_DMA_N_TEN_ST_HEADER_LO;
	pkt_info.msg_long.value = 0xcc412000;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.msg_long.address = base + mmHD0_MME_CTRL_LO_ARCH_DMA_N_TEN_ST_BASE +
			mmMME_CTRL_LO_ARCH_DMA_N_TEN_ST_HEADER_HI;
	pkt_info.msg_long.value = 0x50100145;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.msg_long.address = base + mmHD0_MME_CTRL_LO_ARCH_DMA_N_TEN_BASE +
			mmMME_CTRL_LO_ARCH_DMA_N_TEN_CONV_LO;
	pkt_info.msg_long.value = 0x00aa0028;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.msg_long.address = base + mmHD0_MME_CTRL_LO_ARCH_DMA_N_TEN_BASE +
			mmMME_CTRL_LO_ARCH_DMA_N_TEN_CONV_HI;
	pkt_info.msg_long.value = 0x012c00eb;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.msg_long.address = base + mmHD0_MME_CTRL_LO_ARCH_DMA_N_TEN_BASE +
			mmMME_CTRL_LO_ARCH_DMA_N_TEN_OUTER_LOOP;
	pkt_info.msg_long.value = 0x16d;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.msg_long.address = base +
			mmHD0_MME_CTRL_LO_ARCH_DMA_AGU_IN0_SLAVE_BASE +
			mmMME_CTRL_LO_ARCH_DMA_AGU_IN0_SLAVE_ROI_BASE_OFFSET_0;
	pkt_info.msg_long.value = MME_DMA_SIZE / 2;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.msg_long.address = base +
			mmHD0_MME_CTRL_LO_ARCH_DMA_AGU_COUT0_SLAVE_BASE +
			mmMME_CTRL_LO_ARCH_DMA_AGU_COUT0_SLAVE_ROI_BASE_OFFSET_0;
	pkt_info.msg_long.value = MME_DMA_SIZE / 2;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.msg_long.address = base + mmHD0_MME_CTRL_LO_ARCH_DMA_N_TEN_BASE +
			mmMME_CTRL_LO_ARCH_DMA_N_TEN_SO_CTRL;
	pkt_info.msg_long.value = 0x1bf7f;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.msg_long.address = base + mmHD0_MME_CTRL_LO_ARCH_DMA_N_TEN_BASE +
			mmMME_CTRL_LO_ARCH_DMA_N_TEN_SO_ADDR0;
	pkt_info.msg_long.value = 0xFE380000 + (sob_id * 4);
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.msg_long.address = base + mmHD0_MME_CTRL_LO_ARCH_DMA_N_TEN_BASE +
			mmMME_CTRL_LO_ARCH_DMA_N_TEN_SO_VAL0;
	pkt_info.msg_long.value = 0x80000001;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.msg_long.address = base + mmHD0_MME_CTRL_LO_BASE +
			mmMME_CTRL_LO_ARCH_DMA_B_SS;
	pkt_info.msg_long.value = 0xfff;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	gaudi3_mme_dma_set_tensor(fd, mme_idx, cb, &cb_size, &pkt_info, false);
	gaudi3_mme_dma_set_tensor(fd, mme_idx, cb, &cb_size, &pkt_info, true);

	pkt_info.msg_long.address =
			base + mmHD0_MME_CTRL_LO_ARCH_DMA_N_TEN_BASE +
					mmMME_CTRL_LO_ARCH_DMA_N_TEN_CONV_KERNEL_SIZE_MINUS_1;
	pkt_info.msg_long.value = 0;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	/* Enable mme trigger via msg long */
	pkt_info.msg_long.address = base + mmHD0_MME_CTRL_LO_BASE +
			mmMME_CTRL_LO_MISC;
	pkt_info.msg_long.value = 0x11F1F18;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	execute_arr[0].cb_ptr = cb;
	execute_arr[0].cb_size = cb_size;
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	return 0;
}

static int gaudi3_mme_dma_init(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	uint64_t cap_mask = hltests_get_capabilities_mask();
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t mme_cnt, mme_id;
	uint16_t sob_id;
	int rc;

	if (!hdev->module_params.mme_enable)
		return 0;

	if (!(cap_mask & CAP_MME_DMA_MASK))
		return 0;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	mme_cnt = hltests_get_mme_cnt(fd, hw_ip.mme_master_slave_mode);

	for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++) {
		if (!(hw_ip.mme_enabled_mask & (0x1ULL << mme_id)))
			continue;

		sob_id = hltests_get_first_avail_sob(fd);
		hdev->counters.reserved_sobs++;
		rc = gaudi3_mme_dma_init_single_mme(fd, mme_id, sob_id);
		assert_int_equal(rc, 0);
		hdev->mme_dma_info.sob_id[mme_id] = sob_id;
		hdev->mme_dma_info.mon_id[mme_id] = hltests_get_first_avail_mon(fd);
		hdev->counters.reserved_mons++;
	}

	hdev->mme_dma_info.enable = true;
	return 0;
}

static uint32_t gaudi3_add_mme_dma_pkt(int fd, void *cb, uint32_t cb_size, uint64_t src,
					uint64_t dst, uint32_t qid)
{
	struct hltests_pkt_info pkt_info;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid;
	/* In case of multiple MME requests, we need to verify that the command has been triggered
	 * before updating the source and destination addresses.
	 */
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;

	pkt_info.wreg32.reg_addr = ((mmHD0_MME_CTRL_LO_ARCH_DMA_BASE_ADDR_BASE +
			mmMME_CTRL_LO_ARCH_DMA_BASE_ADDR_A_LO) & 0xFFFF);
	pkt_info.wreg32.value = lower_32_bits(src);
	cb_size = hltests_add_wreg32_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.eb = EB_FALSE;

	pkt_info.wreg32.reg_addr = ((mmHD0_MME_CTRL_LO_ARCH_DMA_BASE_ADDR_BASE +
			mmMME_CTRL_LO_ARCH_DMA_BASE_ADDR_A_HI) & 0xFFFF);
	pkt_info.wreg32.value = upper_32_bits(src);
	cb_size = hltests_add_wreg32_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.wreg32.reg_addr = ((mmHD0_MME_CTRL_LO_ARCH_DMA_BASE_ADDR_BASE +
			mmMME_CTRL_LO_ARCH_DMA_BASE_ADDR_COUT0_LO) & 0xFFFF);
	pkt_info.wreg32.value = lower_32_bits(dst);
	cb_size = hltests_add_wreg32_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.wreg32.reg_addr = ((mmHD0_MME_CTRL_LO_ARCH_DMA_BASE_ADDR_BASE +
			mmMME_CTRL_LO_ARCH_DMA_BASE_ADDR_COUT0_HI) & 0xFFFF);
	pkt_info.wreg32.value = upper_32_bits(dst);
	cb_size = hltests_add_wreg32_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.wreg32.reg_addr = ((mmHD0_MME_CTRL_LO_BASE + mmMME_CTRL_LO_CMD) & 0xFFFF);
	pkt_info.wreg32.value = 0x21ff;
	cb_size = hltests_add_wreg32_pkt(fd, cb, cb_size, &pkt_info);

	return cb_size;
}

static uint32_t gaudi3_get_mme_dma_cb_size(int fd, int num_of_lindma_pkts, uint32_t size)
{
	/* MME DMA request is not a regular packet, but a batch of them, hence need to calculate
	 * mme dma packet size for basic dma request
	 */
	void *temp_cb = hltests_create_cb(fd, 2 * MME_DMA_SIZE, EXTERNAL, 0);
	uint64_t dma_pkt_size;
	int rc;

	assert_true_ret_val(num_of_lindma_pkts >= 0, 0);
	assert_non_null_ret_val(temp_cb, 0);
	dma_pkt_size = hltests_prepare_mme_dma_req(fd, temp_cb, 0, 0, 0, 0, MME_DMA_SIZE);
	rc = hltests_destroy_cb(fd, temp_cb);
	assert_int_equal_ret_val(rc, 0, 0);

	return u32_safe_ret_val(
			((uint32_t)num_of_lindma_pkts * dma_pkt_size * size / MME_DMA_SIZE) +
				(uint32_t)SZ_4K, 0);
}

uint32_t gaudi3_prepare_mme_dma_req(int fd, void *cb, uint32_t cb_size, uint64_t src, uint64_t dst,
				uint8_t mme_idx, uint64_t size)
{
	uint32_t qid = gaudi3_get_mme_qid(0, mme_idx, 0), pkts_num = 0, cb_size_org = cb_size;
	struct hltests_monitor_and_fence mon_and_fence_info;
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hltests_pkt_info pkt_info;

	if (size % MME_DMA_SIZE != 0) {
		printf("Error: mme dma size %#"PRIx64" must be multiplication of %u\n",
			size, MME_DMA_SIZE);
		return 0;
	}

	/* Need to clear the SOB from previous operations */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.value = 0;
	pkt_info.write_to_sob.mode = SOB_SET;
	pkt_info.write_to_sob.sob_id = hdev->mme_dma_info.sob_id[mme_idx];
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

	while (size) {
		cb_size = gaudi3_add_mme_dma_pkt(fd, cb, cb_size, src, dst, qid);
		size -= MME_DMA_SIZE;
		src += MME_DMA_SIZE;
		dst += MME_DMA_SIZE;
		pkts_num++;
	}

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = u8_safe_ret_val(qid, cb_size_org);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = hdev->mme_dma_info.sob_id[mme_idx];
	mon_and_fence_info.mon_id = hdev->mme_dma_info.mon_id[mme_idx];
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = pkts_num;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	mon_and_fence_info.mon_mode = SOB_EQUAL;
	cb_size = hltests_add_monitor_and_fence(fd, cb, cb_size, &mon_and_fence_info);

	return cb_size;
}

int gaudi3_mme_dma(int fd, uint64_t src, uint64_t dst, uint8_t mme_idx, uint64_t size)
{
	uint32_t qid = gaudi3_get_mme_qid(0, mme_idx, 0);
	uint32_t alloc_size, cb_size = 0;
	uint64_t seq;
	void *cb;
	int rc;

	alloc_size = gaudi3_get_mme_dma_cb_size(fd, 1, u32_safe_ret_val(size, -E2BIG));
	cb = hltests_create_cb(fd, alloc_size, EXTERNAL, 0);
	if (!cb)
		return -ENOMEM;

	cb_size = gaudi3_prepare_mme_dma_req(fd, cb, cb_size, src, dst, mme_idx, size);
	assert_int_not_equal(cb_size, 0);

	rc = hltests_submit_cb(fd, cb, cb_size, qid, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	return 0;
}

static uint16_t gaudi3_cq_db_get_available_sob(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	uint32_t sob = hdev->cq_db_counters.reserved_sobs + NUM_OF_SOBS_IN_BATCH;

	assert_true_ret_val(sob <= UINT16_MAX, UINT16_MAX);
	hdev->cq_db_counters.reserved_sobs++;

	return (uint16_t)sob;
}

static uint16_t gaudi3_cq_db_get_available_mon(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	uint32_t mon =  hdev->cq_db_counters.reserved_mons + NUM_OF_MONITORS_IN_BATCH;

	assert_true_ret_val(mon <= UINT16_MAX, UINT16_MAX);
	hdev->cq_db_counters.reserved_mons++;

	return (uint16_t)mon;
}

static uint16_t gaudi3_cq_db_get_available_cq(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	uint32_t cq =  hdev->cq_db_counters.reserved_cqs + NUM_OF_CQS_IN_SM;

	assert_true_ret_val(cq <= UINT16_MAX, UINT16_MAX);
	hdev->cq_db_counters.reserved_cqs++;

	return (uint16_t)cq;
}

static uint64_t gaudi3_nic_get_half_port_mask(int fd, uint64_t port_mask, bool is_upper_half)
{
	uint32_t max_n_ports, max_n_half_of_ports;
	uint64_t half_port_mask;
	bool is_400_gbps;

	max_n_ports = (uint32_t)gaudi3_nic_get_max_num_of_ports();
	is_400_gbps = !NIC_IS_200_GBPS_MODE(fd, port_mask);
	max_n_half_of_ports = max_n_ports >> (is_400_gbps + 1);
	half_port_mask = BIT(max_n_half_of_ports) - 1;

	if (is_upper_half)
		half_port_mask <<= max_n_half_of_ports;

	return port_mask & half_port_mask;
}

static uint32_t gaudi3_add_cq_db_set_cq_queue_pkt(void *buffer, uint32_t buf_off,
		struct hltests_cq_config *cq_config, uint16_t sob_id)
{
	struct hltests_pkt_info pkt_info = {};
	uint64_t offset, sob_addr;

	pkt_info.qid = cq_config->qid;
	/* CQ in hdcore 0 */
	if (cq_config->cq_id  < NUM_OF_CQS_IN_SM) {
		printf("Error CQ for completion mechanism must be on hdcore1\n");
		return 0;

	} else {/* CQ in hdcore 1 */
		offset = HDCORE_OFFSET + ((cq_config->cq_id  - NUM_OF_CQS_IN_SM) * 4ULL);
		sob_addr = mmHD0_SYNC_MNGR_OBJS_BASE + mmSOB_OBJS_SOB_OBJ_0_0 + HDCORE_OFFSET +
				((sob_id - NUM_OF_SOBS_IN_BATCH) * 4ULL);
	}


	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;

	/* Configure CQ Address */
	pkt_info.msg_long.value = lower_32_bits(cq_config->cq_address);
	pkt_info.msg_long.address =
			mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_CQ_BASE_ADDR_L_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = upper_32_bits(cq_config->cq_address);
	pkt_info.msg_long.address =
			mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_CQ_BASE_ADDR_H_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = cq_config->cq_size_log2;
	pkt_info.msg_long.address =
			mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_CQ_SIZE_LOG2_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	/* Configure CQ LBW Address */
	pkt_info.msg_long.value = lower_32_bits(sob_addr);
	pkt_info.msg_long.address =
			mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_LBW_ADDR_L_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = upper_32_bits(sob_addr);
	pkt_info.msg_long.address =
			mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_LBW_ADDR_H_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = 0x80000001;
	pkt_info.msg_long.address =
			mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_LBW_DATA_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	/* Configure CQ mode - “0”: 32 bits, “1”: 64 bits with data increment */
	pkt_info.msg_long.value = !!cq_config->inc_mode ? 0x1 : 0x0;
	pkt_info.msg_long.address =
			mmHD0_SYNC_MNGR_GLBL_BASE + mmSOB_GLBL_CQ_INC_MODE_0 + offset;
	buf_off = gaudi3_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	return buf_off;
}

static void gaudi3_nic_clear_lbw_memory(int fd, uint8_t *sm_obj_base, uint32_t idx,
					uint32_t num_elements)
{
	uint32_t reg_offset, *reg_ptr, i;

	for (i = 0 ; i < num_elements ; i++) {
		reg_offset = (uint32_t)(mmSOB_OBJS_MON_PAY_ADDRL_1_0 - mmSOB_OBJS_SOB_OBJ_1_0 +
				((i + idx) * sizeof(uint32_t)));
		reg_ptr = (void *) (sm_obj_base + reg_offset);
		hltests_write_lbw_reg(fd, reg_ptr, 0);
	}
}

static void gaudi3_nic_fill_bp_offs_params(int fd, uint32_t port, uint32_t *bp_offs_base_id,
						uint32_t *num_bp_offs)
{
	struct hltests_device *hdev;
	struct gaudi3_priv *gaudi3;

	hdev = get_hdev_from_fd(fd);
	gaudi3 = hdev->priv;

	if (NIC_IS_200_GBPS_MODE(fd, BIT(port))) {
		*bp_offs_base_id = (port & 1) ? GAUDI3_NUM_MAX_BP_OFFS / 2 : 0;
		*num_bp_offs = GAUDI3_NUM_MAX_BP_OFFS / 2;
	} else {
		*bp_offs_base_id = 0;
		*num_bp_offs = GAUDI3_NUM_MAX_BP_OFFS;
	}
}

static uint64_t gaudi3_get_hbw_rr_addr(void)
{
	return 0ULL;
}

static uint64_t gaudi3_get_lbw_rr_addr(void)
{
	return mmD0_CPU_TIMESTAMP_BASE;
}

static uint64_t gaudi3_get_addr_dec_err_addr(void)
{
	/* point to the reserved area below the SRAM */
	return SRAM_BASE_ADDR - 0x8;
}

static uint64_t gaudi3_get_tpc_intr_cause_reg(uint32_t tpc_idx)
{
	uint32_t hdcore_id = tpc_idx / NUM_OF_TPC_PER_HDCORE;
	uint32_t tpc_id = tpc_idx % NUM_OF_TPC_PER_HDCORE;

	if (hdcore_id >= (NUM_OF_HDCORES_PER_DIE * MAX_NUM_OF_DIES))
		return ULONG_MAX;

	return mmHD0_TPC0_CFG_BASE + mmTPC_TPC_INTR_CAUSE_0 +
		(hdcore_id * HDCORE_OFFSET) +
		(tpc_id * (mmHD0_TPC1_CFG_BASE - mmHD0_TPC0_CFG_BASE));
}

static uint16_t gaudi3_qid_to_eid(uint16_t qid)
{
	return (qid < GAUDI3_ENGINE_ID_SIZE) ? qid : GAUDI3_ENGINE_ID_SIZE;
}

static uint64_t gaudi3_get_razwi_addr(enum err_trigger type)
{
	uint64_t addr;

	switch (type) {
	case RAZWI_TYPE_LBW_RR:
		addr = gaudi3_get_lbw_rr_addr();
		break;
	case RAZWI_TYPE_HBW_RR:
		addr = gaudi3_get_hbw_rr_addr();
		break;
	case RAZWI_TYPE_ADDR_DEC:
		addr = gaudi3_get_addr_dec_err_addr();
		break;
	default:
		addr = ULONG_MAX;
	}

	return addr;
}

static uint64_t gaudi3_get_pb_secured_addr(void)
{
	/* This address is secured as it's part of the PDMA CMN B block address space */
	return mmD0_SPDMA0_CMN_B_PQM_CMN_B_BASE + mmPDMA_CMN_B_PQM_CMN_B_DBG_CHANNEL_FILTER;
}

static int gaudi3_edp_get_engines_list(int fd, uint32_t **engine_ids, uint32_t *engine_ids_size)
{
	uint32_t engine_idx = 0, tpcs_max_num, mmes_max_num, edmas_max_num,
		tpcs_curr_num, mmes_curr_num, edmas_curr_num, i;
	struct hlthunk_hw_ip_info hw_ip;
	int rc = 0;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	if (rc)
		return rc;

	/* It's reasonable to assume that when it comes to Gaudi3, the list of engines for EDP
	 * test will always include the maximum possible number of engines.
	 */
	tpcs_max_num = gaudi3_get_tpc_cnt(fd, DCORE_MODE_FULL_CHIP);
	tpcs_curr_num = (uint32_t)__builtin_popcountll(hw_ip.tpc_enabled_mask_ext);
	if (tpcs_max_num != tpcs_curr_num) {
		printf("Number of enabled TPCs is %u, but should be %u!\n",
				tpcs_curr_num, tpcs_max_num);
		return -EINVAL;
	}

	mmes_max_num = gaudi3_get_mme_cnt(fd, DCORE_MODE_FULL_CHIP, hw_ip.mme_master_slave_mode);
	mmes_curr_num = (uint32_t)__builtin_popcount(hw_ip.mme_enabled_mask);
	if (mmes_max_num != mmes_curr_num) {
		printf("Number of enabled MMEs is %u, but should be %u!\n",
				mmes_curr_num, mmes_max_num);
		return -EINVAL;
	}

	edmas_max_num = gaudi3_get_edma_cnt(fd, DCORE_MODE_FULL_CHIP);
	edmas_curr_num = (uint32_t)__builtin_popcount(hw_ip.edma_enabled_mask);
	if (edmas_max_num != edmas_curr_num) {
		printf("Number of enabled EDMAs is %u, but should be %u!\n",
				edmas_curr_num, edmas_max_num);
		return -EINVAL;
	}

	*engine_ids_size = tpcs_curr_num + mmes_curr_num + edmas_curr_num;
	*engine_ids = hlthunk_malloc(*engine_ids_size * sizeof(uint32_t));
	if (!(*engine_ids)) {
		*engine_ids_size = 0;
		return -ENOMEM;
	}

	/* Fill-in the list with relevant engine ids */
	for (i = 0; i < tpcs_max_num; i++)
		(*engine_ids)[engine_idx++] = gaudi3_tpc_id_to_engine_id[i];

	for (i = 0; i < mmes_max_num; i++)
		(*engine_ids)[engine_idx++] = gaudi3_mme_id_to_engine_id[i];

	for (i = 0; i < edmas_max_num; i++)
		(*engine_ids)[engine_idx++] = gaudi3_edma_id_to_engine_id[i];

	return 0;
}

static uint64_t gaudi3_get_fw_mem_addr(uint64_t size)
{
	const uint64_t fw_mem_accessible_off = 0x3120000;

	if ((fw_mem_accessible_off + size) > FW_MEM_SIZE)
		return 0;

	return FW_MEM_BASE + fw_mem_accessible_off;
}

static uint32_t gaudi3_add_wreg32_pkt(void *buffer, uint32_t buf_off,
					struct hltests_pkt_info *pkt_info)
{
	struct packet_wreg32 packet;

	if (hltests_is_pdma_eid(pkt_info->qid)) {
		printf("Error: wreg32 packet for pqm is not currently supported\n");
		return buf_off;
	}

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_WREG_32;
	packet.reg_offset = pkt_info->wreg32.reg_addr;
	packet.value = pkt_info->wreg32.value;
	packet.eng_barrier = bitfield_safe_ret_val(pkt_info->eb, 1, buf_off);
	packet.msg_barrier = bitfield_safe_ret_val(pkt_info->mb, 1, buf_off);
	packet.pred = bitfield_safe_ret_val(pkt_info->pred, 5, buf_off);

	packet.ctl = htole32(packet.ctl);
	packet.value = htole32(packet.value);

	return hltests_add_packet_to_cb(buffer, buf_off, &packet,
			sizeof(packet));
}

static int gaudi3_nic_submit_dwq(struct hltests_nic_test_params *params)
{
	struct hltests_nic_db_fifo_packet dwq;
	struct hltests_nic_test_cfg *cfg;
	struct sq_wqe *swqe;
	struct rq_wqe *rwqe;
	struct hltests_nic_qp *qp_p;
	size_t qps_per_port, qp;
	uint32_t port, wq_size, wqe, pi, port_idx;
	int rc;

	cfg = params->cfg;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];
		qps_per_port = (uint32_t)params->num_qps_per_port[port];

		for (qp = 0 ; qp < qps_per_port ; qp++) {
			qp_p = &params->qps[port][qp];
			wq_size = qp_p->req_ctx.wq_size;

			for (pi = qp_p->curr_pi ; pi < qp_p->dest_pi ; pi++) {
				wqe = pi & (wq_size - 1);

				swqe = gaudi3_nic_get_swqe(qp_p->swq_buf, wqe);
				rwqe = gaudi3_nic_get_rwqe(qp_p->rwq_buf, wqe);

				rc = gaudi3_nic_create_dwq_packet(&dwq, swqe, rwqe,
						uint_to_int_safe_ret_val(qp_p->conn_id, -E2BIG));
				if (rc)
					return rc;

				rc = hltests_nic_submit_user_fifo(params, port, &dwq);

				hlthunk_free(dwq.packet);

				if (rc)
					return rc;
			}
		}
	}

	hltests_nic_print_time_elapsed(&params->base, "submit DWQ", cfg->verbose);

	return 0;
}

static int gaudi3_nic_submit_db(struct hltests_nic_test_params *params)
{
	return nic_common_generic_submit_user_fifo_db(params);
}

static void gaudi3_nic_write_desc_to_db_fifo(struct hltests_state *tests_state,
					     struct hltests_nic_db_fifo_data *db_fifo,
					     struct hltests_nic_db_fifo_packet *db_fifo_packet,
					     uint32_t port, bool is_dup)
{
	hltests_nic_write_desc_to_db_fifo_default(tests_state, db_fifo, db_fifo_packet, port,
						  is_dup);
}

static struct hltests_nic_asic_funcs gaudi3_nic_funcs = {
	.asic_priv_init = gaudi3_nic_asic_priv_init,
	.get_default_cfg = gaudi3_nic_get_default_cfg,
	.run_wtd = NULL,
	.run_coll_op = gaudi3_nic_run_coll_op,
	.run_coll_op_new = gaudi3_nic_run_coll_op_new,
	.get_max_num_of_ports = gaudi3_nic_get_max_num_of_ports,
	.get_port_mask = gaudi3_nic_get_port_mask,
	.get_base_qid = NULL,
	.get_wq_offset = gaudi3_nic_get_wq_offset,
	.fill_wqe = gaudi3_nic_fill_wqe,
	.get_swqe = gaudi3_nic_get_swqe,
	.get_rwqe = gaudi3_nic_get_rwqe,
	.get_swqe_size = gaudi3_nic_get_swqe_size,
	.get_rwqe_size = gaudi3_nic_get_rwqe_size,
	.get_max_pi = gaudi3_nic_get_max_pi,
	.get_min_conn_id = gaudi3_nic_get_min_conn_id,
	.get_max_conn_id = gaudi3_nic_get_max_conn_id,
	.get_max_num_of_qps = gaudi3_nic_get_max_num_of_qps,
	.get_min_coll_conn_id = gaudi3_nic_get_min_coll_conn_id,
	.get_max_coll_conn_id = gaudi3_nic_get_max_coll_conn_id,
	.get_coll_qps_offset = gaudi3_nic_get_coll_qps_offset,
	.get_max_num_of_coll_qps = gaudi3_nic_get_max_num_of_coll_qps,
	.pre_setup_ctx = gaudi3_nic_pre_setup_ctx,
	.pre_setup_default_ctx_rdv = gaudi3_nic_pre_setup_default_ctx_rdv,
	.setup_ctx_lpbk = gaudi3_nic_setup_ctx_lpbk,
	.setup_ctx_e2e = gaudi3_nic_setup_ctx_e2e,
	.setup_default_ctx_rdv = gaudi3_nic_setup_default_ctx_rdv,
	.get_user_cqe = gaudi3_nic_get_user_cqe,
	.user_cq_create = gaudi3_nic_user_cq_create,
	.user_cq_destroy = gaudi3_nic_user_cq_destroy,
	.add_bulk_doorbell_pkt = NULL,
	.get_db_fifo_umr = gaudi3_nic_get_db_fifo_umr,
	.get_db_fifo_dup = gaudi3_nic_get_db_fifo_dup,
	.get_db_fifo_entry_size = gaudi3_nic_get_db_fifo_entry_size,
	.get_db_fifo_element_size = gaudi3_nic_get_db_fifo_element_size,
	.get_hw_wq_pi = gaudi3_nic_get_hw_wq_pi,
	.config_reduction = gaudi3_nic_config_reduction,
	.clear_lbw_memory = gaudi3_nic_clear_lbw_memory,
	.create_dwq_packet = gaudi3_nic_create_dwq_packet,
	.parse_eqe_qp_syndrome = gaudi3_nic_parse_eqe_qp_syndrome,
	.read_mem_cmpl = gaudi3_nic_read_mem_cmpl,
	.get_mem_cmpl_addr = gaudi3_nic_get_mem_cmpl_addr,
	.map_lbw_block = gaudi3_nic_map_lbw_block,
	.unmap_lbw_block = gaudi3_nic_unmap_lbw_block,
	.get_half_port_mask = gaudi3_nic_get_half_port_mask,
	.fill_bp_offs_params = gaudi3_nic_fill_bp_offs_params,
	.ovrd_wqes_data_size = gaudi3_nic_vrd_wqes_data_size,
	.submit_wtd = gaudi3_nic_submit_dwq,
	.submit_db = gaudi3_nic_submit_db,
	.write_desc_to_db_fifo = gaudi3_nic_write_desc_to_db_fifo,
};

static const struct hltests_asic_funcs gaudi3_funcs = {
	.add_arb_en_pkt = NULL,
	.add_cq_config_pkt = gaudi3_add_cq_config_pkt,
	.add_pdma_ch_bw_config_pkt = gaudi3_add_pdma_ch_bw_config_pkt,
	.add_monitor_and_fence = gaudi3_add_monitor_and_fence,
	.add_monitor = gaudi3_add_monitor,
	.get_fence_addr = gaudi3_get_fence_addr,
	.add_nop_pkt = gaudi3_add_nop_pkt,
	.add_undef_opcode_pkt = gaudi3_add_undef_opcode_pkt,
	.add_msg_barrier_pkt = gaudi3_add_msg_barrier_pkt,
	.add_wreg32_pkt = gaudi3_add_wreg32_pkt,
	.add_arb_point_pkt = NULL,
	.add_msg_long_pkt = gaudi3_add_msg_long_pkt,
	.add_msg_short_pkt = gaudi3_add_msg_short_pkt,
	.add_arm_monitor_pkt = gaudi3_add_arm_monitor_pkt,
	.add_write_to_sob_pkt = gaudi3_add_write_to_sob_pkt,
	.add_fence_pkt = gaudi3_add_fence_pkt,
	.add_dma_pkt = gaudi3_add_dma_pkt,
	.add_cp_dma_pkt = NULL,
	.add_cb_list_pkt = NULL,
	.add_load_and_exe_pkt = NULL,
	.get_dma_down_qid = gaudi3_get_pdma_down_qid,
	.get_dma_up_qid = gaudi3_get_pdma_up_qid,
	.get_ddma_qid = gaudi3_get_edma_qid,
	.get_ddma_cnt = gaudi3_get_edma_cnt,
	.get_pdma_qid = gaudi3_get_pdma_qid,
	.get_pdma_ch_cnt = gaudi3_get_pdma_ch_cnt,
	.get_tpc_qid = gaudi3_get_tpc_qid,
	.get_mme_qid = gaudi3_get_mme_qid,
	.get_mme_id = gaudi3_get_mme_id,
	.get_nic_qid = NULL,
	.get_tpc_cnt = gaudi3_get_tpc_cnt,
	.get_mme_cnt = gaudi3_get_mme_cnt,
	.get_first_avail_sob = gaudi3_get_first_avail_sob,
	.get_first_avail_mon = gaudi3_get_first_avail_mon,
	.get_first_avail_cq = gaudi3_get_first_avail_cq,
	.get_sob_base_addr = gaudi3_get_sob_base_addr,
	.get_sob_lbw_offset = gaudi3_get_sob_lbw_offset,
	.get_lbw_base_addr = gaudi3_get_lbw_base_addr,
	.get_any_mappable_hw_block_base_addr = gaudi3_get_any_mappable_hw_block_base_addr,
	.get_cache_line_size = gaudi3_get_cache_line_size,
	.asic_priv_init = gaudi3_asic_priv_init,
	.asic_priv_fini = gaudi3_asic_priv_fini,
	.dram_pool_alloc = gaudi3_dram_pool_alloc,
	.dram_pool_free = gaudi3_dram_pool_free,
	.va_pool_alloc = gaudi3_va_pool_alloc,
	.va_pool_free = gaudi3_va_pool_free,
	.submit_cs = gaudi3_submit_cs,
	.wait_for_cs = gaudi3_wait_for_cs,
	.wait_for_cs_until_not_busy = gaudi3_wait_for_cs_until_not_busy,
	.get_max_pll_idx = gaudi3_get_max_pll_idx,
	.stringify_pll_idx = gaudi3_stringify_pll_idx,
	.stringify_pll_type = gaudi3_stringify_pll_type,
	.get_dram_va_hint_mask = gaudi3_get_dram_va_hint_mask,
	.get_dram_va_reserved_addr_start = gaudi3_get_dram_va_reserved_addr_start,
	.get_sob_id = NULL,
	.get_mon_cnt_per_dcore = NULL,
	.get_stream_master_qid_arr = NULL,
	.add_sched_arc_nop_cmd = NULL,
	.add_sched_arc_dispatch_static_ecb_list = NULL,
	.get_arc_cb_suffix_size = gaudi3_arc_get_cb_suffix_size,
	.arc_get_max_cpuid = gaudi3_get_arcs_num,
	.arc_get_va_range_host_start = gaudi3_get_arc_va_range_host_start,
	.arc_get_va_range_dram_start = gaudi3_get_arc_va_range_dram_start,
	.arc_get_sched_cpuid_range = gaudi3_arc_get_sched_cpuid_range,
	.arc_get_engine_cpuid_range = gaudi3_arc_get_engine_cpuid_range,
	.set_arc_asic_fw_load_params = gaudi3_set_arc_asic_fw_load_params,
	.asic_load_fw_to_arcs = gaudi3_asic_load_fw_to_arcs,
	.arc_set_asic_model = gaudi3_arc_set_asic_model,
	.arc_set_regions = gaudi3_arc_set_regions,
	.arc_set_config = gaudi3_arc_set_config,
	.arc_map_lbw_blocks = gaudi3_arc_map_lbw_blocks,
	.arc_get_num_schedulers = gaudi3_get_num_scheduler_arcs,
	.wait_arc_run_done = gaudi3_wait_arc_run_done,
	.arc_activate = gaudi3_arc_activate,
	.arc_unmap_lbw_blocks = gaudi3_arc_unmap_lbw_blocks,
	.arc_set_enabled_cores = gaudi3_arc_set_enabled_cores,
	.arc_configure_scheduler_streams = gaudi3_arc_configure_scheduler_streams,
	.pdma_get_max_ch_id = gaudi3_pdma_get_max_ch_id,
	.pdma_map_lbw_blocks = gaudi3_pdma_map_lbw_blocks,
	.pdma_unmap_lbw_blocks = gaudi3_pdma_unmap_lbw_blocks,
	.pdma_config_ch_blocks = gaudi3_pdma_config_ch_blocks,
	.arc_get_cpu_id_eng_group = gaudi3_arc_get_cpu_id_eng_group,
	.get_tc_base_addr = gaudi3_get_tc_base_addr,
	.get_async_event_id = NULL,
	.get_cq_patch_size = gaudi3_get_cq_patch_size,
	.get_max_pkt_size = gaudi3_get_max_pkt_size,
	.add_direct_write_cq_pkt = gaudi3_add_direct_write_cq_pkt,
	.monitor_dma_test_progress = gaudi3_monitor_dma_test_progress,
	.cq_db_get_available_sob = gaudi3_cq_db_get_available_sob,
	.cq_db_get_available_mon = gaudi3_cq_db_get_available_mon,
	.cq_db_get_available_cq = gaudi3_cq_db_get_available_cq,
	.add_cq_db_set_cq_queue_pkt = gaudi3_add_cq_db_set_cq_queue_pkt,
	.mme_dma_init = gaudi3_mme_dma_init,
	.prepare_mme_dma_req = gaudi3_prepare_mme_dma_req,
	.get_mme_dma_cb_size = gaudi3_get_mme_dma_cb_size,
	.get_razwi_addr = gaudi3_get_razwi_addr,
	.get_pb_secured_addr = gaudi3_get_pb_secured_addr,
	.get_fw_mem_addr = gaudi3_get_fw_mem_addr,
	.debug_completion = gaudi3_debug_completion,
	.edp_get_engines_list = gaudi3_edp_get_engines_list,
	.get_tpc_intr_cause_reg = gaudi3_get_tpc_intr_cause_reg,
	.qid_to_eid = gaudi3_qid_to_eid,
	.cause_page_fault_from_arc = gaudi3_cause_page_fault_from_arc,
	.nic_funcs = &gaudi3_nic_funcs,
};

void gaudi3_tests_set_asic_funcs(struct hltests_device *hdev)
{
	hdev->asic_funcs = &gaudi3_funcs;
}
