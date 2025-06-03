// SPDX-License-Identifier: MIT

/*
 * Copyright 2019-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "gaudi2/gaudi2.h"
#include "gaudi2/gaudi2_packets.h"
#include "gaudi2/gaudi2_nic.h"
#include "specs/hw_ip/nic/nic_v1_1.h"
#include "gaudi2/asic_reg/dcore0_sync_mngr_objs_masks.h"
#include "engines-arc/include/gaudi2/gaudi2_arc_common_packets.h"
#include "engines-arc/include/gaudi2/gaudi2_arc_host_packets.h"
#include "engines-arc/common/include/arc_host_packets.h"
#include "engines-arc/common/include/arc_sched_packets.h"
#include "gaudi2/gaudi2_async_events.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include <infiniband/hbldv.h>

#define DCORE_OFFSET (mmDCORE1_TPC0_CFG_TPC_COUNT - mmDCORE0_TPC0_CFG_TPC_COUNT)

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

#define SCHED_SOB_LBU_ADDR_OFFSET	(CFG_BASE + \
					SCHED_SOB_LBU_ADDR - \
					mmARC_FARM_ARC0_AUX_BASE)

#define SCHED_SOB_LBU_VALUE_OFFSET	(CFG_BASE + \
					SCHED_SOB_LBU_VALUE - \
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

#define SYNDROME_TYPE(syndrome)		(((syndrome) >> 6) & 0x3)
#define MAX_SYNDROM_STRING_LEN		256
#define MAX_SYNDROMS			0x100

#define GAUDI2_MEM_CMPL_ADDR_OFF_MASK	0x7FFFFFF

static char qp_syndroms[MAX_SYNDROMS][MAX_SYNDROM_STRING_LEN] = {
	/* Rx packet errors*/
	[0x1]  = "[RX] pkt err, pkt bad format",
	[0x2]  = "[RX] pkt err, pkt tunnel invalid",
	[0x3]  = "[RX] pkt err, BTH opcode invalid",
	[0x4]  = "[RX] pkt err, syndrome invalid",
	[0x5]  = "[RX] pkt err, Reliable QP max size invalid",
	[0x6]  = "[RX] pkt err, Reliable QP min size invalid",
	[0x7]  = "[RX] pkt err, Raw min size invalid",
	[0x8]  = "[RX] pkt err, Raw max size invalid",
	[0x9]  = "[RX] pkt err, QP invalid",
	[0xa]  = "[RX] pkt err, Transport Service mismatch",
	[0xb]  = "[RX] pkt err, QPC Requester QP state invalid",
	[0xc]  = "[RX] pkt err, QPC Responder QP state invalid",
	[0xd]  = "[RX] pkt err, QPC Responder resync invalid",
	[0xe]  = "[RX] pkt err, QPC Requester PSN invalid",
	[0xf]  = "[RX] pkt err, QPC Requester PSN unset",
	[0x10] = "[RX] pkt err, QPC Responder RKEY invalid",
	[0x11] = "[RX] pkt err, WQE index mismatch",
	[0x12] = "[RX] pkt err, WQE write opcode invalid",
	[0x13] = "[RX] pkt err, WQE Rendezvous opcode invalid",
	[0x14] = "[RX] pkt err, WQE Read  opcode invalid",
	[0x15] = "[RX] pkt err, WQE Write Zero",
	[0x16] = "[RX] pkt err, WQE multi zero",
	[0x17] = "[RX] pkt err, WQE Write send big",
	[0x18] = "[RX] pkt err, WQE multi big",

	/* QPC errors */
	[0x40] = "[qpc] [TMR] max-retry-cnt exceeded",
	[0x41] = "[qpc] [req DB] QP not valid",
	[0x42] = "[qpc] [req DB] security check",
	[0x43] = "[qpc] [req DB] PI > last-index",
	[0x44] = "[qpc] [req DB] wq-type is READ",
	[0x45] = "[qpc] [req TX] QP not valid",
	[0x46] = "[qpc] [req TX] Rendezvous WQE but wq-type is not WRITE",
	[0x47] = "[qpc] [req RX] QP not valid",
	[0x48] = "[qpc] [req RX] max-retry-cnt exceeded",
	[0x49] = "[qpc] [req RDV] QP not valid",
	[0x4a] = "[qpc] [req RDV] wrong wq-type",
	[0x4b] = "[qpc] [req RDV] PI > last-index",
	[0x4c] = "[qpc] [res TX] QP not valid",
	[0x4d] = "[qpc] [res RX] max-retry-cnt exceeded",

	/* tx packet error */
	[0x80] = "[TX] pkt error, QPC.wq_type is write does not support WQE.opcode",
	[0x81] = "[TX] pkt error, QPC.wq_type is rendezvous does not support WQE.opcode",
	[0x82] = "[TX] pkt error, QPC.wq_type is read does not support WQE.opcode",
	[0x83] = "[TX] pkt error, QPC.gaudi1 is set does not support WQE.opcode",
	[0x84] = "[TX] pkt error, WQE.opcode is write but WQE.size is 0",
	[0x85] =
		"[TX] pkt error, WQE.opcode is multi-stride|local-stride|multi-dual but WQE.size is 0",
	[0x86] = "[TX] pkt error, WQE.opcode is send but WQE.size is 0",
	[0x87] = "[TX] pkt error, WQE.opcode is rendezvous-write|rendezvous-read but WQE.size is 0",
	[0x88] = "[TX] pkt error, WQE.opcode is write but size > configured max-write-send-size",
	[0x89] =
		"[TX] pkt error, WQE.opcode is multi-stride|local-stride|multi-dual but size > configured max-stride-size",
	[0x8a] =
		"[TX] pkt error, WQE.opcode is rendezvous-write|rendezvous-read but QPC.remote_wq_log_size <= configured min-remote-log-size",
	[0x8b] =
		"[TX] pkt error, WQE.opcode is rendezvous-write but WQE.size != configured rdv-wqe-size (per granularity)",
	[0x8c] =
		"[TX] pkt error, WQE.opcode is rendezvous-read but WQE.size != configured rdv-wqe-size (per granularity)",
	[0x8d] =
		"[TX] pkt error, WQE.inline is set but WQE.size != configured inline-wqe-size (per granularity)",
	[0x8e] = "[TX] pkt error, QPC.gaudi1 is set but WQE.inline is set",
	[0x8f] =
		"[TX] pkt error, WQE.opcode is multi-stride|local-stride|multi-dual but QPC.swq_granularity is 0",
	[0x90] = "[TX] pkt error, WQE.opcode != NOP but WQE.reserved0 != 0",
	[0x91] = "[TX] pkt error, WQE.opcode != NOP but WQE.wqe_index != execution-index [7.0]",
	[0x92] =
		"[TX] pkt error, WQE.opcode is multi-stride|local-stride|multi-dual but WQE.size < stride-size",
	[0x93] =
		"[TX] pkt error, WQE.reduction_opcode is upscale but WQE.remote_address LSB is not 0",
	[0x94] = "[TX] pkt error, WQE.reduction_opcode is upscale but does not support WQE.opcode",
	[0x95] = "[TX] pkt error, RAW packet but WQE.size not supported",
	[0xA0] = "WQE.opcode is QoS but WQE.inline is set",
	[0xA1] = "WQE.opcode above 15",
	[0xA2] = "RAW above MIN",
	[0xA3] = "RAW below MAX",
	[0xA4] = "WQE.reduction is disable but reduction-opcode is not 0",
	[0xA5] = "WQE.opcode is READ-RDV but WQE.inline is set",
	[0xA7] = "WQE fetch WR size not 4",
	[0xA8] = "WQE fetch WR addr not mod4",
	[0xA9] = "RDV last-index",
	[0xAA] = "Gaudi1 multi-dual",
	[0xAB] = "WQE bad opcode",
	[0xAC] = "WQE bad size",
	[0xAD] = "WQE SE not RAW",
	[0xAE] = "Gaudi1 tunnal",
	[0xAF] = "Tunnel 0-size",
	[0xB0] = "Tunnel max size",
};

int gaudi2_tpc_id_to_engine_id[] = {
	GAUDI2_DCORE0_ENGINE_ID_TPC_0,
	GAUDI2_DCORE0_ENGINE_ID_TPC_1,
	GAUDI2_DCORE0_ENGINE_ID_TPC_2,
	GAUDI2_DCORE0_ENGINE_ID_TPC_3,
	GAUDI2_DCORE0_ENGINE_ID_TPC_4,
	GAUDI2_DCORE0_ENGINE_ID_TPC_5,
	GAUDI2_DCORE1_ENGINE_ID_TPC_0,
	GAUDI2_DCORE1_ENGINE_ID_TPC_1,
	GAUDI2_DCORE1_ENGINE_ID_TPC_2,
	GAUDI2_DCORE1_ENGINE_ID_TPC_3,
	GAUDI2_DCORE1_ENGINE_ID_TPC_4,
	GAUDI2_DCORE1_ENGINE_ID_TPC_5,
	GAUDI2_DCORE2_ENGINE_ID_TPC_0,
	GAUDI2_DCORE2_ENGINE_ID_TPC_1,
	GAUDI2_DCORE2_ENGINE_ID_TPC_2,
	GAUDI2_DCORE2_ENGINE_ID_TPC_3,
	GAUDI2_DCORE2_ENGINE_ID_TPC_4,
	GAUDI2_DCORE2_ENGINE_ID_TPC_5,
	GAUDI2_DCORE3_ENGINE_ID_TPC_0,
	GAUDI2_DCORE3_ENGINE_ID_TPC_1,
	GAUDI2_DCORE3_ENGINE_ID_TPC_2,
	GAUDI2_DCORE3_ENGINE_ID_TPC_3,
	GAUDI2_DCORE3_ENGINE_ID_TPC_4,
	GAUDI2_DCORE3_ENGINE_ID_TPC_5,
	GAUDI2_DCORE0_ENGINE_ID_TPC_6,
};

int gaudi2_mme_id_to_engine_id[] = {
	GAUDI2_DCORE0_ENGINE_ID_MME,
	GAUDI2_DCORE1_ENGINE_ID_MME,
	GAUDI2_DCORE2_ENGINE_ID_MME,
	GAUDI2_DCORE3_ENGINE_ID_MME,
};

int gaudi2_edma_id_to_engine_id[] = {
	GAUDI2_DCORE0_ENGINE_ID_EDMA_0,
	GAUDI2_DCORE0_ENGINE_ID_EDMA_1,
	GAUDI2_DCORE1_ENGINE_ID_EDMA_0,
	GAUDI2_DCORE1_ENGINE_ID_EDMA_1,
	GAUDI2_DCORE2_ENGINE_ID_EDMA_0,
	GAUDI2_DCORE2_ENGINE_ID_EDMA_1,
	GAUDI2_DCORE3_ENGINE_ID_EDMA_0,
	GAUDI2_DCORE3_ENGINE_ID_EDMA_1,
	GAUDI2_ENGINE_ID_PDMA_0,
	GAUDI2_ENGINE_ID_PDMA_1,
	GAUDI2_ENGINE_ID_KDMA,
};

static const uint64_t gaudi2_arc_blocks_bases[NUM_ARC_CPUS] = {
	[CPU_ID_SCHED_ARC0] = mmARC_FARM_ARC0_AUX_BASE,
	[CPU_ID_SCHED_ARC1] = mmARC_FARM_ARC1_AUX_BASE,
	[CPU_ID_SCHED_ARC2] = mmARC_FARM_ARC2_AUX_BASE,
	[CPU_ID_SCHED_ARC3] = mmARC_FARM_ARC3_AUX_BASE,
	[CPU_ID_SCHED_ARC4] = mmDCORE1_MME_QM_ARC_AUX_BASE,
	[CPU_ID_SCHED_ARC5] = mmDCORE3_MME_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC0] = mmDCORE0_TPC0_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC1] = mmDCORE0_TPC1_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC2] = mmDCORE0_TPC2_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC3] = mmDCORE0_TPC3_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC4] = mmDCORE0_TPC4_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC5] = mmDCORE0_TPC5_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC6] = mmDCORE1_TPC0_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC7] = mmDCORE1_TPC1_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC8] = mmDCORE1_TPC2_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC9] = mmDCORE1_TPC3_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC10] = mmDCORE1_TPC4_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC11] = mmDCORE1_TPC5_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC12] = mmDCORE2_TPC0_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC13] = mmDCORE2_TPC1_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC14] = mmDCORE2_TPC2_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC15] = mmDCORE2_TPC3_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC16] = mmDCORE2_TPC4_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC17] = mmDCORE2_TPC5_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC18] = mmDCORE3_TPC0_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC19] = mmDCORE3_TPC1_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC20] = mmDCORE3_TPC2_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC21] = mmDCORE3_TPC3_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC22] = mmDCORE3_TPC4_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC23] = mmDCORE3_TPC5_QM_ARC_AUX_BASE,
	[CPU_ID_TPC_QMAN_ARC24] = mmDCORE0_TPC6_QM_ARC_AUX_BASE,
	[CPU_ID_MME_QMAN_ARC0] = mmDCORE0_MME_QM_ARC_AUX_BASE,
	[CPU_ID_MME_QMAN_ARC1] = mmDCORE2_MME_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC0] = mmDCORE0_EDMA0_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC1] = mmDCORE0_EDMA1_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC2] = mmDCORE1_EDMA0_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC3] = mmDCORE1_EDMA1_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC4] = mmDCORE2_EDMA0_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC5] = mmDCORE2_EDMA1_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC6] = mmDCORE3_EDMA0_QM_ARC_AUX_BASE,
	[CPU_ID_EDMA_QMAN_ARC7] = mmDCORE3_EDMA1_QM_ARC_AUX_BASE,
	[CPU_ID_PDMA_QMAN_ARC0] = mmPDMA0_QM_ARC_AUX_BASE,
	[CPU_ID_PDMA_QMAN_ARC1] = mmPDMA1_QM_ARC_AUX_BASE,
	[CPU_ID_ROT_QMAN_ARC0] = mmROT0_QM_ARC_AUX_BASE,
	[CPU_ID_ROT_QMAN_ARC1] = mmROT1_QM_ARC_AUX_BASE,
	[CPU_ID_NIC_QMAN_ARC0] = mmNIC0_QM_ARC_AUX0_BASE,
	[CPU_ID_NIC_QMAN_ARC1] = mmNIC0_QM_ARC_AUX1_BASE,
	[CPU_ID_NIC_QMAN_ARC2] = mmNIC1_QM_ARC_AUX0_BASE,
	[CPU_ID_NIC_QMAN_ARC3] = mmNIC1_QM_ARC_AUX1_BASE,
	[CPU_ID_NIC_QMAN_ARC4] = mmNIC2_QM_ARC_AUX0_BASE,
	[CPU_ID_NIC_QMAN_ARC5] = mmNIC2_QM_ARC_AUX1_BASE,
	[CPU_ID_NIC_QMAN_ARC6] = mmNIC3_QM_ARC_AUX0_BASE,
	[CPU_ID_NIC_QMAN_ARC7] = mmNIC3_QM_ARC_AUX1_BASE,
	[CPU_ID_NIC_QMAN_ARC8] = mmNIC4_QM_ARC_AUX0_BASE,
	[CPU_ID_NIC_QMAN_ARC9] = mmNIC4_QM_ARC_AUX1_BASE,
	[CPU_ID_NIC_QMAN_ARC10] = mmNIC5_QM_ARC_AUX0_BASE,
	[CPU_ID_NIC_QMAN_ARC11] = mmNIC5_QM_ARC_AUX1_BASE,
	[CPU_ID_NIC_QMAN_ARC12] = mmNIC6_QM_ARC_AUX0_BASE,
	[CPU_ID_NIC_QMAN_ARC13] = mmNIC6_QM_ARC_AUX1_BASE,
	[CPU_ID_NIC_QMAN_ARC14] = mmNIC7_QM_ARC_AUX0_BASE,
	[CPU_ID_NIC_QMAN_ARC15] = mmNIC7_QM_ARC_AUX1_BASE,
	[CPU_ID_NIC_QMAN_ARC16] = mmNIC8_QM_ARC_AUX0_BASE,
	[CPU_ID_NIC_QMAN_ARC17] = mmNIC8_QM_ARC_AUX1_BASE,
	[CPU_ID_NIC_QMAN_ARC18] = mmNIC9_QM_ARC_AUX0_BASE,
	[CPU_ID_NIC_QMAN_ARC19] = mmNIC9_QM_ARC_AUX1_BASE,
	[CPU_ID_NIC_QMAN_ARC20] = mmNIC10_QM_ARC_AUX0_BASE,
	[CPU_ID_NIC_QMAN_ARC21] = mmNIC10_QM_ARC_AUX1_BASE,
	[CPU_ID_NIC_QMAN_ARC22] = mmNIC11_QM_ARC_AUX0_BASE,
	[CPU_ID_NIC_QMAN_ARC23] = mmNIC11_QM_ARC_AUX1_BASE,
};

const uint32_t gaudi2_engine_arc_queue_to_cpu_id[] = {
	[GAUDI2_QUEUE_ID_PDMA_0_0] = CPU_ID_PDMA_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_PDMA_0_1] = CPU_ID_PDMA_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_PDMA_0_2] = CPU_ID_PDMA_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_PDMA_0_3] = CPU_ID_PDMA_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_PDMA_1_0] = CPU_ID_PDMA_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_PDMA_1_1] = CPU_ID_PDMA_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_PDMA_1_2] = CPU_ID_PDMA_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_PDMA_1_3] = CPU_ID_PDMA_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_DCORE0_EDMA_0_0] = CPU_ID_EDMA_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_DCORE0_EDMA_0_1] = CPU_ID_EDMA_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_DCORE0_EDMA_0_2] = CPU_ID_EDMA_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_DCORE0_EDMA_0_3] = CPU_ID_EDMA_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_DCORE0_EDMA_1_0] = CPU_ID_EDMA_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_DCORE0_EDMA_1_1] = CPU_ID_EDMA_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_DCORE0_EDMA_1_2] = CPU_ID_EDMA_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_DCORE0_EDMA_1_3] = CPU_ID_EDMA_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_DCORE0_MME_0_0] = CPU_ID_MME_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_DCORE0_MME_0_1] = CPU_ID_MME_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_DCORE0_MME_0_2] = CPU_ID_MME_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_DCORE0_MME_0_3] = CPU_ID_MME_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_0_0] = CPU_ID_TPC_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_0_1] = CPU_ID_TPC_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_0_2] = CPU_ID_TPC_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_0_3] = CPU_ID_TPC_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_1_0] = CPU_ID_TPC_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_1_1] = CPU_ID_TPC_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_1_2] = CPU_ID_TPC_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_1_3] = CPU_ID_TPC_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_2_0] = CPU_ID_TPC_QMAN_ARC2,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_2_1] = CPU_ID_TPC_QMAN_ARC2,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_2_2] = CPU_ID_TPC_QMAN_ARC2,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_2_3] = CPU_ID_TPC_QMAN_ARC2,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_3_0] = CPU_ID_TPC_QMAN_ARC3,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_3_1] = CPU_ID_TPC_QMAN_ARC3,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_3_2] = CPU_ID_TPC_QMAN_ARC3,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_3_3] = CPU_ID_TPC_QMAN_ARC3,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_4_0] = CPU_ID_TPC_QMAN_ARC4,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_4_1] = CPU_ID_TPC_QMAN_ARC4,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_4_2] = CPU_ID_TPC_QMAN_ARC4,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_4_3] = CPU_ID_TPC_QMAN_ARC4,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_5_0] = CPU_ID_TPC_QMAN_ARC5,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_5_1] = CPU_ID_TPC_QMAN_ARC5,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_5_2] = CPU_ID_TPC_QMAN_ARC5,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_5_3] = CPU_ID_TPC_QMAN_ARC5,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_6_0] = CPU_ID_TPC_QMAN_ARC24,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_6_1] = CPU_ID_TPC_QMAN_ARC24,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_6_2] = CPU_ID_TPC_QMAN_ARC24,
	[GAUDI2_QUEUE_ID_DCORE0_TPC_6_3] = CPU_ID_TPC_QMAN_ARC24,
	[GAUDI2_QUEUE_ID_DCORE1_EDMA_0_0] = CPU_ID_EDMA_QMAN_ARC2,
	[GAUDI2_QUEUE_ID_DCORE1_EDMA_0_1] = CPU_ID_EDMA_QMAN_ARC2,
	[GAUDI2_QUEUE_ID_DCORE1_EDMA_0_2] = CPU_ID_EDMA_QMAN_ARC2,
	[GAUDI2_QUEUE_ID_DCORE1_EDMA_0_3] = CPU_ID_EDMA_QMAN_ARC2,
	[GAUDI2_QUEUE_ID_DCORE1_EDMA_1_0] = CPU_ID_EDMA_QMAN_ARC3,
	[GAUDI2_QUEUE_ID_DCORE1_EDMA_1_1] = CPU_ID_EDMA_QMAN_ARC3,
	[GAUDI2_QUEUE_ID_DCORE1_EDMA_1_2] = CPU_ID_EDMA_QMAN_ARC3,
	[GAUDI2_QUEUE_ID_DCORE1_EDMA_1_3] = CPU_ID_EDMA_QMAN_ARC3,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_0_0] = CPU_ID_TPC_QMAN_ARC6,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_0_1] = CPU_ID_TPC_QMAN_ARC6,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_0_2] = CPU_ID_TPC_QMAN_ARC6,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_0_3] = CPU_ID_TPC_QMAN_ARC6,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_1_0] = CPU_ID_TPC_QMAN_ARC7,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_1_1] = CPU_ID_TPC_QMAN_ARC7,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_1_2] = CPU_ID_TPC_QMAN_ARC7,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_1_3] = CPU_ID_TPC_QMAN_ARC7,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_2_0] = CPU_ID_TPC_QMAN_ARC8,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_2_1] = CPU_ID_TPC_QMAN_ARC8,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_2_2] = CPU_ID_TPC_QMAN_ARC8,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_2_3] = CPU_ID_TPC_QMAN_ARC8,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_3_0] = CPU_ID_TPC_QMAN_ARC9,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_3_1] = CPU_ID_TPC_QMAN_ARC9,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_3_2] = CPU_ID_TPC_QMAN_ARC9,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_3_3] = CPU_ID_TPC_QMAN_ARC9,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_4_0] = CPU_ID_TPC_QMAN_ARC10,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_4_1] = CPU_ID_TPC_QMAN_ARC10,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_4_2] = CPU_ID_TPC_QMAN_ARC10,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_4_3] = CPU_ID_TPC_QMAN_ARC10,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_5_0] = CPU_ID_TPC_QMAN_ARC11,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_5_1] = CPU_ID_TPC_QMAN_ARC11,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_5_2] = CPU_ID_TPC_QMAN_ARC11,
	[GAUDI2_QUEUE_ID_DCORE1_TPC_5_3] = CPU_ID_TPC_QMAN_ARC11,
	[GAUDI2_QUEUE_ID_DCORE2_EDMA_0_0] = CPU_ID_EDMA_QMAN_ARC4,
	[GAUDI2_QUEUE_ID_DCORE2_EDMA_0_1] = CPU_ID_EDMA_QMAN_ARC4,
	[GAUDI2_QUEUE_ID_DCORE2_EDMA_0_2] = CPU_ID_EDMA_QMAN_ARC4,
	[GAUDI2_QUEUE_ID_DCORE2_EDMA_0_3] = CPU_ID_EDMA_QMAN_ARC4,
	[GAUDI2_QUEUE_ID_DCORE2_EDMA_1_0] = CPU_ID_EDMA_QMAN_ARC5,
	[GAUDI2_QUEUE_ID_DCORE2_EDMA_1_1] = CPU_ID_EDMA_QMAN_ARC5,
	[GAUDI2_QUEUE_ID_DCORE2_EDMA_1_2] = CPU_ID_EDMA_QMAN_ARC5,
	[GAUDI2_QUEUE_ID_DCORE2_EDMA_1_3] = CPU_ID_EDMA_QMAN_ARC5,
	[GAUDI2_QUEUE_ID_DCORE2_MME_0_0] = CPU_ID_MME_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_DCORE2_MME_0_1] = CPU_ID_MME_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_DCORE2_MME_0_2] = CPU_ID_MME_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_DCORE2_MME_0_3] = CPU_ID_MME_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_0_0] = CPU_ID_TPC_QMAN_ARC12,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_0_1] = CPU_ID_TPC_QMAN_ARC12,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_0_2] = CPU_ID_TPC_QMAN_ARC12,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_0_3] = CPU_ID_TPC_QMAN_ARC12,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_1_0] = CPU_ID_TPC_QMAN_ARC13,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_1_1] = CPU_ID_TPC_QMAN_ARC13,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_1_2] = CPU_ID_TPC_QMAN_ARC13,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_1_3] = CPU_ID_TPC_QMAN_ARC13,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_2_0] = CPU_ID_TPC_QMAN_ARC14,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_2_1] = CPU_ID_TPC_QMAN_ARC14,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_2_2] = CPU_ID_TPC_QMAN_ARC14,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_2_3] = CPU_ID_TPC_QMAN_ARC14,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_3_0] = CPU_ID_TPC_QMAN_ARC15,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_3_1] = CPU_ID_TPC_QMAN_ARC15,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_3_2] = CPU_ID_TPC_QMAN_ARC15,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_3_3] = CPU_ID_TPC_QMAN_ARC15,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_4_0] = CPU_ID_TPC_QMAN_ARC16,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_4_1] = CPU_ID_TPC_QMAN_ARC16,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_4_2] = CPU_ID_TPC_QMAN_ARC16,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_4_3] = CPU_ID_TPC_QMAN_ARC16,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_5_0] = CPU_ID_TPC_QMAN_ARC17,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_5_1] = CPU_ID_TPC_QMAN_ARC17,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_5_2] = CPU_ID_TPC_QMAN_ARC17,
	[GAUDI2_QUEUE_ID_DCORE2_TPC_5_3] = CPU_ID_TPC_QMAN_ARC17,
	[GAUDI2_QUEUE_ID_DCORE3_EDMA_0_0] = CPU_ID_EDMA_QMAN_ARC6,
	[GAUDI2_QUEUE_ID_DCORE3_EDMA_0_1] = CPU_ID_EDMA_QMAN_ARC6,
	[GAUDI2_QUEUE_ID_DCORE3_EDMA_0_2] = CPU_ID_EDMA_QMAN_ARC6,
	[GAUDI2_QUEUE_ID_DCORE3_EDMA_0_3] = CPU_ID_EDMA_QMAN_ARC6,
	[GAUDI2_QUEUE_ID_DCORE3_EDMA_1_0] = CPU_ID_EDMA_QMAN_ARC7,
	[GAUDI2_QUEUE_ID_DCORE3_EDMA_1_1] = CPU_ID_EDMA_QMAN_ARC7,
	[GAUDI2_QUEUE_ID_DCORE3_EDMA_1_2] = CPU_ID_EDMA_QMAN_ARC7,
	[GAUDI2_QUEUE_ID_DCORE3_EDMA_1_3] = CPU_ID_EDMA_QMAN_ARC7,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_0_0] = CPU_ID_TPC_QMAN_ARC18,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_0_1] = CPU_ID_TPC_QMAN_ARC18,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_0_2] = CPU_ID_TPC_QMAN_ARC18,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_0_3] = CPU_ID_TPC_QMAN_ARC18,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_1_0] = CPU_ID_TPC_QMAN_ARC19,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_1_1] = CPU_ID_TPC_QMAN_ARC19,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_1_2] = CPU_ID_TPC_QMAN_ARC19,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_1_3] = CPU_ID_TPC_QMAN_ARC19,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_2_0] = CPU_ID_TPC_QMAN_ARC20,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_2_1] = CPU_ID_TPC_QMAN_ARC20,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_2_2] = CPU_ID_TPC_QMAN_ARC20,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_2_3] = CPU_ID_TPC_QMAN_ARC20,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_3_0] = CPU_ID_TPC_QMAN_ARC21,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_3_1] = CPU_ID_TPC_QMAN_ARC21,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_3_2] = CPU_ID_TPC_QMAN_ARC21,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_3_3] = CPU_ID_TPC_QMAN_ARC21,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_4_0] = CPU_ID_TPC_QMAN_ARC22,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_4_1] = CPU_ID_TPC_QMAN_ARC22,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_4_2] = CPU_ID_TPC_QMAN_ARC22,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_4_3] = CPU_ID_TPC_QMAN_ARC22,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_5_0] = CPU_ID_TPC_QMAN_ARC23,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_5_1] = CPU_ID_TPC_QMAN_ARC23,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_5_2] = CPU_ID_TPC_QMAN_ARC23,
	[GAUDI2_QUEUE_ID_DCORE3_TPC_5_3] = CPU_ID_TPC_QMAN_ARC23,
	[GAUDI2_QUEUE_ID_ROT_0_0] = CPU_ID_ROT_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_ROT_0_1] = CPU_ID_ROT_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_ROT_0_2] = CPU_ID_ROT_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_ROT_0_3] = CPU_ID_ROT_QMAN_ARC0,
	[GAUDI2_QUEUE_ID_ROT_1_0] = CPU_ID_ROT_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_ROT_1_1] = CPU_ID_ROT_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_ROT_1_2] = CPU_ID_ROT_QMAN_ARC1,
	[GAUDI2_QUEUE_ID_ROT_1_3] = CPU_ID_ROT_QMAN_ARC1
};

const uint32_t gaudi2_engine_arc_cpu_id_to_eng_group[] = {
	[CPU_ID_TPC_QMAN_ARC0] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC1] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC2] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC3] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC4] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC5] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC6] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC7] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC8] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC9] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC10] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC11] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC12] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC13] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC14] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC15] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC16] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC17] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC18] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC19] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC20] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC21] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC22] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC23] = ENG_GROUP_TPC_COMPUTE,
	[CPU_ID_TPC_QMAN_ARC24] = ENG_GROUP_INVALID, /*isolated tpc, don't duplicate message to it*/
	[CPU_ID_MME_QMAN_ARC0] = ENG_GROUP_MME_COMPUTE,
	[CPU_ID_MME_QMAN_ARC1] = ENG_GROUP_MME_COMPUTE,
	[CPU_ID_EDMA_QMAN_ARC0] = ENG_GROUP_EDMA_COMPUTE,
	[CPU_ID_EDMA_QMAN_ARC1] = ENG_GROUP_EDMA_COMPUTE,
	[CPU_ID_EDMA_QMAN_ARC2] = ENG_GROUP_EDMA_COMPUTE,
	[CPU_ID_EDMA_QMAN_ARC3] = ENG_GROUP_EDMA_COMPUTE,
	[CPU_ID_EDMA_QMAN_ARC4] = ENG_GROUP_EDMA_COMPUTE,
	[CPU_ID_EDMA_QMAN_ARC5] = ENG_GROUP_EDMA_COMPUTE,
	[CPU_ID_EDMA_QMAN_ARC6] = ENG_GROUP_EDMA_COMPUTE,
	[CPU_ID_EDMA_QMAN_ARC7] = ENG_GROUP_EDMA_COMPUTE,
	[CPU_ID_PDMA_QMAN_ARC0] = ENG_GROUP_PDMA_TX_CMD,
	[CPU_ID_PDMA_QMAN_ARC1] = ENG_GROUP_PDMA_TX_DATA,
	[CPU_ID_ROT_QMAN_ARC0] = ENG_GROUP_RTR_MEDIA,
	[CPU_ID_ROT_QMAN_ARC1] = ENG_GROUP_RTR_MEDIA,
	[CPU_ID_NIC_QMAN_ARC0] = ENG_GROUP_NIC_RECEIVE_SCALE_UP,
	[CPU_ID_NIC_QMAN_ARC1] = ENG_GROUP_NIC_RECEIVE_SCALE_UP,
	[CPU_ID_NIC_QMAN_ARC2] = ENG_GROUP_NIC_RECEIVE_SCALE_UP,
	[CPU_ID_NIC_QMAN_ARC3] = ENG_GROUP_NIC_RECEIVE_SCALE_UP,
	[CPU_ID_NIC_QMAN_ARC4] = ENG_GROUP_NIC_RECEIVE_SCALE_UP,
	[CPU_ID_NIC_QMAN_ARC5] = ENG_GROUP_NIC_RECEIVE_SCALE_UP,
	[CPU_ID_NIC_QMAN_ARC6] = ENG_GROUP_NIC_RECEIVE_SCALE_OUT,
	[CPU_ID_NIC_QMAN_ARC7] = ENG_GROUP_NIC_RECEIVE_SCALE_OUT,
	[CPU_ID_NIC_QMAN_ARC8] = ENG_GROUP_NIC_RECEIVE_SCALE_OUT,
	[CPU_ID_NIC_QMAN_ARC9] = ENG_GROUP_NIC_RECEIVE_SCALE_OUT,
	[CPU_ID_NIC_QMAN_ARC10] = ENG_GROUP_NIC_RECEIVE_SCALE_OUT,
	[CPU_ID_NIC_QMAN_ARC11] = ENG_GROUP_NIC_RECEIVE_SCALE_OUT,
	[CPU_ID_NIC_QMAN_ARC12] = ENG_GROUP_NIC_SEND_SCALE_UP,
	[CPU_ID_NIC_QMAN_ARC13] = ENG_GROUP_NIC_SEND_SCALE_UP,
	[CPU_ID_NIC_QMAN_ARC14] = ENG_GROUP_NIC_SEND_SCALE_UP,
	[CPU_ID_NIC_QMAN_ARC15] = ENG_GROUP_NIC_SEND_SCALE_UP,
	[CPU_ID_NIC_QMAN_ARC16] = ENG_GROUP_NIC_SEND_SCALE_UP,
	[CPU_ID_NIC_QMAN_ARC17] = ENG_GROUP_NIC_SEND_SCALE_UP,
	[CPU_ID_NIC_QMAN_ARC18] = ENG_GROUP_NIC_SEND_SCALE_OUT,
	[CPU_ID_NIC_QMAN_ARC19] = ENG_GROUP_NIC_SEND_SCALE_OUT,
	[CPU_ID_NIC_QMAN_ARC20] = ENG_GROUP_NIC_SEND_SCALE_OUT,
	[CPU_ID_NIC_QMAN_ARC21] = ENG_GROUP_NIC_SEND_SCALE_OUT,
	[CPU_ID_NIC_QMAN_ARC22] = ENG_GROUP_NIC_SEND_SCALE_OUT,
	[CPU_ID_NIC_QMAN_ARC23] = ENG_GROUP_NIC_SEND_SCALE_OUT,
};

#define DUP_ENG_DUP_REG_OFFSET(reg, block_offset) \
	((mmARC_FARM_ARC0_DUP_ENG_DUP_##reg) - \
	 mmARC_FARM_ARC0_DUP_ENG_DUP_TPC_ENG_ADDR_0 + \
	 sizeof(uint32_t) * (block_offset))

#define MON_PER_ENG_GROUP 1
#define SOB_PER_ENG_GROUP 2

#define GAUDI2_ARC_CQ_SIZE_LOG_2 3
#define GAUDI2_ARC_CQ_SIZE BIT_ULL(GAUDI2_ARC_CQ_SIZE_LOG_2)

enum gaudi2_arc_dup_trigger {
	DUP_TRIGGER_TPC = 0,
	DUP_TRIGGER_MME = 1,
	DUP_TRIGGER_EDMA = 2,
	DUP_TRIGGER_PDMA = 3,
	DUP_TRIGGER_ROT = 4,
	DUP_TRIGGER_RSRVD = 5,
	DUP_TRIGGER_NIC_PRI0_I = 6,
	DUP_TRIGGER_NIC_PRI1_I = 7,
	DUP_TRIGGER_NIC_PRI2_I = 8,
	DUP_TRIGGER_NIC_PRI3_I = 9,
	DUP_TRIGGER_NIC_PRI0_E = 10,
	DUP_TRIGGER_NIC_PRI1_E = 11,
	DUP_TRIGGER_NIC_PRI2_E = 12,
	DUP_TRIGGER_NIC_PRI3_E = 13
};

struct gaudi2_priv {
	struct hltests_nic_cq *cq;
	uint32_t max_num_of_qps[NIC_NUMBER_OF_PORTS];
	uint32_t qp_idx_offset[NIC_NUMBER_OF_PORTS];
};

static uint32_t gaudi2_nic_get_wq_offset(int fd, int port, uint32_t conn_id)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi2_priv *gaudi2 = hdev->priv;

	return gaudi2->qp_idx_offset[port];
}

/* While filling up WQEs for WR-RDV transfer,
 * For WQEs of the Send side,
 * 1. The local buffer (source) address needs to be filled but the remote address (destination)
 *    should not be filled. It will be filled by the receive side.
 * 2. The WQE opcode should be WQE_LINEAR as it is a normal RDMA write.
 * 3. The WQE opcode should be WQE_WR_RDV as it is a special transfer wherein we write the WQE
 *    of the send side directly.
 * For WQEs of the Receive side,
 * 1. The local buffer address should not be filled but the remote address field needs to be
 *    written with the dest buff address as this would be copied on to the send side WQE's
 *    remote_address field.
 * 2. The inline bit in the wqe should be set as we are directly transferring the data as part of
 *    the wqe itself.
 * 3. The size of the wqe should be '16' as we are transferring exactly 16 bytes.
 *
 * While filling up WQEs for RD-RDV transfer,
 * There are no WQEs for the send side.
 * For WQEs of the Receive side,
 * 1. Both the local buffer address and the remote address field needs to be filled as this would
 *    entirely be copied onto the send side WQE
 * 2. The inline bit in the wqe should be set as we are directly transferring the data as part of
 *    the wqe itself.
 * 3. The size of the wqe should be '32' as we are transferring the entire WQE.
 */
static int gaudi2_nic_fill_wqe(int fd, void *p_in)
{
	struct hltests_nic_wqe_params *in_params = (struct hltests_nic_wqe_params *) p_in;
	struct sq_wqe *swq = (struct sq_wqe *) in_params->sq_wqe;
	struct rq_wqe *rwq = (struct rq_wqe *) in_params->rq_wqe;
	int remote_sob_id, local_sob_id;
	uint8_t completion_type;

	local_sob_id = LOCAL_SOB_ADDR + 4 * in_params->local_sob_id;
	remote_sob_id = REMOTE_SOB_ADDR + 4 * in_params->remote_sob_id;

	switch (in_params->cmpl) {
	case NONE:
		completion_type = 0;
		break;
	case SOB:
		completion_type = 1;
		break;
	case CQ_USR:
		completion_type = 2;
		break;
	default:
		printf("invalid cmpl type %d\n", in_params->cmpl);
		completion_type = 0;
		break;
	}

	memset(swq, 0, sizeof(*swq));

	swq->opcode = WQE_LINEAR;
	swq->wqe_index = (in_params->wqe_index & 0xffULL);
	swq->reduction_opcode = in_params->reduction_cfg;
	swq->ackreq = (in_params->ackreq & 0x1ULL);
	swq->remote_sync_object = (in_params->cmpl & CQ_USR) ? 0 : remote_sob_id;
	swq->size = (in_params->size & 0xffffffffULL);
	swq->local_address_31_0 = in_params->local_address;
	swq->local_address_63_32 = in_params->local_address >> 32;
	swq->remote_address_31_0 = in_params->remote_address;
	swq->remote_address_63_32 = in_params->remote_address >> 32;
	swq->completion_type = completion_type;
	swq->tag = (in_params->cmpl & CQ_USR) ? in_params->tag : ((uint32_t) SOB_ADD << 31) | 1;

	if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE) {
		if (in_params->is_wr_rdv_send) {
			swq->remote_address_31_0 = 0;
			swq->remote_address_63_32 = 0;
			swq->tag = 0;
			swq->remote_sync_object = 0;
			swq->remote_sync_object_data = 0;
			swq->sob_command = 0;
			swq->completion_type = 0;
		} else {
			/* we are overloading the existing send wqe structure with this inline WQE
			 * instead of creating a separate structure.
			 * Local Address of Send WQE = Remote Address field of Inline WQE
			 * Remote Address of Send WQE = Inline Data field of Inline WQE
			 */
			swq->opcode = WQE_WR_RDV;
			swq->size = NIC_SEND_WQE_SIZE >> 1;
			swq->in_line = 1;
			swq->local_address_31_0 = 0;
			swq->local_address_63_32 = 0;
			swq->reduction_opcode = 0;
		}
	} else if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) {
		swq->opcode = WQE_RD_RDV;
	}

	memset(rwq, 0, sizeof(*rwq));

	rwq->opcode = WQE_LINEAR;
	rwq->size = in_params->size;
	rwq->completion_type = completion_type;
	rwq->wqe_index = in_params->wqe_index;
	rwq->local_sync_object = local_sob_id;
	rwq->local_sync_object_data = (in_params->cmpl & CQ_USR) ? 0 : 1;
	rwq->sob_command = (in_params->cmpl & CQ_USR) ? 0 : SOB_ADD;

	if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE) {
		if (!in_params->is_wr_rdv_send) {
			rwq->opcode = WQE_WR_RDV;
			rwq->size = NIC_SEND_WQE_SIZE >> 1;
			rwq->local_sync_object = remote_sob_id;
		}
	} else if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) {
		rwq->opcode = WQE_RD_RDV;
		rwq->local_sync_object = remote_sob_id;
		rwq->size = NIC_SEND_WQE_SIZE;
	}

	return 0;
}

static void *gaudi2_nic_get_swqe(void *swq, int offset)
{
	return ((struct sq_wqe *) swq) + offset;
}

static void *gaudi2_nic_get_rwqe(void *rwq, int offset)
{
	return ((struct rq_wqe *) rwq) + offset;
}

static uint8_t gaudi2_nic_get_swqe_size(void)
{
	return NIC_SEND_WQE_SIZE;
}

static uint8_t gaudi2_nic_get_rwqe_size(void)
{
	return NIC_RECV_WQE_SIZE;
}

static uint32_t gaudi2_nic_get_max_pi(struct hltests_nic_qp *qp_p)
{
	return qp_p->req_ctx.wq_size;
}

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

static uint32_t gaudi2_add_undef_opcode_pkt(void *buffer, uint32_t buf_off,
		struct hltests_pkt_info *pkt_info)
{
	struct packet_nop packet;

	memset(&packet, 0, sizeof(packet));
	packet.opcode = PACKET_UNDEF_OPCODE;
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

static uint64_t gaudi2_get_fence_addr_fixed(int fd, uint32_t qid, bool cmdq_fence)
{
	uint64_t fence_addr = 0;
	uint32_t index = 0;

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
	case GAUDI2_QUEUE_ID_NIC_0_0:
		if (cmdq_fence)
			fence_addr = mmNIC0_QM0_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC0_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_1_0:
		if (cmdq_fence)
			fence_addr = mmNIC0_QM1_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC0_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_2_0:
		if (cmdq_fence)
			fence_addr = mmNIC1_QM0_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC1_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_3_0:
		if (cmdq_fence)
			fence_addr = mmNIC1_QM1_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC1_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_4_0:
		if (cmdq_fence)
			fence_addr = mmNIC2_QM0_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC2_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_5_0:
		if (cmdq_fence)
			fence_addr = mmNIC2_QM1_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC2_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_6_0:
		if (cmdq_fence)
			fence_addr = mmNIC3_QM0_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC3_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_7_0:
		if (cmdq_fence)
			fence_addr = mmNIC3_QM1_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC3_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_8_0:
		if (cmdq_fence)
			fence_addr = mmNIC4_QM0_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC4_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_9_0:
		if (cmdq_fence)
			fence_addr = mmNIC4_QM1_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC4_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_10_0:
		if (cmdq_fence)
			fence_addr = mmNIC5_QM0_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC5_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_11_0:
		if (cmdq_fence)
			fence_addr = mmNIC5_QM1_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC5_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_12_0:
		if (cmdq_fence)
			fence_addr = mmNIC6_QM0_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC6_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_13_0:
		if (cmdq_fence)
			fence_addr = mmNIC6_QM1_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC6_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_14_0:
		if (cmdq_fence)
			fence_addr = mmNIC7_QM0_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC7_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_15_0:
		if (cmdq_fence)
			fence_addr = mmNIC7_QM1_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC7_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_16_0:
		if (cmdq_fence)
			fence_addr = mmNIC8_QM0_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC8_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_17_0:
		if (cmdq_fence)
			fence_addr = mmNIC8_QM1_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC8_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_18_0:
		if (cmdq_fence)
			fence_addr = mmNIC9_QM0_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC9_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_19_0:
		if (cmdq_fence)
			fence_addr = mmNIC9_QM1_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC9_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_20_0:
		if (cmdq_fence)
			fence_addr = mmNIC10_QM0_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC10_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_21_0:
		if (cmdq_fence)
			fence_addr = mmNIC10_QM1_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC10_QM1_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_22_0:
		if (cmdq_fence)
			fence_addr = mmNIC11_QM0_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC11_QM0_CP_FENCE0_RDATA_0;
		break;
	case GAUDI2_QUEUE_ID_NIC_23_0:
		if (cmdq_fence)
			fence_addr = mmNIC11_QM1_CP_FENCE0_RDATA_4;
		else
			fence_addr = mmNIC11_QM1_CP_FENCE0_RDATA_0;
		break;
	default:
		printf("Failed to configure fence - invalid QID %d\n", qid);
		fail();
	}

	return CFG_BASE + fence_addr;
}

static uint64_t gaudi2_get_fence_addr(int fd, uint32_t qid, bool cmdq_fence)
{
	if (!hltests_is_legacy_mode_enabled(fd))
		cmdq_fence = true;

	return gaudi2_get_fence_addr_fixed(fd, qid, cmdq_fence);
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
			pkt_info.arm_monitor.mon_mode = mon_info->mon_mode;
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
		pkt_info.arm_monitor.mon_mode = mon_info->mon_mode;
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
	mon_info.mon_mode = mon_and_fence_info->mon_mode;

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
	pkt_info.msg_long.value = lower_32_bits(RESERVED_VA_FOR_VIRTUAL_MSIX_DOORBELL_START);
	pkt_info.msg_long.address = CFG_BASE + mmDCORE0_SYNC_MNGR_GLBL_LBW_ADDR_L_0 + offset;
	buf_off = gaudi2_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = upper_32_bits(RESERVED_VA_FOR_VIRTUAL_MSIX_DOORBELL_START);
	pkt_info.msg_long.address = CFG_BASE + mmDCORE0_SYNC_MNGR_GLBL_LBW_ADDR_H_0 + offset;
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

	/* TODO: always use the enabled mask when EDMA in ARC mode is re-enabled (SW-174350) */
	return hltests_is_legacy_mode_enabled(fd) ?
			(uint8_t)__builtin_popcount(hw_ip.edma_enabled_mask) : 0;
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

static uint32_t gaudi2_get_nic_qid(
			enum hltests_dcore_separation_mode dcore_sep_mode,
			uint8_t nic_id,	enum hltests_stream_id stream)
{
	return GAUDI2_QUEUE_ID_NIC_0_0 + (NUM_OF_PQ_PER_QMAN * nic_id) + stream;
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

static uint64_t gaudi2_get_any_mappable_hw_block_base_addr(int fd)
{
	return mmDCORE3_SYNC_MNGR_OBJS_BASE;
}

static uint16_t gaudi2_get_cache_line_size(void)
{
	return DEVICE_CACHE_LINE_SIZE;
}

static int gaudi2_nic_get_max_num_of_ports(void)
{
	return NIC_NUMBER_OF_PORTS;
}

static int gaudi2_asic_priv_init(struct hltests_device *hdev)
{
	struct hlthunk_hw_ip_info hw_ip;
	struct gaudi2_priv *gaudi2;
	int rc;

	rc = hlthunk_get_hw_ip_info(hdev->fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled)
		hdev->sim_dram_on_host = true;
	else
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

static int gaudi2_nic_asic_priv_init(struct hltests_device *hdev, void *arg, uint64_t ctx_port_mask)
{
	struct hlthunk_nic_user_get_app_params_out app_params;
	struct hbldv_query_port_attr port_attr = {};
	struct ibv_port_attr ib_port_attr = {};
	struct ibv_context *ibctx;
	struct gaudi2_priv *gaudi2 = hdev->priv;
	uint64_t port_mask;
	int rc, port, fd = hdev->fd, max_n_ports;

	rc = hlthunk_nic_get_enabled_ports_mask(fd, &port_mask);
	assert_int_equal(rc, 0);

	max_n_ports = gaudi2_nic_get_max_num_of_ports();

	if (hltests_nic_is_ibdev(fd))
		port_mask &= ctx_port_mask;

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		if (hltests_nic_is_ibdev(fd)) {
			assert_non_null(arg);
			ibctx = (struct ibv_context *) arg;
			rc = hbldv_query_port(ibctx, hltests_nic_to_ibdev_port_num(fd, port),
						&port_attr);
			assert_int_equal(rc, 0);

			rc = hlibv_query_port(ibctx, hltests_nic_to_ibdev_port_num(fd, port),
						&ib_port_attr);
			assert_int_equal(rc, 0);

			gaudi2->max_num_of_qps[port] = port_attr.max_num_of_qps;
			gaudi2->qp_idx_offset[port] = port_attr.max_allocated_qp_num;
		} else {
			memset(&app_params, 0, sizeof(app_params));

			rc = hlthunk_nic_user_get_app_params(fd, port, &app_params);
			assert_int_equal(rc, 0);

			gaudi2->max_num_of_qps[port] = app_params.max_num_of_qps;
			gaudi2->qp_idx_offset[port] = app_params.max_allocated_qp_idx;
		}
	}

	return 0;

	return 0;
}

static int gaudi2_dram_pool_alloc(struct hltests_device *hdev, uint64_t size,
				uint64_t *return_addr)
{
	return -EOPNOTSUPP;
}

static void gaudi2_dram_pool_free(struct hltests_device *hdev, uint64_t addr,
					uint64_t size)
{

}

static int gaudi2_va_pool_alloc(struct hltests_device *hdev, uint64_t size, uint64_t *return_addr)
{
	return -EOPNOTSUPP;
}

static void gaudi2_va_pool_free(struct hltests_device *hdev, uint64_t addr, uint64_t size)
{

}

static uint64_t gaudi2_get_user_cq_umr(int fd, uint32_t port, uint32_t cq_id)
{
	uint64_t macro_offset = mmNIC1_MSTR_IF_RR_SHRD_HBW_BASE -
				mmNIC0_MSTR_IF_RR_SHRD_HBW_BASE;
	uint64_t port_offset = mmNIC0_QM1_BASE - mmNIC0_QM0_BASE;
	uint64_t umr_offset = mmNIC0_UMR0_1_UNSECURE_DOORBELL0_BASE -
				mmNIC0_UMR0_0_UNSECURE_DOORBELL0_BASE;

	return mmNIC0_UMR0_0_UNSECURE_DOORBELL0_BASE +
		(port / NIC_NUMBER_OF_QM_PER_MACRO) * macro_offset +
		(port % NIC_NUMBER_OF_QM_PER_MACRO) * port_offset +
		((cq_id >> 1) - 1) * umr_offset;
}

/**
 * gaudi2_get_user_cqe - Read user CQE and update CI
 * @fd: Device file descriptor.
 * @cqe_sw: HW agnostic CQE.
 * @port_cq: Port user CQ.
 * @hw_ci: CI(index) into user CQ buffer to read.
 *
 * @return: Updated CI
 */
static uint32_t gaudi2_nic_get_user_cqe(int fd, struct hl_nic_cqe *cqe_sw,
					struct hltests_nic_port_cq *port_cq, uint32_t hw_ci)
{
	struct nic_cqe_raw *cq_hw_arr = port_cq->cq_buf, *cqe_hw;
	struct hltests_nic_cq *cq = port_cq->thread_params.cq;
	struct hltests_state *tests_state = cq->tests_state;
	uint64_t val, reg_addr, *ptr;
	uint32_t user_cq_buf_len = port_cq->cq_buf_len,
			port = port_cq->thread_params.port;
	int id = port_cq->id;

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
	} else {
		cqe_sw->type = HL_NIC_CQE_TYPE_RES;
		cqe_sw->responder.msg_id = CQE_TAG(cqe_hw);
	}

	CQE_SET_INVALID(cqe_hw);

	/* Increment CI. H/W CI wraps every 32 bits */
	hw_ci++;

	/* Config user CQ HW with updated CI. */
	val = ((uint64_t) hw_ci) << 32 | id;

	if (hltests_is_simulator(fd)) {
		reg_addr = gaudi2_get_user_cq_umr(fd, port, id) + port_cq->regs_offset;
		WRITE64(reg_addr, val);
	} else {
		ptr = (uint64_t *) ((char *) port_cq->regs_ptr + port_cq->regs_offset);
		*ptr = val;
	}

	return hw_ci;
}

static int gaudi2_nic_user_cq_create(int fd, struct hltests_nic_cq *cq)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi2_priv *gaudi2 = hdev->priv;
	int rc;

	assert_int_equal(cq->type, HLTESTS_NIC_CQ_TYPE_PORT);

	cq->user_cq.raw_cqe_size = sizeof(struct nic_cqe_raw);
	cq->user_cq.user_cq_port_poll = hltests_nic_user_cq_port_poll;

	rc = hltests_nic_user_cq_create(fd, cq);
	assert_int_equal(rc, 0);

	gaudi2->cq = cq;

	return 0;
}

static int gaudi2_nic_user_cq_destroy(int fd, struct hltests_nic_cq *cq)
{
	return hltests_nic_user_cq_destroy(fd, cq);
}

static void gaudi2_nic_pre_setup_ctx(int fd, struct hltests_nic_requester_conn_ctx *req)
{
	req->wq_type = hltests_nic_is_ibdev(fd) ? HBLDV_WQ_WRITE : WQ_WRITE;
}

static void gaudi2_nic_setup_ctx_defaults(int fd, int port,
						struct hltests_nic_requester_conn_ctx *req,
						struct hltests_nic_responder_conn_ctx *res)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi2_priv *gaudi2 = hdev->priv;
	struct hltests_nic_cq *cq = gaudi2->cq;
	uint8_t cq_number;

	cq_number = cq ? cq->user_cq.port_cq[port].id : 0;

	req->cq_number = cq_number;

	res->cq_number = cq_number;
}

static int gaudi2_nic_setup_ctx_lpbk(int fd, int port,
					struct hltests_nic_requester_conn_ctx *req_ctx,
					struct hltests_nic_responder_conn_ctx *res_ctx,
					uint32_t conn, struct hltests_nic_lpbk_cfg *cfg)
{
	gaudi2_nic_setup_ctx_defaults(fd, port, req_ctx, res_ctx);

	return 0;
}

static int gaudi2_nic_setup_ctx_e2e(int fd, int port,
					struct hltests_nic_requester_conn_ctx *req_ctx,
					struct hltests_nic_responder_conn_ctx *res_ctx,
					struct hltests_nic_e2e_cfg *cfg)
{
	gaudi2_nic_setup_ctx_defaults(fd, port, req_ctx, res_ctx);

	return 0;
}

/* For WRITE_RDV transfer,
 * 1. The send side QP/WQ type should be RENDEZVOUS
 * 2. The receive side QP/WQ type should be WRITE.
 * 3. The receive side should be programmed with the max QP size of the send side in the
 *    wq_remote_log_size field.
 */
static void gaudi2_nic_pre_setup_default_ctx_rdv(int fd,
						struct hltests_nic_requester_conn_ctx *req_ctx,
						enum hltests_nic_test_opcode test_opcode,
						bool is_rdv_send, bool swq_granularity)
{
	if (is_rdv_send) {
		/* In case of Send side, wq/qp type is RDV Write or RDV read based on the
		 * test type
		 */
		if (test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
			req_ctx->wq_type = hltests_nic_is_ibdev(fd) ?
						HBLDV_WQ_SEND_RDV : WQ_RENDEZVOUS_WRITE;
		else
			req_ctx->wq_type = hltests_nic_is_ibdev(fd) ?
						HBLDV_WQ_READ_RDV_ENDP : WQ_RENDEZVOUS_READ;

		/* 0 equates to 32B, 1 equates to 64B */
		req_ctx->swq_granularity = swq_granularity ? HBLDV_SWQE_GRAN_64B :
									HBLDV_SWQE_GRAN_32B;
	} else {
		/* In case of Send side, wq/qp type is normal write */
		req_ctx->wq_type = hltests_nic_is_ibdev(fd) ? HBLDV_WQ_RECV_RDV : WQ_WRITE;
	}
}

/* For WRITE_RDV transfer,
 * 1. The send side QP/WQ type should be RENDEZVOUS
 * 2. The receive side QP/WQ type should be WRITE.
 * 3. The receive side should be programmed with the max QP size of the send side in the
 *    wq_remote_log_size field.
 */
static void gaudi2_nic_setup_default_ctx_rdv(int fd, int port,
						struct hltests_nic_requester_conn_ctx *req_ctx,
						struct hltests_nic_responder_conn_ctx *res_ctx,
						bool is_rdv_send, uint32_t conn_id,
						bool swq_granularity)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi2_priv *gaudi2 = hdev->priv;
	struct hltests_nic_cq *cq = gaudi2->cq;
	uint8_t cq_number;

	cq_number = cq ? cq->user_cq.port_cq[port].id : 0;

	req_ctx->cq_number = cq_number;

	res_ctx->cq_number = cq_number;
	res_ctx->conn_peer = conn_id;
	res_ctx->rdv = is_rdv_send;
}

static uint32_t gaudi2_nic_add_bulk_doorbell_pkt(void *buf, uint32_t buf_size, int nic,
							uint64_t conn_id, uint64_t db_val)
{
	struct packet_wreg_bulk *bulk_doorbell;

	bulk_doorbell =
		(struct packet_wreg_bulk *) ((uintptr_t) buf + buf_size);

	memset(bulk_doorbell, 0, sizeof(*bulk_doorbell));

	bulk_doorbell->reg_offset = lower_16_bits(mmNIC0_QPC0_QMAN_DOORBELL);
	bulk_doorbell->opcode = PACKET_WREG_BULK;
	bulk_doorbell->eng_barrier = 0;
	bulk_doorbell->swtc = 1;
	bulk_doorbell->msg_barrier = 1;
	bulk_doorbell->size64 = 1;
	bulk_doorbell->values[0] = ((uint64_t) (((uint32_t) nic << 24) |
				conn_id) << 32) | db_val;

	return buf_size + sizeof(*bulk_doorbell) + 8;
}

static int gaudi2_nic_get_min_conn_id(int fd, uint32_t port)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi2_priv *gaudi2 = hdev->priv;

	return NIC_MIN_CONN_ID + gaudi2->qp_idx_offset[port];
}

static int gaudi2_nic_get_max_conn_id(int fd, uint32_t port)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi2_priv *gaudi2 = hdev->priv;

	return gaudi2->max_num_of_qps[port] + gaudi2->qp_idx_offset[port] - 1;
}

static int gaudi2_nic_get_max_num_of_qps(int fd, uint32_t port)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct gaudi2_priv *gaudi2 = hdev->priv;

	return gaudi2->max_num_of_qps[port];
}

static uint64_t gaudi2_nic_get_port_mask(void)
{
	return GAUDI2_NIC_PORTS_MASK;
}

static uint32_t gaudi2_nic_get_base_qid(void)
{
	return GAUDI2_QUEUE_ID_NIC_0_0;
}

static uint64_t gaudi2_nic_get_db_fifo_umr(int fd, uint32_t port, uint32_t db_fifo_id)
{
	uint64_t macro_offset = mmNIC1_MSTR_IF_RR_SHRD_HBW_BASE -
				mmNIC0_MSTR_IF_RR_SHRD_HBW_BASE;
	uint64_t port_offset = mmNIC0_QM1_BASE - mmNIC0_QM0_BASE;
	uint64_t umr_offset = mmNIC0_UMR0_1_UNSECURE_DOORBELL0_BASE -
				mmNIC0_UMR0_0_UNSECURE_DOORBELL0_BASE;
	uint32_t db_fifo_hw_id = db_fifo_id - 1;

	return mmNIC0_UMR0_0_UNSECURE_DOORBELL0_BASE +
		(port / NIC_NUMBER_OF_QM_PER_MACRO) * macro_offset +
		(port % NIC_NUMBER_OF_QM_PER_MACRO) * port_offset +
		(db_fifo_hw_id / 2) * umr_offset;
}

static int gaudi2_nic_get_default_cfg(void *cfg, enum hltests_nic_id id)
{
	struct hltests_nic_lpbk_cfg *lpbk_cfg;
	struct hltests_nic_gen_test_cfg *gen_test_cfg;
	int port;

	switch (id) {
	case HLTESTS_NIC_E2E_LPBK:
		lpbk_cfg = cfg;
		for (port = 0 ; port < MAX_NIC_NUMBER_OF_PORTS ; port++) {
			lpbk_cfg->ports[port] = port;
			lpbk_cfg->qps_per_port[port] = 1;
		}
		lpbk_cfg->ports_num = MAX_NIC_NUMBER_OF_PORTS;
		lpbk_cfg->qps_per_port_num_elements = MAX_NIC_NUMBER_OF_PORTS;
		lpbk_cfg->max_qps_per_port = 1;
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
		lpbk_cfg->user_db = false;
		/* driver decides MTU value */
		lpbk_cfg->mtu = 0;
		lpbk_cfg->test_opcode = TEST_OPCODE_LINEAR_WRITE;
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

static int gaudi2_submit_cs(int fd, struct hltests_cs_chunk *restore_arr,
		uint32_t restore_arr_size, struct hltests_cs_chunk *execute_arr,
		uint32_t execute_arr_size, uint32_t flags, uint32_t timeout,
		uint64_t *seq)
{
	int rc;

	if (hltests_is_legacy_mode_enabled(fd))
		return hltests_submit_legacy_cs(fd, restore_arr,
				restore_arr_size, execute_arr, execute_arr_size,
				flags, timeout, seq);
	else {
		/*
		 * TODO: some handling of restore arr is required.
		 * The way it is now is not a solution.
		 */
		rc = hltests_sched_arc_submit_cs(
			fd, restore_arr, restore_arr_size, CPU_ID_SCHED_ARC0, seq);
		if (rc)
			return rc;
		return hltests_sched_arc_submit_cs(
			fd, execute_arr, execute_arr_size, CPU_ID_SCHED_ARC0, seq);
	}
}

static int gaudi2_wait_for_cs(int fd, uint64_t seq, uint64_t timeout_us)
{
	if (hltests_is_legacy_mode_enabled(fd))
		return hltests_wait_for_legacy_cs(fd, seq, timeout_us);
	else
		return hltests_wait_for_job(fd, seq, timeout_us);
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

static inline int gaudi2_arc_add_config_engine(int fd, uint32_t cpu_id,
						struct hltests_arc_db *arc_db, void *cb,
						uint32_t cb_size)
{
	struct engine_config_t eng_config;

	memset(&eng_config, 0, sizeof(struct engine_config_t));

	eng_config.qm_base = gaudi2_arc_blocks_bases[cpu_id] - mmDCORE0_TPC0_QM_ARC_AUX_BASE +
			     mmDCORE0_TPC0_QM_BASE - CFG_BASE;

	return hltests_arc_add_arc_config(fd, arc_db, &eng_config, sizeof(eng_config), cb,
						cb_size, cpu_id, gaudi2_arc_blocks_bases[cpu_id],
						SCHED_FW_CONFIG_ADDR_OFFSET,
						SCHED_FW_CONFIG_SIZE_OFFSET, ARC_REGION9_PCIE, 0);
}

static inline int gaudi2_arc_add_config_scheduler(int fd, uint32_t cpu_id,
						struct hltests_arc_db *arc_db, void *cb,
						uint32_t cb_size)
{
	struct scheduler_config_t sched_config;
	int i;

	memset(&sched_config, 0, sizeof(struct scheduler_config_t));

	sched_config.common_cfg.version = ARC_FW_INIT_CONFIG_VER;

	for (i = 0 ; i < ARRAY_SIZE(gaudi2_engine_arc_cpu_id_to_eng_group) ; ++i) {
		sched_config.eng_arc_cfg[i].enabled = arc_db->fw_info[i].enabled;
		sched_config.eng_arc_cfg[i].arc_aux_base = gaudi2_arc_blocks_bases[i] - CFG_BASE;
		sched_config.eng_arc_cfg[i].engine_group_type =
				gaudi2_engine_arc_cpu_id_to_eng_group[i];
	}

	return hltests_arc_add_arc_config(fd, arc_db, &sched_config, sizeof(sched_config), cb,
						cb_size, cpu_id, gaudi2_arc_blocks_bases[cpu_id],
						SCHED_FW_CONFIG_ADDR_OFFSET,
						SCHED_FW_CONFIG_SIZE_OFFSET, ARC_REGION9_PCIE, 0);
}

static int gaudi2_arc_set_config(int fd, uint32_t cpu_id, struct hltests_arc_db *arc_db,
					uint16_t run_arc_done_sob)
{
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size = 0, dma_qid;
	uint64_t base;
	void *cb;
	int rc;

	base = gaudi2_arc_blocks_bases[cpu_id];
	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);
	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	if (!cb)
		return -ENOMEM;

	/* clear SOB with msg_long since clear_sob doesn't work here */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.value = 0;
	pkt_info.msg_long.address = gaudi2_get_sob_base_addr(fd) + (run_arc_done_sob * 0x4);
	cb_size = gaudi2_add_msg_long_pkt(cb, cb_size, &pkt_info);
	rc = hltests_submit_and_wait_legacy_cs(fd, cb, cb_size, dma_qid,
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
	if (rc) {
		hltests_destroy_cb(fd, cb);
		return rc;
	}

	cb_size = 0;

	if (cpu_id < NUM_OF_SCHEDULER_ARC)
		cb_size = gaudi2_arc_add_config_scheduler(fd, cpu_id, arc_db, cb, cb_size);
	else
		cb_size = gaudi2_arc_add_config_engine(fd, cpu_id, arc_db, cb, cb_size);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + ARC_AUX_ARC_NUM_OFFSET;
	pkt_info.msg_long.value = cpu_id;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + SCHED_SOB_LBU_ADDR_OFFSET;
	pkt_info.msg_long.value = ARC_BUILD_ADDR((uint64_t)(ARC_REGION15_LBU),
					hltests_get_sob_base_addr(fd) + (run_arc_done_sob * 0x4));
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + SCHED_SOB_LBU_VALUE_OFFSET;
	pkt_info.msg_long.value = DCORE0_SYNC_MNGR_OBJS_SOB_OBJ_INC_MASK | 0x1;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	return hltests_submit_and_wait_legacy_cs(fd, cb, cb_size, dma_qid,
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

static uint32_t gaudi2_get_num_scheduler_arcs(void)
{
	return NUM_OF_SCHEDULER_ARC;
}

static int gaudi2_arc_map_lbw_blocks(int fd, uint32_t cpu_id,
					struct hltests_arc_db *arc_db)
{
	uint64_t block_addr, base = gaudi2_arc_blocks_bases[cpu_id];
	struct arc_fw_info *fw_info = &arc_db->fw_info[cpu_id];

	/* Map DCCM block.
	 * For ARC farm scheduler ARCs it maps both DCCM0 and DCCM1.
	 */
	if (cpu_id < NUM_OF_ARC_FARMS_ARC)
		block_addr = base + mmARC_FARM_ARC0_DCCM0_BASE -
				mmARC_FARM_ARC0_AUX_BASE;
	else
		block_addr = base + mmDCORE1_MME_QM_ARC_DCCM_BASE -
				mmDCORE1_MME_QM_ARC_AUX_BASE;

	fw_info->dccm_host_addr = hltests_map_hw_block(fd, block_addr,
							&fw_info->dccm_size);
	if (!fw_info->dccm_host_addr) {
		printf("Failed to map DCCM block of ARC %d\n", cpu_id);
		return -ENOMEM;
	}

	/* Map ACP block for scheduler ARCs */
	if (cpu_id >= NUM_OF_SCHEDULER_ARC)
		return 0;

	block_addr = base + mmARC_FARM_ARC0_ACP_ENG_BASE -
			mmARC_FARM_ARC0_AUX_BASE;

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

static void gaudi2_arc_unmap_lbw_blocks(int fd, uint32_t cpu_id,
					struct hltests_arc_db *arc_db)
{
	struct arc_fw_info *fw_info = &arc_db->fw_info[cpu_id];

	if (cpu_id < NUM_OF_SCHEDULER_ARC)
		hltests_unmap_hw_block(fd, fw_info->acp_host_addr,
					fw_info->acp_size);

	hltests_unmap_hw_block(fd, fw_info->dccm_host_addr,
				fw_info->dccm_size);
}

static int gaudi2_wait_arc_run_done(int fd, struct hltests_arc_db *arc_db,
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
	mon_and_fence_info.queue_id = dma_qid;
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = arc_run_done_sob;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = gaudi2_get_fence_addr_fixed(fd, dma_qid, false);
	mon_and_fence_info.sob_val = arc_db->arc_count;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	mon_and_fence_info.mon_mode = SOB_EQUAL;
	cb_size = hltests_add_monitor_and_fence(fd, cb, cb_size, &mon_and_fence_info);

	/* have to use legacy CS as ARCs not ready yet */
	rc = hltests_submit_and_wait_legacy_cs(fd, cb, cb_size, dma_qid, DESTROY_CB_FALSE,
							HL_WAIT_CS_STATUS_COMPLETED);
	if (rc) {
		hltests_destroy_cb(fd, cb);
		return rc;
	}

	cb_size = 0;

	/* clear SOB with msg_long since clear_sob doesn't work here */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.value = 0;
	pkt_info.msg_long.address = gaudi2_get_sob_base_addr(fd) + (arc_run_done_sob * 0x4);
	cb_size = gaudi2_add_msg_long_pkt(cb, cb_size, &pkt_info);
	return hltests_submit_and_wait_legacy_cs(fd, cb, cb_size, dma_qid,
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

static int gaudi2_arc_activate(int fd, uint32_t cpu_id,
				struct hltests_arc_db *arc_db)
{
	void *addr;

	/* Write SCAL_INIT_COMPLETED to the canary register */
	addr = hltests_arc_get_canary_addr(cpu_id, arc_db);
	return hltests_write_lbw_reg(fd, addr, SCAL_INIT_COMPLETED);
}

static int gaudi2_arc_set_asic_model(int fd, uint32_t cpu_id,
				struct hltests_arc_db *arc_db)
{
	void *addr;

	addr = hltests_arc_get_asic_model_addr(cpu_id, arc_db);
	return hltests_write_lbw_reg(fd, addr, ARC_ASIC_MODEL_GAUDI2);
}

static int gaudi2_arc_set_regions(int fd, uint32_t cpu_id,
					struct hltests_arc_db *arc_db)
{
	uint64_t base = gaudi2_arc_blocks_bases[cpu_id];
	uint32_t cb_size = 0, dram_device_va;
	struct hltests_pkt_info pkt_info;
	void *cb;

	cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	if (!cb)
		return -ENOMEM;

	dram_device_va = lower_32_bits(arc_db->dram_device_va);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + ARC_AUX_HBM0_LSB_OFFSET;
	pkt_info.msg_long.value = dram_device_va >> 28;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + ARC_AUX_HBM0_MSB_OFFSET;
	pkt_info.msg_long.value = (uint32_t)(arc_db->dram_device_va >> 32);
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + ARC_AUX_HBM0_OFF_OFFSET;
	pkt_info.msg_long.value = arc_db->fw_info[cpu_id].hbm_offset;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + ARC_AUX_PCIE_LSB_OFFSET;
	pkt_info.msg_long.value = (uint32_t)(arc_db->host_device_va);
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = base + ARC_AUX_PCIE_MSB_OFFSET;
	pkt_info.msg_long.value =
		(uint32_t)(arc_db->host_device_va >> 32);
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	return hltests_submit_and_wait_legacy_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

static void gaudi2_arc_get_sched_cpuid_range(int *sched_first, int *sched_last)
{
	*sched_first = CPU_ID_SCHED_ARC0;
	*sched_last = CPU_ID_SCHED_ARC5;
}

static void gaudi2_arc_get_engine_cpuid_range(int *engine_first, int *engine_last)
{
	*engine_first = CPU_ID_TPC_QMAN_ARC0;
	*engine_last = CPU_ID_NIC_QMAN_ARC23;
}

static void gaudi2_asic_load_fw_to_arc(struct iterate_arcs_ctx *ctx, uint32_t cpu_id)
{
	uint32_t dccm_image_size, hbm_image_offset;
	struct arc_load_data *arc_load_data;
	uint64_t dram_device_va, src_va;
	struct hltests_arc_db *arc_db;
	void *src_ptr;
	int rc, fd;

	arc_load_data = ctx->data;
	arc_db = ctx->arc_db;
	fd = arc_load_data->fd;

	dram_device_va = arc_db->dram_device_va + arc_db->fw_info[cpu_id].hbm_offset;

	switch (cpu_id) {
	case CPU_ID_SCHED_ARC0 ... CPU_ID_SCHED_ARC3:
		dccm_image_size = SCHED_ARC_IMAGE_DCCM_SIZE;
		hbm_image_offset = SCHED_ARC_IMAGE_DCCM_SIZE;
		src_ptr = arc_load_data->sched_img_data.img_host_ptr;
		src_va = arc_load_data->sched_img_data.img_host_va;
		break;
	case CPU_ID_SCHED_ARC4 ... CPU_ID_SCHED_ARC5:
		/* The DCCM image for MME scheduler ARCs is loaded in 2 halves */
		dccm_image_size = SCHED_ARC_IMAGE_DCCM_SIZE / 2;
		hbm_image_offset = SCHED_ARC_IMAGE_DCCM_SIZE;
		src_ptr = arc_load_data->sched_img_data.img_host_ptr;
		src_va = arc_load_data->sched_img_data.img_host_va;
		break;
	default:
		dccm_image_size = ENGINE_ARC_IMAGE_DCCM_SIZE;
		hbm_image_offset = ENGINE_ARC_IMAGE_DCCM_SIZE;
		src_ptr = arc_load_data->eng_img_data.img_host_ptr;
		src_va = arc_load_data->eng_img_data.img_host_va;
		break;
	}

	/* Copy the F/W DCCM image */
	rc = hltests_write_lbw_mem(fd, arc_db->fw_info[cpu_id].dccm_host_addr,
					src_ptr, dccm_image_size);
	if (rc) {
		ctx->rc = rc;
		return;
	}

	/* Copy the 2nd half of the F/W DCCM image for MME scheduler ARCs.
	 * Need to select the upper DCCM address map before copying.
	 */
	if (cpu_id == CPU_ID_SCHED_ARC4 || cpu_id == CPU_ID_SCHED_ARC5) {
		struct hltests_pkt_info pkt_info;
		uint64_t address;
		uint32_t cb_size;
		void *cb;

		cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
		if (!cb) {
			ctx->rc = -ENOMEM;
			return;
		}

		address = gaudi2_arc_blocks_bases[cpu_id] + ARC_AUX_MME_ARC_UPPER_DCCM_EN_OFFSET;

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.msg_long.address = address;
		pkt_info.msg_long.value = 1;
		cb_size = hltests_add_msg_long_pkt(fd, cb, 0, &pkt_info);
		rc = hltests_submit_and_wait_legacy_cs(fd, cb, cb_size,
						hltests_get_dma_down_qid(fd, STREAM0),
						DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
		if (rc) {
			hltests_destroy_cb(fd, cb);
			ctx->rc = rc;
			return;
		}

		rc = hltests_write_lbw_mem(fd, arc_db->fw_info[cpu_id].dccm_host_addr,
					(uint8_t *) src_ptr + dccm_image_size, dccm_image_size);
		if (rc) {
			hltests_destroy_cb(fd, cb);
			ctx->rc = rc;
			return;
		}

		pkt_info.msg_long.value = 0;
		cb_size = hltests_add_msg_long_pkt(fd, cb, 0, &pkt_info);
		rc = hltests_submit_and_wait_legacy_cs(fd, cb, cb_size,
						hltests_get_dma_down_qid(fd, STREAM0),
						DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
		if (rc) {
			ctx->rc = rc;
			return;
		}
	}

	/* Copy the F/W HBM image */
	ctx->rc = hltests_dma_transfer_legacy(fd, hltests_get_dma_down_qid(fd, STREAM0),
					EB_FALSE, MB_FALSE, src_va + hbm_image_offset,
					dram_device_va, ARC_IMAGE_HBM_SIZE,
					DMA_DIR_HOST_TO_DRAM);
}

static int gaudi2_asic_load_fw_to_arcs(struct iterate_arcs_ctx *ctx)
{
	ctx->fn = gaudi2_asic_load_fw_to_arc;
	return hltests_asic_iterate_arcs(ctx, ARC_TYPE_ALL_MASK);
}

static void gaudi2_set_arc_asic_fw_load_params(struct arc_asic_fw_load_params *load_param)
{
	load_param->sched_arc_image_size = SCHED_ARC_IMAGE_SIZE;
	load_param->eng_arc_image_size = ENGINE_ARC_IMAGE_SIZE;
	load_param->sched_arc_first_idx = CPU_ID_SCHED_ARC0;
	load_param->sched_arc_last_idx = CPU_ID_SCHED_ARC5;
	load_param->eng_arc_first_idx = CPU_ID_TPC_QMAN_ARC0;
	load_param->eng_arc_last_idx = NUM_ARC_CPUS - 1;
	load_param->arc_image_hbm_size = ARC_IMAGE_HBM_SIZE;
}

static int gaudi2_arc_set_enabled_cores(int fd, struct hltests_arc_db *arc_db)
{
	uint64_t capabilities_mask = hltests_get_capabilities_mask();
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hlthunk_hw_ip_info hw_ip;
	uint32_t engine_id;
	int rc, i;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	if (rc)
		return rc;

	for (i = 0 ; i < NUM_ARC_CPUS ; i++) {
		if (i == CPU_ID_SCHED_ARC0 && !(capabilities_mask & CAP_ARC_FW_LOAD_SCHED_MASK))
			continue;
		if (i >= CPU_ID_SCHED_ARC1 && i <= CPU_ID_SCHED_ARC5)
			continue;

		if (i >= CPU_ID_TPC_QMAN_ARC0 && i <= CPU_ID_TPC_QMAN_ARC24) {
			engine_id = i - CPU_ID_TPC_QMAN_ARC0;
			if (!((hw_ip.tpc_enabled_mask_ext & (0x1ULL << engine_id))
				&& !!(capabilities_mask & CAP_ARC_FW_LOAD_TPC_MASK)))
				continue;
		}

		if (i >= CPU_ID_MME_QMAN_ARC0 && i <= CPU_ID_MME_QMAN_ARC1) {
			engine_id = i - CPU_ID_MME_QMAN_ARC0;

			if (!hdev->module_params.mme_enable ||
				!(capabilities_mask & CAP_ARC_FW_LOAD_MME_MASK))
				continue;

			if (!(hw_ip.mme_enabled_mask & (0x1ULL << engine_id)))
				continue;
		}

		if (i >= CPU_ID_EDMA_QMAN_ARC0 && i <= CPU_ID_EDMA_QMAN_ARC7) {
			/*
			 * TODO - un-commnet when EDMA in ARC mode is re-enabled (SW-174350)
			 * engine_id = i - CPU_ID_EDMA_QMAN_ARC0;
			 * if (!((hw_ip.edma_enabled_mask & (0x1 << engine_id)) &&
			 *		!!(capabilities_mask & CAP_ARC_FW_LOAD_EDMA_MASK)))
			 *	continue;
			 */
			continue;
		}

		if (i >= CPU_ID_PDMA_QMAN_ARC0 && i <= CPU_ID_PDMA_QMAN_ARC1 &&
				!(capabilities_mask & CAP_ARC_FW_LOAD_PDMA_MASK))
			continue;

		if (i >= CPU_ID_ROT_QMAN_ARC0 && i <= CPU_ID_ROT_QMAN_ARC1) {
			engine_id = i - CPU_ID_ROT_QMAN_ARC0;
			if (!((hdev->module_params.rotator_mask & (0x1 << engine_id))
				&& !!(capabilities_mask & CAP_ARC_FW_LOAD_ROT_MASK)))
				continue;
		}

		if (i >= CPU_ID_NIC_QMAN_ARC0 && i <= CPU_ID_NIC_QMAN_ARC23)
			continue;

		arc_db->fw_info[i].enabled = true;
		arc_db->fw_info[i].arc_id = i;
		arc_db->arc_count++;
	}

	return 0;
}

static int gaudi2_arc_configure_scheduler_streams(int fd, struct hltests_arc_db *arc_db)
{
	struct arc_fw_info *fw_info = &arc_db->fw_info[CPU_ID_SCHED_ARC0];

	fw_info->ccb_size = SCHED_QUEUE_SIZE;

	return 0;
}

uint64_t gaudi2_get_dram_va_hint_mask(void)
{
	return DRAM_VA_HINT_MASK;
}

uint64_t gaudi2_get_dram_va_reserved_addr_start(void)
{
	return RESERVED_VA_RANGE_FOR_ARC_ON_HBM_START;
}

static uint32_t add_bulk_swtd_pkt(void *buf, uint32_t buf_size, void *swtd)
{
	struct packet_wreg_bulk *bulk_doorbell;

	bulk_doorbell =
		(struct packet_wreg_bulk *) ((uintptr_t) buf + buf_size);

	memset(bulk_doorbell, 0, sizeof(*bulk_doorbell));

	bulk_doorbell->reg_offset =
		lower_16_bits(mmNIC0_QPC0_LINEAR_WQE_STATIC_0);
	bulk_doorbell->opcode = PACKET_WREG_BULK;
	bulk_doorbell->eng_barrier = 0;
	bulk_doorbell->swtc = 1;
	bulk_doorbell->msg_barrier = 1;
	bulk_doorbell->size64 = 5;
	memcpy((uint8_t *) &bulk_doorbell->values[0], (uint8_t *)swtd,
		bulk_doorbell->size64 * sizeof(uint64_t));

	return buf_size + sizeof(struct packet_wreg_bulk) + 40;
}

static uint32_t add_bulk_dwtd_pkt(void *buf, uint32_t buf_size, void *dwtd)
{
	struct packet_wreg_bulk *bulk_doorbell;

	bulk_doorbell =
		(struct packet_wreg_bulk *) ((uintptr_t) buf + buf_size);

	memset(bulk_doorbell, 0, sizeof(*bulk_doorbell));

	bulk_doorbell->reg_offset =
		lower_16_bits(mmNIC0_QPC0_LINEAR_WQE_DYNAMIC_0);
	bulk_doorbell->opcode = PACKET_WREG_BULK;
	bulk_doorbell->eng_barrier = 0;
	bulk_doorbell->swtc = 1;
	bulk_doorbell->msg_barrier = 1;
	bulk_doorbell->size64 = 4;
	memcpy((uint8_t *) &bulk_doorbell->values[0], (uint8_t *)dwtd,
		bulk_doorbell->size64 * sizeof(uint64_t));

	return buf_size + sizeof(struct packet_wreg_bulk) + 32;
}

static void fill_wtd_desc(struct wtd_static *swtd, struct wtd_dynamic *dwtd,
				int wqe_index, uint64_t local_addr,
				uint64_t remote_addr, uint32_t size,
				uint32_t conn_id, uint32_t tag, bool ackreq)
{
	memset(swtd, 0, sizeof(*swtd));

	swtd->rcv_opcode = WQE_LINEAR;
	swtd->rcv_wqe_index = wqe_index & 0xffULL;
	swtd->pt = 0x3;
	swtd->rcv_completion_type = HLTESTS_NIC_CQ_COMP;
	swtd->rcv_tag = tag;
	swtd->send_opcode = WQE_LINEAR;
	swtd->send_wqe_index = wqe_index & 0xffULL;
	swtd->in_line = 0;
	swtd->ackreq = ackreq & 0x1ULL;
	swtd->local_address_31_0 = lower_32_bits(local_addr);
	swtd->local_address_63_32 = upper_32_bits(local_addr);
	swtd->remote_address_31_0 = lower_32_bits(remote_addr);
	swtd->remote_address_63_32 = upper_32_bits(remote_addr);
	swtd->send_tag = tag;
	swtd->send_completion_type = HLTESTS_NIC_CQ_COMP;

	memset(dwtd, 0, sizeof(*dwtd));
	dwtd->rcv_size = size;
	dwtd->send_size = size;
	dwtd->qp_number = conn_id & 0xffffffULL;
}

static void fill_wtd_desc_wrrdv(struct wtd_static *swtd, struct wtd_dynamic *dwtd,
				int wqe_index, uint64_t local_addr,
				uint64_t remote_addr, uint32_t size,
				uint32_t conn_id, uint32_t tag, bool ackreq,
				bool is_rdv_send)
{
	memset(swtd, 0, sizeof(*swtd));

	if (is_rdv_send) {
		swtd->rcv_opcode = WQE_LINEAR;
		swtd->send_opcode = WQE_LINEAR;
		swtd->local_address_31_0 = lower_32_bits(local_addr);
		swtd->local_address_63_32 = upper_32_bits(local_addr);
	} else {
		swtd->rcv_opcode = WQE_WR_RDV;
		swtd->send_opcode = WQE_WR_RDV;
		swtd->in_line = 1;
		swtd->remote_address_31_0 = lower_32_bits(remote_addr);
		swtd->remote_address_63_32 = upper_32_bits(remote_addr);
	}

	swtd->rcv_wqe_index = wqe_index & 0xffULL;
	swtd->pt = 0x3;
	swtd->rcv_completion_type = HLTESTS_NIC_CQ_COMP;
	swtd->rcv_tag = tag;
	swtd->send_wqe_index = wqe_index & 0xffULL;
	swtd->ackreq = ackreq & 0x1ULL;
	swtd->send_tag = tag;
	swtd->send_completion_type = HLTESTS_NIC_CQ_COMP;

	memset(dwtd, 0, sizeof(*dwtd));

	if (is_rdv_send) {
		dwtd->rcv_size = size;
		dwtd->send_size = size;
	} else {
		dwtd->rcv_size = NIC_SEND_WQE_SIZE >> 1;
		dwtd->send_size = NIC_SEND_WQE_SIZE >> 1;
	}

	dwtd->qp_number = conn_id & 0xffffffULL;
}

static void fill_wtd_desc_rdrdv(struct wtd_static *swtd, struct wtd_dynamic *dwtd,
				int wqe_index, uint64_t local_addr,
				uint64_t remote_addr, uint32_t size,
				uint32_t conn_id, uint32_t tag, bool ackreq)
{
	memset(swtd, 0, sizeof(*swtd));

	swtd->rcv_opcode = WQE_RD_RDV;
	swtd->rcv_wqe_index = wqe_index & 0xffULL;
	swtd->pt = 0x3;
	swtd->rcv_completion_type = HLTESTS_NIC_CQ_COMP;
	swtd->rcv_tag = tag;
	swtd->send_opcode = WQE_RD_RDV;
	swtd->send_wqe_index = wqe_index & 0xffULL;
	swtd->in_line = 0;
	swtd->ackreq = ackreq & 0x1ULL;
	swtd->local_address_31_0 = lower_32_bits(local_addr);
	swtd->local_address_63_32 = upper_32_bits(local_addr);
	swtd->remote_address_31_0 = lower_32_bits(remote_addr);
	swtd->remote_address_63_32 = upper_32_bits(remote_addr);
	swtd->send_tag = tag;
	swtd->send_completion_type = HLTESTS_NIC_CQ_COMP;

	memset(dwtd, 0, sizeof(*dwtd));
	dwtd->rcv_size = NIC_SEND_WQE_SIZE;
	dwtd->send_size = size;
	dwtd->qp_number = conn_id & 0xffffffULL;
}

static int gaudi2_nic_run_wtd(int fd, void *p_in)
{
	struct hltests_cs_chunk restore_arr[1], execute_arr[2];
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	struct hltests_nic_in_params *in_params;
	struct hltests_device *hdev;
	struct wtd_static swtd;
	struct wtd_dynamic dwtd;
	void *restore_cb, *int_cb, *dma_cb, *db_buf;
	uint64_t data_size, seq, local_addr, remote_addr,
		 src_buf_va = 0, dst_buf_va = 0, db_buf_va, local_conn_base,
		 remote_conn_base;
	uint32_t wqe_size, restore_cb_size, dma_cb_size, db_buf_size, nwq, offset_factor,
		wq_nwq, port_mask, qps_per_port, tag_mask, conn_id, qps_till_now = 0, nic_idx;
	uint16_t first_sob = 0, first_mon = 0;
	enum hl_nic_mem_id wq_loc;
	int rc = 0, i, nic, qp, tag_idx = 0, dma_qp = 0;
	bool ackreq, is_dram, single_alloc, is_rdv_send = false;

	in_params = (struct hltests_nic_in_params *) p_in;

	is_dram = in_params->is_dram;
	single_alloc = in_params->single_alloc;
	port_mask = in_params->port_mask;
	wqe_size = in_params->wqe_size;
	data_size = in_params->data_size;
	wq_loc = in_params->wq_loc;
	nwq = in_params->nwq;
	wq_nwq = nwq < WQES_MIN ? WQES_MIN : nwq;
	tag_mask = ~(next_pow2(in_params->max_qps_per_port) - 1);
	first_sob = hltests_get_first_avail_sob(fd);
	first_mon = hltests_get_first_avail_mon(fd);
	hdev = get_hdev_from_fd(fd);

	restore_cb = hltests_create_cb(fd, HL_MAX_CB_SIZE, EXTERNAL, 0);
	assert_non_null(restore_cb);

	rc = hltests_nic_cb_list_push(restore_cb);
	assert_int_equal(rc, 0);

	dma_cb = hltests_create_cb(fd, HL_MAX_CB_SIZE, EXTERNAL, 0);
	assert_non_null(dma_cb);

	rc = hltests_nic_cb_list_push(dma_cb);
	assert_int_equal(rc, 0);

	db_buf = hltests_allocate_host_mem(fd, HL_MAX_CB_SIZE, NOT_HUGE_MAP);
	assert_non_null(db_buf);

	rc = hltests_nic_hmem_list_push(db_buf);
	assert_int_equal(rc, 0);

	db_buf_va = hltests_get_device_va_for_host_ptr(fd, db_buf);

	int_cb = hltests_create_cb(fd, HL_MAX_CB_SIZE, INTERNAL, db_buf_va);
	assert_non_null(int_cb);

	rc = hltests_nic_cb_list_push(int_cb);
	assert_int_equal(rc, 0);

	/* For RDV transfer, the data to be transferred will be present in the local_conn_base
	 * of the send side, which is the odd qp index. The local_conn_base of the receive side
	 * will not be used. So in case of a single alloc config, we need to DMA the source addr
	 * of the qp 1 (send side) to DRAM.
	 */
	if (single_alloc)
		dma_qp = (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE) ? 1 : 0;

	for (nic = 0, nic_idx = 0 ; nic < MAX_NIC_NUMBER_OF_PORTS ; nic++) {
		if (!(port_mask & BIT_ULL(nic)))
			continue;

		if (single_alloc) {
			src_buf_va =
				hltests_get_device_va_for_host_ptr(fd,
						in_params->src_buf[nic][0]);
			dst_buf_va =
				hltests_get_device_va_for_host_ptr(fd,
						in_params->dst_buf[nic][0]);
		}

		qps_per_port = in_params->qps_per_port[nic];
		for (qp = 0 ; qp < qps_per_port ; qp++) {
			if (!single_alloc) {
				src_buf_va =
					hltests_get_device_va_for_host_ptr(fd,
						in_params->src_buf[nic][qp]);
				dst_buf_va =
					hltests_get_device_va_for_host_ptr(fd,
						in_params->dst_buf[nic][qp]);
			}

			if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
				is_rdv_send = qp & 1;

			if ((in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) && (qp & 1))
				continue;

			if (is_dram) {
				offset_factor = single_alloc ? nic_idx : (qps_till_now + qp);
				local_conn_base = in_params->local_dram_addr +
					offset_factor * data_size;
				remote_conn_base = in_params->remote_dram_addr +
					offset_factor * data_size;
			} else {
				local_conn_base = src_buf_va;
				remote_conn_base = dst_buf_va;
			}

			if (is_dram && (qp == dma_qp || !single_alloc)) {
				memset(dma_cb, 0, HL_MAX_CB_SIZE);
				dma_cb_size = 0;

				/* Down phase */
				memset(&pkt_info, 0, sizeof(pkt_info));
				pkt_info.eb = EB_FALSE;
				pkt_info.mb = MB_TRUE;
				pkt_info.dma.src_addr = src_buf_va;
				pkt_info.dma.dst_addr = local_conn_base;
				pkt_info.dma.size = data_size;
				pkt_info.dma.dma_dir =
					DMA_DIR_HOST_TO_DRAM;
				dma_cb_size = hltests_add_dma_pkt(fd,
					dma_cb, dma_cb_size, &pkt_info);

				execute_arr[0].cb_ptr = dma_cb;
				execute_arr[0].cb_size = dma_cb_size;
				execute_arr[0].queue_index =
					hltests_get_dma_down_qid(fd, STREAM0);

				rc = hltests_submit_cs(fd, NULL, 0,
					execute_arr, 1, 0, &seq);
				assert_int_equal(rc, 0);

				rc = hltests_wait_for_cs_until_not_busy(fd,
									seq);
				assert_int_equal(rc,
						HL_WAIT_CS_STATUS_COMPLETED);
			}

			/* Send WTD packet */
			for (i = 0 ; i < nwq ; i++) {
				local_addr = local_conn_base + i * wqe_size;
				remote_addr = remote_conn_base + i * wqe_size;
				ackreq = !(i % 4);
				tag_idx = (nic * MAX_NUM_OF_QPS + qp) * nwq + i;
				conn_id = in_params->nic_conn->conn_id[nic][qp];

				/* embed the QP idx in the tag for the CQE */
				in_params->tag[tag_idx] &= tag_mask;
				in_params->tag[tag_idx] |= qp;

				if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
					fill_wtd_desc_wrrdv(&swtd, &dwtd, i, local_addr,
					remote_addr, wqe_size, conn_id,
					in_params->tag[tag_idx], ackreq,
					is_rdv_send);
				else if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ)
					fill_wtd_desc_rdrdv(&swtd, &dwtd, i, local_addr,
					remote_addr, wqe_size, conn_id,
					in_params->tag[tag_idx], ackreq);
				else
					fill_wtd_desc(&swtd, &dwtd, i, local_addr,
						remote_addr, wqe_size, conn_id,
						in_params->tag[tag_idx], ackreq);

				memset(restore_cb, 0, HL_MAX_CB_SIZE);
				restore_cb_size = 0;

				memset(db_buf, 0, HL_MAX_CB_SIZE);
				db_buf_size = 0;

				memset(dma_cb, 0, HL_MAX_CB_SIZE);
				dma_cb_size = 0;

				/* Clear SOB */
				memset(&pkt_info, 0, sizeof(pkt_info));
				pkt_info.eb = EB_FALSE;
				pkt_info.mb = MB_TRUE;
				pkt_info.write_to_sob.sob_id = first_sob;
				pkt_info.write_to_sob.value = 0;
				pkt_info.write_to_sob.mode = SOB_SET;
				restore_cb_size =
						hltests_add_write_to_sob_pkt(fd,
								restore_cb,
								restore_cb_size,
								&pkt_info);

				memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
				mon_and_fence_info.queue_id = GAUDI2_QUEUE_ID_NIC_0_0 + nic * 4;
				mon_and_fence_info.cmdq_fence = false;
				mon_and_fence_info.sob_id = first_sob;
				mon_and_fence_info.mon_id = first_mon;
				mon_and_fence_info.mon_address = 0;
				mon_and_fence_info.sob_val = 1;
				mon_and_fence_info.dec_fence = true;
				mon_and_fence_info.mon_payload = 1;
				mon_and_fence_info.mon_mode = SOB_EQUAL;
				/* Put a fence before the WTD packet */
				db_buf_size = hltests_add_monitor_and_fence(fd, db_buf,
							db_buf_size, &mon_and_fence_info);

				db_buf_size = add_bulk_swtd_pkt(db_buf, db_buf_size, &swtd);
				db_buf_size = add_bulk_dwtd_pkt(db_buf, db_buf_size, &dwtd);

				/* Activate SM - release fence */
				memset(&pkt_info, 0, sizeof(pkt_info));
				pkt_info.eb = EB_TRUE;
				pkt_info.mb = MB_TRUE;
				pkt_info.write_to_sob.sob_id = first_sob;
				pkt_info.write_to_sob.value = 1;
				pkt_info.write_to_sob.mode = SOB_SET;
				dma_cb_size = hltests_add_write_to_sob_pkt(fd,
							dma_cb, dma_cb_size,
							&pkt_info);

				restore_arr[0].cb_ptr = restore_cb;
				restore_arr[0].cb_size = restore_cb_size;
				restore_arr[0].queue_index =
					hltests_get_dma_down_qid(fd, STREAM0);

				execute_arr[0].cb_ptr = int_cb;
				execute_arr[0].cb_size = db_buf_size;
				execute_arr[0].queue_index =
					GAUDI2_QUEUE_ID_NIC_0_0 + nic * 4;

				execute_arr[1].cb_ptr = dma_cb;
				execute_arr[1].cb_size = dma_cb_size;
				execute_arr[1].queue_index =
					hltests_get_dma_down_qid(fd, STREAM0);

				rc = hltests_submit_cs(fd, restore_arr, 1,
					execute_arr, 2,
					HL_CS_FLAGS_FORCE_RESTORE, &seq);
				assert_int_equal(rc, 0);

				rc = hltests_wait_for_cs_until_not_busy(fd,
									seq);
				assert_int_equal(rc,
						HL_WAIT_CS_STATUS_COMPLETED);
			}
		}
		qps_till_now += qps_per_port;
		nic_idx++;
	}

	return rc;
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

static uint32_t gaudi2_add_sched_arc_nop_cmd(void *buffer, uint32_t buf_off,
					struct hltests_sched_arc_cmd_params *params)
{
	struct sched_arc_cmd_nop_t cmd;
	uint32_t padding_cnt_in_bytes, padding_cnt_in_dwords;

	padding_cnt_in_bytes = params->nop.padding_cnt_in_bytes;
	padding_cnt_in_dwords = padding_cnt_in_bytes >> 2;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = SCHED_ARC_CMD_NOP;
	cmd.padding_count = padding_cnt_in_dwords;

	buf_off = hltests_add_packet_to_cb(buffer, buf_off, &cmd, sizeof(cmd));

	memset((uint8_t *) buffer + buf_off, 0, padding_cnt_in_bytes);
	return buf_off + padding_cnt_in_bytes;
}

static uint32_t gaudi2_add_sched_arc_dispatch_static_ecb_list(void *buffer, uint32_t buf_off,
					struct hltests_sched_arc_cmd_params *params)
{
	struct sched_arc_cmd_dispatch_static_ecb_t cmd = {
		.opcode = SCHED_ARC_CMD_DISPATCH_STATIC_ECB,
		.engine_group_type = params->dispatch_static_ecb_list.engine_group_type,
		.size = params->dispatch_static_ecb_list.size,
		.engine_cpu_id = params->dispatch_static_ecb_list.engine_cpu_id,
		.addr = params->dispatch_static_ecb_list.addr,
	};

	return hltests_add_packet_to_cb(buffer, buf_off, &cmd, sizeof(cmd));
}

static int gaudi2_get_stream_master_qid_arr(uint32_t **qid_arr)
{
	return -1;
}

static uint32_t gaudi2_arc_get_cb_suffix_size(void)
{
	return SZ_4K; /* For now */
}

static uint32_t gaudi2_get_arcs_num(void)
{
	return NUM_ARC_CPUS;
}

static uint64_t gaudi2_get_arc_va_range_host_start(void)
{
	return RESERVED_VA_RANGE_FOR_ARC_ON_HOST_START;
}

static uint64_t gaudi2_get_arc_va_range_dram_start(void)
{
	return RESERVED_VA_RANGE_FOR_ARC_ON_HBM_START;
}

static int gaudi2_arc_get_cpu_id_eng_group(int fd, uint32_t queue_idx,
					uint32_t *cpu_id, uint32_t *eng_group)
{
	if (queue_idx >= ARRAY_SIZE(gaudi2_engine_arc_queue_to_cpu_id))
		return -EINVAL;

	*cpu_id = gaudi2_engine_arc_queue_to_cpu_id[queue_idx];

	if (*cpu_id >= ARRAY_SIZE(gaudi2_engine_arc_cpu_id_to_eng_group))
		return -EINVAL;

	*eng_group = gaudi2_engine_arc_cpu_id_to_eng_group[*cpu_id];

	return 0;
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

static enum gaudi2_red_op gaudi2_map_red_op(enum hltests_nic_reduction_operation red_op)
{
	switch (red_op) {
	case HLTESTS_NIC_REDUCTION_OP_ADDITION:
		return GAUDI2_NIC_REDUCTION_OP_ADDITION;

	case HLTESTS_NIC_REDUCTION_OP_SUBTRACTION:
		return GAUDI2_NIC_REDUCTION_OP_SUBSTRACTION;

	case HLTESTS_NIC_REDUCTION_OP_MINIMUM:
		return GAUDI2_NIC_REDUCTION_OP_MINIMUM;

	case HLTESTS_NIC_REDUCTION_OP_MAXIMUM:
		return GAUDI2_NIC_REDUCTION_OP_MAXIMUM;

	default:
		return GAUDI2_NIC_REDUCTION_OP_INVALID;
	}
}

static enum gaudi2_red_datatype gaudi2_map_red_dt(enum hltests_nic_reduction_datatype red_dt)
{
	switch (red_dt) {
	case HLTESTS_NIC_REDUCTION_INT8:
		return GAUDI2_NIC_REDUCTION_INT8;

	case HLTESTS_NIC_REDUCTION_BF16:
		return GAUDI2_NIC_REDUCTION_BF16;

	case HLTESTS_NIC_REDUCTION_FP32:
		return GAUDI2_NIC_REDUCTION_FP32;

	case HLTESTS_NIC_REDUCTION_UPSCALING_BF16:
		return GAUDI2_NIC_REDUCTION_UPSCALING_BF16;

	default:
		return GAUDI2_NIC_REDUCTION_DT_INVALID;
	}
}

static int gaudi2_nic_config_reduction(int fd, enum hltests_nic_reduction_operation red_op,
					enum hltests_nic_reduction_datatype red_data_type,
					uint64_t *reduction)
{
	enum gaudi2_red_op gaudi2_red_op;
	enum gaudi2_red_datatype gaudi2_red_dt;

	gaudi2_red_op = gaudi2_map_red_op(red_op);
	gaudi2_red_dt = gaudi2_map_red_dt(red_data_type);

	if (gaudi2_red_op == GAUDI2_NIC_REDUCTION_OP_INVALID)
		return -ENOTSUP;

	if (gaudi2_red_dt == GAUDI2_NIC_REDUCTION_DT_INVALID)
		return -ENOTSUP;

	*reduction = (REDUCTION_INDICATION_MSK |
			(gaudi2_red_dt & REDUCTION_DATA_TYPE_MSK) << REDUCTION_DATA_TYPE_SHIFT |
			(gaudi2_red_op & REDUCTION_OPERATION_MSK) << REDUCTION_OPERATION_SHIFT);

	return 0;
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
	/* Gaudi2's PDMA supports streams rather than the channels
	 * supported in Gaudi3's PDMA, for that matter we shall return 0.
	 */
	return 0;
}

uint32_t gaudi2_get_max_pkt_size(int fd, bool mb, bool eb, uint32_t qid)
{
	return sizeof(struct packet_lin_dma);
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
static uint32_t gaudi2_nic_get_hw_wq_pi(uint32_t nwqs, uint32_t wq_size, uint32_t iteration,
					uint32_t cmpl, bool is_bp_offs)
{
	return ((cmpl != SOB || is_bp_offs) ? nwqs :
			((++iteration) * (nwqs >> HL_LOG2(DB_ITER_PER_CYCLE))) &
			(wq_size - 1));
}

static uint8_t gaudi2_nic_get_db_fifo_element_size(void)
{
	return DB_FIFO_ELEMENT_SIZE;
}

static uint32_t gaudi2_nic_get_db_fifo_entry_size(void)
{
	return GAUDI2_DB_FIFO_ENTRY_SIZE;
}

void gaudi2_nic_parse_eqe_qp_syndrome(uint32_t port, struct hlthunk_nic_eq_poll_out *eqe)
{
	uint32_t syndrome = eqe->ev_data;
	int syndrome_type;
	char *str;

	/* syndrome comprised from 8 bits
	 * [2:type, 6:syndrome]
	 * 6 bits for syndrome
	 * 2 bits for type
	 *   0 - rx packet error
	 *   1 - qp error
	 *   2 - tx packet error
	 */

	if (syndrome >= MAX_SYNDROMS) {
		syndrome_type = SYNDROME_TYPE(syndrome);

		switch (syndrome_type) {
		case 0:
			str = "RX packet syndrome unknown";
			break;
		case 1:
			str = "QPC syndrome unknown";
			break;
		case 2:
			str = "TX packet syndrome unknown";
			break;
		default:
			str = "syndrome unknown";
			break;
		}
	} else {
		str = qp_syndroms[syndrome];
	}

	printf("Port %u: got QP %u error: %s\n",
		port, eqe->idx, str);

}

static uint32_t gaudi2_nic_read_mem_cmpl(int fd, uint32_t idx, uint8_t *blk)
{
	uint32_t reg_val = 0, reg_offset, *reg_ptr;
	int rc;
	uint64_t objs_base;

	objs_base = mmDCORE0_SYNC_MNGR_OBJS_BASE - CFG_BASE;
	reg_offset = mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_ADDRL_0 + (idx * sizeof(uint32_t));

	reg_ptr = (void *) (blk + ((reg_offset - objs_base)));

	rc = hltests_read_lbw_reg(fd, reg_ptr, &reg_val);
	assert_int_equal(rc, 0);

	return reg_val;
}

static uint32_t gaudi2_nic_get_mem_cmpl_addr(int fd, uint32_t idx)
{
	uint32_t reg_offset;
	uint64_t objs_base;

	objs_base = mmDCORE0_SYNC_MNGR_OBJS_BASE - CFG_BASE;
	reg_offset = mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_ADDRL_0 + (idx * sizeof(uint32_t));

	return (mmDCORE1_SYNC_MNGR_OBJS_BASE + (reg_offset - objs_base)) &
		GAUDI2_MEM_CMPL_ADDR_OFF_MASK;
}

static uint8_t *gaudi2_nic_map_lbw_block(int fd, uint32_t *sm_obj_size)
{
	return hltests_map_hw_block(fd, mmDCORE1_SYNC_MNGR_OBJS_BASE, sm_obj_size);
}

static int gaudi2_nic_unmap_lbw_block(int fd, void *host_addr, uint32_t block_size)
{
	return hltests_unmap_hw_block(fd, host_addr, block_size);
}

static uint16_t gaudi2_cq_db_get_available_sob(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	uint16_t sob = hltests_get_first_avail_sob(fd);

	hdev->counters.reserved_sobs++;

	return sob;
}

static uint16_t gaudi2_cq_db_get_available_mon(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	uint16_t mon = hltests_get_first_avail_mon(fd);

	hdev->counters.reserved_mons++;

	return mon;
}

static uint32_t gaudi2_add_cq_db_set_cq_queue_pkt(void *buffer, uint32_t buf_off,
		struct hltests_cq_config *cq_config, uint16_t sob_id)
{
	struct hltests_pkt_info pkt_info = {};
	uint64_t sob_addr;
	uint32_t offset;

	offset = cq_config->cq_id * 4;
	sob_addr = CFG_BASE + mmDCORE0_SYNC_MNGR_OBJS_SOB_OBJ_0 + (sob_id * 4);
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
	pkt_info.msg_long.value = lower_32_bits(sob_addr);
	pkt_info.msg_long.address =
			CFG_BASE + mmDCORE0_SYNC_MNGR_GLBL_LBW_ADDR_L_0 + offset;
	buf_off = gaudi2_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = upper_32_bits(sob_addr);
	pkt_info.msg_long.address =
			CFG_BASE + mmDCORE0_SYNC_MNGR_GLBL_LBW_ADDR_H_0 + offset;
	buf_off = gaudi2_add_msg_long_pkt(buffer, buf_off, &pkt_info);

	pkt_info.msg_long.value = 0x80000001;
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

static uint16_t gaudi2_cq_db_get_available_cq(int fd)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	uint16_t cq = hltests_get_first_avail_cq(fd);

	hdev->counters.reserved_cqs++;

	return cq;
}

static void gaudi2_nic_clear_lbw_memory(int fd, uint8_t *sm_obj_base, uint32_t idx,
					uint32_t num_elements)
{
	uint32_t reg_offset, *reg_ptr, i;
	uint64_t objs_base;

	objs_base = mmDCORE0_SYNC_MNGR_OBJS_BASE - CFG_BASE;

	for (i = 0 ; i < num_elements ; i++) {
		reg_offset = mmDCORE0_SYNC_MNGR_OBJS_MON_PAY_ADDRL_0 +
				((i + idx) * sizeof(uint32_t));
		reg_ptr = (void *) (sm_obj_base + ((reg_offset - objs_base)));

		hltests_write_lbw_reg(fd, reg_ptr, 0);
	}
}

static void gaudi2_nic_fill_bp_offs_params(int fd, uint32_t port, uint32_t *bp_offs_base_id,
						uint32_t *num_bp_offs)
{
	*bp_offs_base_id = 0;
	*num_bp_offs = GAUDI2_NUM_MAX_BP_OFFS;
}

static uint64_t gaudi2_get_hbw_rr_addr(void)
{
	return PCIE_FW_SRAM_ADDR;
}

static uint64_t gaudi2_get_lbw_rr_addr(void)
{
	return mmNIC0_TX_AXUSER_BASE;
}

static uint64_t gaudi2_get_addr_dec_err_addr(void)
{
	return BAR0_RSRVD_BASE_ADDR;
}

static uint64_t gaudi2_get_tpc_intr_cause_reg(uint32_t tpc_idx)
{
	uint8_t dcore_id = tpc_idx / NUM_OF_TPC_PER_DCORE;
	uint8_t tpc_id = tpc_idx - (dcore_id * NUM_OF_TPC_PER_DCORE);

	return CFG_BASE + mmDCORE0_TPC0_CFG_TPC_INTR_CAUSE +
		tpc_id * DCORE_TPC_OFFSET + dcore_id * DCORE_OFFSET;
}

static uint16_t gaudi2_qid_to_eid(uint16_t qid)
{
	uint16_t index;

	switch (qid) {
	case GAUDI2_QUEUE_ID_PDMA_0_0 ... GAUDI2_QUEUE_ID_PDMA_0_3:
		return GAUDI2_ENGINE_ID_PDMA_0;
	case GAUDI2_QUEUE_ID_PDMA_1_0 ... GAUDI2_QUEUE_ID_PDMA_1_3:
		return GAUDI2_ENGINE_ID_PDMA_1;
	case GAUDI2_QUEUE_ID_DCORE0_EDMA_0_0 ... GAUDI2_QUEUE_ID_DCORE0_EDMA_0_3:
		return GAUDI2_DCORE0_ENGINE_ID_EDMA_0;
	case GAUDI2_QUEUE_ID_DCORE0_EDMA_1_0 ... GAUDI2_QUEUE_ID_DCORE0_EDMA_1_3:
		return GAUDI2_DCORE0_ENGINE_ID_EDMA_1;
	case GAUDI2_QUEUE_ID_DCORE0_MME_0_0 ... GAUDI2_QUEUE_ID_DCORE0_MME_0_3:
		return GAUDI2_DCORE0_ENGINE_ID_MME;
	case GAUDI2_QUEUE_ID_DCORE0_TPC_0_0 ... GAUDI2_QUEUE_ID_DCORE0_TPC_5_3:
		index = (qid - GAUDI2_QUEUE_ID_DCORE0_TPC_0_0) >> 2;
		return GAUDI2_DCORE0_ENGINE_ID_TPC_0 + index;
	case GAUDI2_QUEUE_ID_DCORE1_EDMA_0_0 ... GAUDI2_QUEUE_ID_DCORE1_EDMA_0_3:
		return GAUDI2_DCORE1_ENGINE_ID_EDMA_0;
	case GAUDI2_QUEUE_ID_DCORE1_EDMA_1_0 ... GAUDI2_QUEUE_ID_DCORE1_EDMA_1_3:
		return GAUDI2_DCORE1_ENGINE_ID_EDMA_1;
	case GAUDI2_QUEUE_ID_DCORE1_MME_0_0 ... GAUDI2_QUEUE_ID_DCORE1_MME_0_3:
		return GAUDI2_DCORE1_ENGINE_ID_MME;
	case GAUDI2_QUEUE_ID_DCORE1_TPC_0_0 ... GAUDI2_QUEUE_ID_DCORE1_TPC_5_3:
		index = (qid - GAUDI2_QUEUE_ID_DCORE1_TPC_0_0) >> 2;
		return GAUDI2_DCORE1_ENGINE_ID_TPC_0 + index;
	case GAUDI2_QUEUE_ID_DCORE2_EDMA_0_0 ... GAUDI2_QUEUE_ID_DCORE2_EDMA_0_3:
		return GAUDI2_DCORE2_ENGINE_ID_EDMA_0;
	case GAUDI2_QUEUE_ID_DCORE2_EDMA_1_0 ... GAUDI2_QUEUE_ID_DCORE2_EDMA_1_3:
		return GAUDI2_DCORE2_ENGINE_ID_EDMA_1;
	case GAUDI2_QUEUE_ID_DCORE2_MME_0_0 ... GAUDI2_QUEUE_ID_DCORE2_MME_0_3:
		return GAUDI2_DCORE2_ENGINE_ID_MME;
	case GAUDI2_QUEUE_ID_DCORE2_TPC_0_0 ... GAUDI2_QUEUE_ID_DCORE2_TPC_5_3:
		index = (qid - GAUDI2_QUEUE_ID_DCORE2_TPC_0_0) >> 2;
		return GAUDI2_DCORE2_ENGINE_ID_TPC_0 + index;
	case GAUDI2_QUEUE_ID_DCORE3_EDMA_0_0 ... GAUDI2_QUEUE_ID_DCORE3_EDMA_0_3:
		return GAUDI2_DCORE3_ENGINE_ID_EDMA_0;
	case GAUDI2_QUEUE_ID_DCORE3_EDMA_1_0 ... GAUDI2_QUEUE_ID_DCORE3_EDMA_1_3:
		return GAUDI2_DCORE3_ENGINE_ID_EDMA_1;
	case GAUDI2_QUEUE_ID_DCORE3_MME_0_0 ... GAUDI2_QUEUE_ID_DCORE3_MME_0_3:
		return GAUDI2_DCORE3_ENGINE_ID_MME;
	case GAUDI2_QUEUE_ID_DCORE3_TPC_0_0 ... GAUDI2_QUEUE_ID_DCORE3_TPC_5_3:
		index = (qid - GAUDI2_QUEUE_ID_DCORE3_TPC_0_0) >> 2;
		return GAUDI2_DCORE3_ENGINE_ID_TPC_0 + index;
	case GAUDI2_QUEUE_ID_NIC_0_0 ... GAUDI2_QUEUE_ID_NIC_23_3:
		index = (qid - GAUDI2_QUEUE_ID_NIC_0_0) >> 4;
		return GAUDI2_ENGINE_ID_NIC0_0 + index;
	case GAUDI2_QUEUE_ID_ROT_0_0 ... GAUDI2_QUEUE_ID_ROT_0_3:
		return GAUDI2_ENGINE_ID_ROT_0;
	case GAUDI2_QUEUE_ID_ROT_1_0 ... GAUDI2_QUEUE_ID_ROT_1_3:
		return GAUDI2_ENGINE_ID_ROT_1;
	default: return GAUDI2_ENGINE_ID_SIZE;
	}
}

static uint64_t gaudi2_get_razwi_addr(enum err_trigger type)
{
	uint64_t addr;

	switch (type) {
	case RAZWI_TYPE_LBW_RR:
		addr = gaudi2_get_lbw_rr_addr();
		break;
	case RAZWI_TYPE_HBW_RR:
		addr = gaudi2_get_hbw_rr_addr();
		break;
	case RAZWI_TYPE_ADDR_DEC:
		addr = gaudi2_get_addr_dec_err_addr();
		break;
	default:
		addr = ULONG_MAX;
	}

	return addr;
}

static uint64_t gaudi2_get_pb_secured_addr(void)
{
	return CFG_BASE + mmDCORE0_MME_QM_GLBL_CFG0;
}

static int gaudi2_edp_get_engines_list(int fd, uint32_t **engine_ids, uint32_t *engine_ids_size)
{
	uint32_t engine_idx = 0, tpcs_max_num, mmes_max_num, edmas_max_num,
		tpcs_curr_num, mmes_curr_num, edmas_curr_num;
	struct hlthunk_hw_ip_info hw_ip;
	int i, rc = 0;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	if (rc)
		return rc;

	/* It's reasonable to assume that when it comes to Gaudi2, the list of engines for EDP
	 * test will always include the maximum possible number of engines.
	 */
	tpcs_max_num = gaudi2_get_tpc_cnt(fd, DCORE_MODE_FULL_CHIP) - 1;
	tpcs_curr_num = (uint32_t)__builtin_popcountll(hw_ip.tpc_enabled_mask_ext);
	if (tpcs_max_num != tpcs_curr_num) {
		printf("Number of enabled TPCs is %u, but should be %u!\n",
				tpcs_curr_num, tpcs_max_num);
		return -EINVAL;
	}

	mmes_max_num = gaudi2_get_mme_cnt(fd, DCORE_MODE_FULL_CHIP, hw_ip.mme_master_slave_mode);
	mmes_curr_num = (uint32_t)__builtin_popcount(hw_ip.mme_enabled_mask);
	if (mmes_max_num != mmes_curr_num) {
		printf("Number of enabled MMEs is %u, but should be %u!\n",
				mmes_curr_num, mmes_max_num);
		return -EINVAL;
	}

	edmas_max_num = gaudi2_get_ddma_cnt(fd, DCORE_MODE_FULL_CHIP);
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

	/* Fill-in the list with relevant engines ids */
	for (i = 0 ; i < tpcs_max_num ; ++i)
		(*engine_ids)[engine_idx++] = gaudi2_tpc_id_to_engine_id[i];

	for (i = 0 ; i < mmes_max_num ; ++i)
		(*engine_ids)[engine_idx++] = gaudi2_mme_id_to_engine_id[i];

	for (i = 0 ; i < edmas_max_num ; ++i)
		(*engine_ids)[engine_idx++] = gaudi2_edma_id_to_engine_id[i];

	return 0;
}

static int submit_wtd_cb(int fd, uint32_t qid, void *swtd, void *dwtd)
{
	void *cb;
	uint64_t seq, timeout;
	uint32_t cb_size = 0;
	int rc;

	cb = hltests_create_cb(fd, HL_MAX_CB_SIZE, INTERNAL, 0);
	assert_non_null(cb);

	cb_size = add_bulk_swtd_pkt(cb, cb_size, swtd);
	cb_size = add_bulk_dwtd_pkt(cb, cb_size, dwtd);

	rc = hltests_submit_cb(fd, cb, cb_size, qid, 0, &seq);
	assert_int_equal(rc, 0);

	timeout = hltests_is_pldm(fd) ? NIC_PDMA_TIMEOUT_PLDM_USEC : NIC_PDMA_TIMEOUT_USEC;
	rc = hltests_wait_for_cs(fd, seq, timeout);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_destroy_cb(fd, cb);

	return rc;
}

static void convert_wqe_to_wtd(struct hltests_nic_qp *qp_p, struct sq_wqe *swqe,
				struct rq_wqe *rwqe, struct wtd_static *swtd,
				struct wtd_dynamic *dwtd)
{
	memset(swtd, 0, sizeof(*swtd));

	swtd->local_address_31_0 = swqe->local_address_31_0;
	swtd->local_address_63_32 = swqe->local_address_63_32;
	swtd->remote_address_31_0 = swqe->remote_address_31_0;
	swtd->remote_address_63_32 = swqe->remote_address_63_32;

	swtd->pt = 0x3;
	swtd->ackreq = swqe->ackreq & 0x1ULL;
	swtd->in_line = swqe->in_line;
	swtd->reduction_opcode = swqe->reduction_opcode;

	swtd->send_opcode = swqe->opcode;
	swtd->send_wqe_index = swqe->wqe_index & 0xffULL;
	swtd->send_completion_type = swqe->completion_type;
	swtd->send_tag = swqe->tag;
	swtd->remote_completion_addr = swqe->remote_sync_object;
	swtd->send_sync_object_data = swqe->remote_sync_object_data;
	swtd->send_sob_command = swqe->sob_command;

	swtd->rcv_opcode = rwqe->opcode;
	swtd->rcv_wqe_index = rwqe->wqe_index & 0xffULL;
	swtd->rcv_completion_type = rwqe->completion_type;
	swtd->rcv_tag = rwqe->tag;
	swtd->rcv_sync_object_addr = rwqe->local_sync_object;
	swtd->rcv_sync_object_data = rwqe->local_sync_object_data;
	swtd->rcv_sob_command = rwqe->sob_command;

	memset(dwtd, 0, sizeof(*dwtd));

	dwtd->qp_number = qp_p->conn_id & 0xffffffULL;
	dwtd->send_size = swqe->size;
	dwtd->rcv_size = rwqe->size;
}

static int gaudi2_nic_submit_wtd(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg;
	struct wtd_static swtd;
	struct wtd_dynamic dwtd;
	struct sq_wqe *swqe;
	struct rq_wqe *rwqe;
	struct hltests_nic_qp *qp_p;
	uint32_t port, qp, qps_per_port, base_nic_qid, wq_size, wqe, nic_qid, pi;
	int fd, rc, port_idx;

	cfg = params->cfg;
	fd = params->fd;
	base_nic_qid = hltests_nic_get_base_qid(fd);

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];
		qps_per_port = params->num_qps_per_port[port];
		nic_qid = base_nic_qid + port * 4;

		for (qp = 0 ; qp < qps_per_port ; qp++) {
			qp_p = &params->qps[port][qp];
			wq_size = qp_p->req_ctx.wq_size;

			for (pi = qp_p->curr_pi ; pi < qp_p->dest_pi ; pi++) {
				wqe = pi & (wq_size - 1);

				swqe = gaudi2_nic_get_swqe(qp_p->swq_buf, wqe);
				rwqe = gaudi2_nic_get_rwqe(qp_p->rwq_buf, wqe);

				convert_wqe_to_wtd(qp_p, swqe, rwqe, &swtd, &dwtd);

				rc = submit_wtd_cb(fd, nic_qid, &swtd, &dwtd);
				if (rc)
					return rc;
			}
		}
	}

	hltests_nic_print_time_elapsed(&params->base, "submit WTD", cfg->verbose);

	return 0;
}

static int submit_qman_db(struct hltests_nic_test_params *params)
{
	struct hltests_cs_chunk execute_arr[MAX_NIC_NUMBER_OF_PORTS];
	void *cb[MAX_NIC_NUMBER_OF_PORTS], *cb_p;
	struct hltests_nic_test_cfg *cfg;
	struct hltests_device *hdev;
	struct hltests_nic_qp *qp_p;
	uint64_t seq, timeout;
	uint32_t port, base_nic_qid, cb_size, qp, qps_per_port, max_pi, pi;
	int fd, rc, port_idx;

	fd = params->fd;
	hdev = get_hdev_from_fd(fd);
	cfg = params->cfg;
	base_nic_qid = hltests_nic_get_base_qid(fd);

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		cb_p = hltests_create_cb(fd, HL_MAX_CB_SIZE, INTERNAL, 0);
		assert_non_null(cb_p);
		cb_size = 0;

		port = cfg->ports[port_idx];
		qps_per_port = params->num_qps_per_port[port];

		for (qp = 0 ; qp < qps_per_port ; qp++) {
			qp_p = &params->qps[port][qp];

			/* Skip in case there is no work to be submitted */
			if (qp_p->dest_pi == qp_p->curr_pi)
				continue;

			max_pi = hdev->asic_funcs->nic_funcs->get_max_pi(qp_p);
			pi = qp_p->dest_pi & (max_pi - 1);

			cb_size = hltests_nic_add_bulk_doorbell_pkt(fd, cb_p, cb_size, port,
									qp_p->conn_id, pi);
		}

		execute_arr[port_idx].cb_ptr = cb_p;
		execute_arr[port_idx].cb_size = cb_size;
		execute_arr[port_idx].queue_index = base_nic_qid + port * 4;

		/* save cb pointer for the destroy_cb */
		cb[port_idx] = cb_p;
	}

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, port_idx, 0, &seq);
	assert_int_equal(rc, 0);

	timeout = hltests_is_pldm(fd) ? NIC_PDMA_TIMEOUT_PLDM_USEC : NIC_PDMA_TIMEOUT_USEC;
	rc = hltests_wait_for_cs(fd, seq, timeout);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		rc = hltests_destroy_cb(fd, cb[port_idx]);
		assert_int_equal(rc, 0);
	}

	hltests_nic_print_time_elapsed(&params->base, "submit db via QMAN", cfg->verbose);

	return 0;
}

static int gaudi2_nic_submit_db(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	int rc;

	if (cfg->submission == QMAN)
		rc = submit_qman_db(params);
	else
		rc = nic_common_generic_submit_user_fifo_db(params);

	return rc;
}

static void gaudi2_nic_write_desc_to_db_fifo(struct hltests_state *tests_state,
					     struct hltests_nic_db_fifo_data *db_fifo,
					     struct hltests_nic_db_fifo_packet *db_fifo_packet,
					     uint32_t port, bool is_dup)
{
	hltests_nic_write_desc_to_db_fifo_default(tests_state, db_fifo, db_fifo_packet, port,
						  is_dup);
}

static struct hltests_nic_asic_funcs gaudi2_nic_funcs = {
	.asic_priv_init = gaudi2_nic_asic_priv_init,
	.get_default_cfg = gaudi2_nic_get_default_cfg,
	.run_wtd = gaudi2_nic_run_wtd,
	.run_coll_op = NULL,
	.get_max_num_of_ports = gaudi2_nic_get_max_num_of_ports,
	.get_port_mask = gaudi2_nic_get_port_mask,
	.get_base_qid = gaudi2_nic_get_base_qid,
	.get_wq_offset = gaudi2_nic_get_wq_offset,
	.fill_wqe = gaudi2_nic_fill_wqe,
	.get_swqe = gaudi2_nic_get_swqe,
	.get_rwqe = gaudi2_nic_get_rwqe,
	.get_swqe_size = gaudi2_nic_get_swqe_size,
	.get_rwqe_size = gaudi2_nic_get_rwqe_size,
	.get_max_pi = gaudi2_nic_get_max_pi,
	.get_min_conn_id = gaudi2_nic_get_min_conn_id,
	.get_max_conn_id = gaudi2_nic_get_max_conn_id,
	.get_max_num_of_qps = gaudi2_nic_get_max_num_of_qps,
	.get_min_coll_conn_id = NULL,
	.get_max_coll_conn_id = NULL,
	.get_coll_qps_offset = NULL,
	.get_max_num_of_coll_qps = NULL,
	.pre_setup_ctx = gaudi2_nic_pre_setup_ctx,
	.pre_setup_default_ctx_rdv = gaudi2_nic_pre_setup_default_ctx_rdv,
	.setup_ctx_lpbk = gaudi2_nic_setup_ctx_lpbk,
	.setup_ctx_e2e = gaudi2_nic_setup_ctx_e2e,
	.setup_default_ctx_rdv = gaudi2_nic_setup_default_ctx_rdv,
	.get_user_cqe = gaudi2_nic_get_user_cqe,
	.user_cq_create = gaudi2_nic_user_cq_create,
	.user_cq_destroy = gaudi2_nic_user_cq_destroy,
	.add_bulk_doorbell_pkt = gaudi2_nic_add_bulk_doorbell_pkt,
	.get_db_fifo_umr = gaudi2_nic_get_db_fifo_umr,
	.get_db_fifo_dup = NULL,
	.get_db_fifo_entry_size = gaudi2_nic_get_db_fifo_entry_size,
	.get_db_fifo_element_size = gaudi2_nic_get_db_fifo_element_size,
	.get_hw_wq_pi = gaudi2_nic_get_hw_wq_pi,
	.config_reduction = gaudi2_nic_config_reduction,
	.clear_lbw_memory = gaudi2_nic_clear_lbw_memory,
	.create_dwq_packet = NULL,
	.parse_eqe_qp_syndrome = gaudi2_nic_parse_eqe_qp_syndrome,
	.read_mem_cmpl = gaudi2_nic_read_mem_cmpl,
	.get_mem_cmpl_addr = gaudi2_nic_get_mem_cmpl_addr,
	.map_lbw_block = gaudi2_nic_map_lbw_block,
	.unmap_lbw_block = gaudi2_nic_unmap_lbw_block,
	.get_half_port_mask = NULL,
	.fill_bp_offs_params = gaudi2_nic_fill_bp_offs_params,
	.ovrd_wqes_data_size = NULL,
	.submit_wtd = gaudi2_nic_submit_wtd,
	.submit_db = gaudi2_nic_submit_db,
	.write_desc_to_db_fifo = gaudi2_nic_write_desc_to_db_fifo,
};

static const struct hltests_asic_funcs gaudi2_funcs = {
	.add_arb_en_pkt = gaudi2_add_arb_en_pkt,
	.add_cq_config_pkt = gaudi2_add_cq_config_pkt,
	.add_pdma_ch_bw_config_pkt = NULL,
	.add_monitor_and_fence = gaudi2_add_monitor_and_fence,
	.add_monitor = gaudi2_add_monitor,
	.get_fence_addr = gaudi2_get_fence_addr,
	.add_nop_pkt = gaudi2_add_nop_pkt,
	.add_undef_opcode_pkt = gaudi2_add_undef_opcode_pkt,
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
	.get_nic_qid = gaudi2_get_nic_qid,
	.get_tpc_cnt = gaudi2_get_tpc_cnt,
	.get_mme_cnt = gaudi2_get_mme_cnt,
	.get_first_avail_sob = gaudi2_get_first_avail_sob,
	.get_first_avail_mon = gaudi2_get_first_avail_mon,
	.get_first_avail_cq = gaudi2_get_first_avail_cq,
	.get_sob_base_addr = gaudi2_get_sob_base_addr,
	.get_any_mappable_hw_block_base_addr = gaudi2_get_any_mappable_hw_block_base_addr,
	.get_cache_line_size = gaudi2_get_cache_line_size,
	.asic_priv_init = gaudi2_asic_priv_init,
	.asic_priv_fini = gaudi2_asic_priv_fini,
	.dram_pool_alloc = gaudi2_dram_pool_alloc,
	.dram_pool_free = gaudi2_dram_pool_free,
	.va_pool_alloc = gaudi2_va_pool_alloc,
	.va_pool_free = gaudi2_va_pool_free,
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
	.add_sched_arc_nop_cmd = gaudi2_add_sched_arc_nop_cmd,
	.add_sched_arc_dispatch_static_ecb_list = gaudi2_add_sched_arc_dispatch_static_ecb_list,
	.get_arc_cb_suffix_size = gaudi2_arc_get_cb_suffix_size,
	.arc_get_max_cpuid = gaudi2_get_arcs_num,
	.arc_get_va_range_host_start = gaudi2_get_arc_va_range_host_start,
	.arc_get_va_range_dram_start = gaudi2_get_arc_va_range_dram_start,
	.arc_get_sched_cpuid_range = gaudi2_arc_get_sched_cpuid_range,
	.arc_get_engine_cpuid_range = gaudi2_arc_get_engine_cpuid_range,
	.set_arc_asic_fw_load_params = gaudi2_set_arc_asic_fw_load_params,
	.asic_load_fw_to_arcs = gaudi2_asic_load_fw_to_arcs,
	.arc_set_asic_model = gaudi2_arc_set_asic_model,
	.arc_set_regions = gaudi2_arc_set_regions,
	.arc_set_config = gaudi2_arc_set_config,
	.arc_map_lbw_blocks = gaudi2_arc_map_lbw_blocks,
	.arc_get_num_schedulers = gaudi2_get_num_scheduler_arcs,
	.wait_arc_run_done = gaudi2_wait_arc_run_done,
	.arc_activate = gaudi2_arc_activate,
	.arc_unmap_lbw_blocks = gaudi2_arc_unmap_lbw_blocks,
	.arc_set_enabled_cores = gaudi2_arc_set_enabled_cores,
	.arc_configure_scheduler_streams = gaudi2_arc_configure_scheduler_streams,
	.pdma_get_max_ch_id = gaudi2_pdma_get_max_ch_id,
	.pdma_map_lbw_blocks = NULL,
	.pdma_unmap_lbw_blocks = NULL,
	.pdma_config_ch_blocks = NULL,
	.arc_get_cpu_id_eng_group = gaudi2_arc_get_cpu_id_eng_group,
	.get_tc_base_addr = gaudi2_get_tc_base_addr,
	.get_async_event_id = gaudi2_get_async_event_id,
	.get_cq_patch_size = gaudi2_get_cq_patch_size,
	.get_max_pkt_size = gaudi2_get_max_pkt_size,
	.add_direct_write_cq_pkt = NULL,
	.monitor_dma_test_progress = NULL,
	.cq_db_get_available_sob = gaudi2_cq_db_get_available_sob,
	.cq_db_get_available_mon = gaudi2_cq_db_get_available_mon,
	.cq_db_get_available_cq = gaudi2_cq_db_get_available_cq,
	.add_cq_db_set_cq_queue_pkt = gaudi2_add_cq_db_set_cq_queue_pkt,
	.mme_dma_init = NULL,
	.prepare_mme_dma_req = NULL,
	.get_razwi_addr = gaudi2_get_razwi_addr,
	.get_pb_secured_addr = gaudi2_get_pb_secured_addr,
	.edp_get_engines_list = gaudi2_edp_get_engines_list,
	.get_tpc_intr_cause_reg = gaudi2_get_tpc_intr_cause_reg,
	.qid_to_eid = gaudi2_qid_to_eid,
	.nic_funcs = &gaudi2_nic_funcs,
};

void gaudi2_tests_set_asic_funcs(struct hltests_device *hdev)
{
	hdev->asic_funcs = &gaudi2_funcs;
}
