/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2021 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#include "gaudi2/asic_reg/gaudi2_regs.h"

#include "gaudi2/asic_reg/gaudi2_blocks.h"

#include "eng_asic_specific_data.h"

struct arc_eng_regs gaudi2_eng_regs = {
	.arc_cq = {
		.lbu_arc_cq_ptr_lo = mmDCORE0_MME_QM_ARC_CQ_PTR_LO,
		.lbu_arc_cq_ptr_hi = mmDCORE0_MME_QM_ARC_CQ_PTR_HI,
		.lbu_arc_cq_tsize = mmDCORE0_MME_QM_ARC_CQ_TSIZE,
		.lbu_arc_cq_ctl = mmDCORE0_MME_QM_ARC_CQ_CTL,
	},
	.mme_qm = {
		.arc_num = mmDCORE0_MME_QM_ARC_AUX_ARC_NUM,
		.arc_cq_shadow_ci = mmDCORE0_MME_QM_ARC_AUX_QMAN_ARC_CQ_SHADOW_CI,
		.ififo_shadow_ci = mmDCORE0_MME_QM_ARC_AUX_QMAN_CQ_IFIFO_SHADOW_CI,
		.arc_cq_cfg0 = mmDCORE0_MME_QM_ARC_CQ_CFG0,
		.ififo_ci = mmDCORE0_MME_QM_ARC_CQ_IFIFO_CI,
		.cp_ext_switch = mmDCORE0_MME_QM_CP_EXT_SWITCH,
		.cq_cfg0 = mmDCORE0_MME_QM_CQ_CFG0_4,
	},
	.dccm_queue = {
		.base_addr = mmDCORE0_MME_QM_ARC_AUX_DCCM_QUEUE_BASE_ADDR_0,
		.size = mmDCORE0_MME_QM_ARC_AUX_DCCM_QUEUE_SIZE_0,
		.ci = mmDCORE0_MME_QM_ARC_AUX_DCCM_QUEUE_CI_0,
		.pi = mmDCORE0_MME_QM_ARC_AUX_DCCM_QUEUE_PI_0,
	},

	.inflight_lbu_wr_cnt = mmDCORE0_MME_QM_ARC_AUX_INFLIGHT_LBU_WR_CNT,
};
