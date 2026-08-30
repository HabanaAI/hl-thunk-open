/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2021 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#include "gaudi3/asic_reg/gaudi3_regs.h"
#include "gaudi3/asic_reg/gaudi3_blocks.h"
#include "gaudi3/gaudi3_arc_common_packets.h"

#include "eng_asic_specific_data.h"

struct arc_eng_regs gaudi3_eng_regs = {
	.arc_cq = {
		.lbu_arc_cq_ptr_lo = mmQMAN_ARC_CQ_PTR_LO,
		.lbu_arc_cq_ptr_hi = mmQMAN_ARC_CQ_PTR_HI,
		.lbu_arc_cq_tsize = mmQMAN_ARC_CQ_TSIZE,
		.lbu_arc_cq_ctl = mmQMAN_ARC_CQ_CTL,
	},
	.mme_qm = {
		.arc_num = mmQMAN_ARC_AUX_ARC_NUM,
		.arc_cq_shadow_ci = mmQMAN_ARC_AUX_QMAN_ARC_CQ_SHADOW_CI,
		.ififo_shadow_ci = mmQMAN_ARC_AUX_QMAN_CQ_IFIFO_SHADOW_CI,
		.arc_cq_cfg0 = mmQMAN_ARC_CQ_CFG0,
		.ififo_ci = mmQMAN_ARC_CQ_IFIFO_CI,
		.cp_ext_switch = mmQMAN_CP_EXT_SWITCH,
		.cq_cfg0 = mmQMAN_CQ_CFG0,
	},
	.dccm_queue = {
		.base_addr = mmQMAN_ARC_AUX_DCCM_QUEUE_BASE_ADDR_0,
		.size = mmQMAN_ARC_AUX_DCCM_QUEUE_SIZE_0,
		.ci = mmQMAN_ARC_AUX_DCCM_QUEUE_CI_0,
		.pi = mmQMAN_ARC_AUX_DCCM_QUEUE_PI_0,
	},

	.inflight_lbu_wr_cnt = mmQMAN_ARC_AUX_INFLIGHT_LBU_WR_CNT,
};
