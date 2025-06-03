/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2021 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#include "gaudi2/asic_reg/gaudi2_regs.h"

#include "gaudi2/asic_reg/gaudi2_blocks.h"

#include "sched_asic_specific_data.h"

#include "arc_queue_local.h"
#include "gaudi2/gaudi2_arc_common_packets.h"

struct arc_sched_regs gaudi2_sched_regs = {
	.defs = {
		.dccm_qs_in_use = SCHED_QUEUES_IN_USE,
		.dccm_q_act_size = SCHED_QUEUE_SIZE,
	},

	.dccm_queue = {
		.base_addr = mmARC_FARM_ARC0_AUX_DCCM_QUEUE_BASE_ADDR_0,
		.size = mmARC_FARM_ARC0_AUX_DCCM_QUEUE_SIZE_0,
		.ci = mmARC_FARM_ARC0_AUX_DCCM_QUEUE_CI_0,
		.pi = mmARC_FARM_ARC0_AUX_DCCM_QUEUE_PI_0,
	},

	.arc_num = mmARC_FARM_ARC0_AUX_ARC_NUM,
	.inflight_lbu_wr_cnt = mmARC_FARM_ARC0_AUX_INFLIGHT_LBU_WR_CNT,
	.valid_entries = mmARC_FARM_ARC0_AUX_DCCM_QUEUE_VALID_ENTRIES_0,
};
