/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2021 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#include "gaudi3/asic_reg/gaudi3_regs.h"
#include "gaudi3/asic_reg/gaudi3_blocks.h"
#include "gaudi3/gaudi3_arc_common_packets.h"

#include "sched_asic_specific_data.h"

#include "arc_queue_local.h"

struct arc_sched_regs gaudi3_sched_regs = {
	.defs = {
		.dccm_qs_in_use = SCHED_QUEUES_IN_USE,
		.dccm_q_act_size = SCHED_QUEUE_SIZE,
	},

	.dccm_queue = {
		.base_addr = mmQMAN_ARC_AUX_DCCM_QUEUE_BASE_ADDR_0,
		.size = mmQMAN_ARC_AUX_DCCM_QUEUE_SIZE_0,
		.ci = mmQMAN_ARC_AUX_DCCM_QUEUE_CI_0,
		.pi = mmQMAN_ARC_AUX_DCCM_QUEUE_PI_0,
	},

	.arc_num = mmQMAN_ARC_AUX_ARC_NUM,
	.inflight_lbu_wr_cnt = mmQMAN_ARC_AUX_INFLIGHT_LBU_WR_CNT,
	.valid_entries = mmQMAN_ARC_AUX_DCCM_QUEUE_VALID_ENTRIES_0,
};
