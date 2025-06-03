/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2021 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#include "gaudi3/asic_reg/gaudi3_regs.h"
#include "gaudi3/asic_reg/gaudi3_blocks.h"
#include "gaudi3/gaudi3_arc_common_packets.h"
#include "gaudi3/gaudi3_arc_host_packets.h"

#include "comm_asic_specific_data.h"

struct arc_comm_regs gaudi3_comm_regs = {
	.dccm_base_addr = mmQMAN_ARC_AUX_DCCM_QUEUE_BASE_ADDR_0,
	.valid_entries_addr = mmQMAN_ARC_AUX_DCCM_QUEUE_VALID_ENTRIES_0,
	.push_reg = mmQMAN_ARC_AUX_DCCM_QUEUE_PUSH_REG_0,
	.ci_addr = mmQMAN_ARC_AUX_DCCM_QUEUE_CI_0,
	.pi_addr = mmQMAN_ARC_AUX_DCCM_QUEUE_PI_0,
	.sched_sob_lbu_addr = SCHED_SOB_LBU_ADDR,
	.sched_sob_lbu_value = SCHED_SOB_LBU_VALUE,
	.sched_fw_config_addr = SCHED_FW_CONFIG_ADDR,
	.sched_fw_config_size = SCHED_FW_CONFIG_SIZE,
	.eng_sob_lbu_addr = ENG_SOB_LBU_ADDR,
	.eng_sob_lbu_value = ENG_SOB_LBU_VALUE,
	.eng_fw_config_addr = ENG_FW_CONFIG_ADDR,
	.eng_fw_config_size = ENG_FW_CONFIG_SIZE,

	.last_sched_id = CPU_ID_SCHED_ARC15,
	.max_arc_cpu_id = NUM_ACTIVE_ARCS - 1,
};
