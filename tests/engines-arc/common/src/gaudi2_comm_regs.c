/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2021 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#include "comm_asic_specific_data.h"

#include "gaudi2/asic_reg/gaudi2_regs.h"

#include "gaudi2/asic_reg/gaudi2_blocks.h"

#include "gaudi2/gaudi2_arc_common_packets.h"


struct arc_comm_regs gaudi2_comm_regs = {
#ifdef ENGINE_ARC
	.dccm_base_addr = mmDCORE0_MME_QM_ARC_AUX_DCCM_QUEUE_BASE_ADDR_0,
	.valid_entries_addr = mmDCORE0_MME_QM_ARC_AUX_DCCM_QUEUE_VALID_ENTRIES_0,
	.push_reg = mmDCORE0_MME_QM_ARC_AUX_DCCM_QUEUE_PUSH_REG_0,
	.ci_addr = mmDCORE0_MME_QM_ARC_AUX_DCCM_QUEUE_CI_0,
	.pi_addr = mmDCORE0_MME_QM_ARC_AUX_DCCM_QUEUE_PI_0,
#endif
#ifdef SCHED_ARC
	.dccm_base_addr = mmARC_FARM_ARC0_AUX_DCCM_QUEUE_BASE_ADDR_0,
	.valid_entries_addr = mmARC_FARM_ARC0_AUX_DCCM_QUEUE_VALID_ENTRIES_0,
	.push_reg = mmARC_FARM_ARC0_AUX_DCCM_QUEUE_PUSH_REG_0,
	.ci_addr = mmARC_FARM_ARC0_AUX_DCCM_QUEUE_CI_0,
	.pi_addr = mmARC_FARM_ARC0_AUX_DCCM_QUEUE_PI_0,
#endif
	.sched_sob_lbu_addr = mmARC_FARM_ARC0_AUX_SCRATCHPAD_0,
	.sched_sob_lbu_value = mmARC_FARM_ARC0_AUX_SCRATCHPAD_3,
	.sched_fw_config_addr = mmARC_FARM_ARC0_AUX_SCRATCHPAD_1,
	.sched_fw_config_size = mmARC_FARM_ARC0_AUX_SCRATCHPAD_2,
	.eng_sob_lbu_addr = mmDCORE0_MME_QM_ARC_AUX_SCRATCHPAD_0,
	.eng_sob_lbu_value = mmDCORE0_MME_QM_ARC_AUX_SCRATCHPAD_3,
	.eng_fw_config_addr = mmDCORE0_MME_QM_ARC_AUX_SCRATCHPAD_1,
	.eng_fw_config_size = mmDCORE0_MME_QM_ARC_AUX_SCRATCHPAD_2,

	.last_sched_id = CPU_ID_SCHED_ARC5,
	.max_arc_cpu_id = CPU_ID_MAX,
};
