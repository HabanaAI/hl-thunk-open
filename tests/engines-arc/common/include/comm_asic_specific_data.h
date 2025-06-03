/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2021 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#ifndef __COMM_ASIC_SPECIFIC_DATA__
#define __COMM_ASIC_SPECIFIC_DATA__

#include <stdint.h>

struct arc_comm_regs {
	uint32_t dccm_base_addr;
	uint32_t valid_entries_addr;
	uint32_t push_reg;
	uint32_t ci_addr;
	uint32_t pi_addr;

	uint32_t sched_sob_lbu_addr;
	uint32_t sched_sob_lbu_value;
	uint32_t sched_fw_config_addr;
	uint32_t sched_fw_config_size;
	uint32_t eng_sob_lbu_addr;
	uint32_t eng_sob_lbu_value;
	uint32_t eng_fw_config_addr;
	uint32_t eng_fw_config_size;

	uint32_t last_sched_id;
	uint32_t max_arc_cpu_id;
};

extern struct arc_comm_regs gaudi2_comm_regs;
extern struct arc_comm_regs gaudi3_comm_regs;

/* Point to the specific registers set */
extern struct arc_comm_regs *cr;

#endif /*__COMM_ASIC_SPECIFIC_DATA__*/
