/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2021 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#ifndef __SCHED_ASIC_SPECIFIC_DATA__
#define __SCHED_ASIC_SPECIFIC_DATA__

#include <stdint.h>

struct arc_sched_regs {
	struct {
		uint32_t dccm_qs_in_use;
		uint32_t dccm_q_act_size;
	} defs;

	struct {
		uint32_t base_addr;
		uint32_t size;
		uint32_t ci;
		uint32_t pi;
	} dccm_queue;

	/* misc */
	uint32_t arc_num;
	uint32_t inflight_lbu_wr_cnt;
	uint32_t valid_entries;
};

extern struct arc_sched_regs gaudi2_sched_regs;
extern struct arc_sched_regs gaudi3_sched_regs;

/* Point to the actual arc_sched_regs structure */
extern struct arc_sched_regs *sr;

#endif /*__SCHED_ASIC_SPECIFIC_DATA__*/