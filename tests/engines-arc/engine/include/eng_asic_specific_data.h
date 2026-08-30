/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2021 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#ifndef __ENG_ASIC_SPECIFIC_DATA__
#define __ENG_ASIC_SPECIFIC_DATA__

#include <stdint.h>

struct arc_eng_regs {
	struct {
		uint32_t lbu_arc_cq_ptr_lo;
		uint32_t lbu_arc_cq_ptr_hi;
		uint32_t lbu_arc_cq_tsize;
		uint32_t lbu_arc_cq_ctl;
	} arc_cq;

	struct {
		uint32_t arc_num;
		uint32_t arc_cq_shadow_ci;
		uint32_t ififo_shadow_ci;
		uint32_t arc_cq_cfg0;
		uint32_t ififo_ci;
		uint32_t cp_ext_switch;
		uint32_t cq_cfg0;
	} mme_qm;

	struct {
		uint32_t base_addr;
		uint32_t size;
		uint32_t ci;
		uint32_t pi;
	} dccm_queue;

	/* Misc */
	uint32_t inflight_lbu_wr_cnt;
};

extern struct arc_eng_regs gaudi2_eng_regs;
extern struct arc_eng_regs gaudi3_eng_regs;

/* Point to the specific registers set */
extern struct arc_eng_regs *sr;

#endif /*__SCHED_ASIC_SPECIFIC_DATA__*/