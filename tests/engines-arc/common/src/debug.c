/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#include "compile_target.h"

#include "arc_types.h"

#ifdef SCHED_ARC
#include "arc_sched.h"

#ifdef CORAL_BFM_MODE
#include "scheduler_bfm.hpp"
#endif

#endif

#ifdef ENGINE_ARC
#include "engine_arc.h"
#ifdef CORAL_BFM_MODE
#include "engine_bfm.hpp"
#endif

#endif

#ifdef SCHED_ARC
void CORAL_CLS_PREFIX arc_log_error(u32 value)
{
	uint32_t idx = sched_interface_ctxt.sched_regs.common_regs.checkpoint_index;

	sched_interface_ctxt.sched_regs.checkpoint[idx] = value;
	idx = (idx + 1) % SCHED_MAX_CHECKPOINT_COUNT;
	sched_interface_ctxt.sched_regs.common_regs.checkpoint_index = idx;
}
#endif

#ifdef ENGINE_ARC
void CORAL_CLS_PREFIX arc_log_error(u32 value)
{
	uint32_t idx = engine_interface_ctxt.regs.common_regs.checkpoint_index;

	engine_interface_ctxt.regs.checkpoint[idx] = value;
	idx = (idx + 1) % ENG_MAX_CHECKPOINT_COUNT;
	engine_interface_ctxt.regs.common_regs.checkpoint_index = idx;
}
#endif
