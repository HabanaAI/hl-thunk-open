/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "compile_target.h"

#ifdef CORAL_BFM_MODE
	#ifdef ENGINE_ARC
		#include "engine_bfm.hpp"
	#else
		#include "scheduler_bfm.hpp"
	#endif
#endif

#include "arc_queue_local.h"
#include "utils.h"
#include "debug_fns.h"

#include "comm_asic_specific_data.h"

u32 CORAL_CLS_PREFIX arc_queue_grab_data(void *_dst, void *_src, u32 len,
					 u32 pi, u32 ci, u32 qlen)
{
	uint8_t *src = (uint8_t *)_src, *dst = (uint8_t *)_dst;
	u32 i;

	arc_assert(arc_queue_data_length(pi, ci, qlen) >= len);
	for (i = 0; i < len; ++i, ci = arc_queue_move_ci(1, ci, qlen))
		dst[i] = src[ci];

	return ci;
}

u32 CORAL_CLS_PREFIX arc_queue_data_length(u32 pi, u32 ci, u32 qlen)
{
	if (pi > ci)
		return pi - ci;
	else
		return pi + qlen - ci;
}

u32 CORAL_CLS_PREFIX arc_queue_move_ci(u32 factor, u32 ci, u32 qlen)
{
	ci += factor;
	ci %= qlen;
	return ci;
}

void CORAL_CLS_PREFIX arc_queue_local_push(u32 q_id, u32 data)
{
	u32 base_addr;

	base_addr = ARC_AUX_ADDR(cr->dccm_base_addr) + q_id * 4;
	arc_aux_reg_write(data, base_addr);
}

u32 CORAL_CLS_PREFIX arc_queue_local_valid_entries(u32 q_id)
{
	u32 valid_entries_addr;
	u32 valid_entries;

	valid_entries_addr = ARC_AUX_ADDR(cr->valid_entries_addr) + q_id * 4;

	valid_entries = _lr(valid_entries_addr);

	return valid_entries;
}

u32 CORAL_CLS_PREFIX arc_queue_local_ci(u32 q_id)
{
	u32 ci_addr;
	u32 ci;

	ci_addr = ARC_AUX_ADDR(cr->ci_addr) + q_id * 4;

	ci = _lr(ci_addr);

	return ci;
}

u32 CORAL_CLS_PREFIX arc_queue_local_pi(u32 q_id)
{
	u32 pi_addr;
	u32 pi;

	pi_addr = ARC_AUX_ADDR(cr->pi_addr) + q_id * 4;

	pi = _lr(pi_addr);

	return pi;
}

void CORAL_CLS_PREFIX arc_queue_local_update_ci(u32 q_id, u32 ci)
{
	u32 ci_addr;

	ci_addr = ARC_AUX_ADDR(cr->ci_addr) + q_id * 4;

	arc_aux_reg_write(ci, ci_addr);
}
