/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "compile_target.h"

#ifdef CORAL_BFM_MODE
#include "engine_bfm.hpp"
#endif

#include "arc_queue_pvt.h"
#include "arc_queue_local.h"
#include "arc_msgs.h"
#include "utils.h"
#include "engine_arc.h"
#include "sob_common.h"
#include "debug.h"
#include "logger.h"

#ifndef CORAL_BFM_MODE
#include "arc_queue_pvt_gbls.h"
#endif

#include "eng_asic_specific_data.h"

void CORAL_CLS_PREFIX eng_queues_pre_init()
{
	u32 q, pi;

	arc_memset(&arc_queue_ctxt, 0x0, sizeof(arc_queue_ctxt));

	for (q = 0; q < MAX_DCCM_QUEUE_COUNT; q++) {
		arc_queue_ctxt[q].base = (uintptr)engine_interface_ctxt.arc_queue_buff_q[q];
		arc_queue_ctxt[q].size = sizeof(engine_interface_ctxt.arc_queue_buff_q[q]);

		arc_aux_reg_write(ARC_DCCM_OFFSET(arc_queue_ctxt[q].base),
						ARC_AUX_ADDR(sr->dccm_queue.base_addr) + q * 4);
		arc_aux_reg_write(arc_queue_ctxt[q].size,
						ARC_AUX_ADDR(sr->dccm_queue.size) + q * 4);
		pi = arc_aux_reg_read(ARC_AUX_ADDR(sr->dccm_queue.pi) + q * 4);
		arc_aux_reg_write(pi, ARC_AUX_ADDR(sr->dccm_queue.ci) + q * 4);
	}
}

void CORAL_CLS_PREFIX eng_queues_post_init()
{
}
