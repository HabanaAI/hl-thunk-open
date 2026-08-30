/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ARC_QUEUE_LOCAL_H_
#define _ARC_QUEUE_LOCAL_H_

#include "arc_types.h"
#include "utils.h"

#define ENGINE_ARC_QUEUE_SCHED_QID0	0
#define ENGINE_ARC_QUEUE_SCHED_QID1	1
#define ENGINE_ARC_QUEUE_SCHED_QID2	2
#define ENGINE_ARC_QUEUE_SCHED_QID3	3
#define ENGINE_ARC_QUEUE_SCHED_QID4	4
#define ENGINE_ARC_QUEUE_UNUSED_QID0	5
#define ENGINE_ARC_QUEUE_UNUSED_QID1	6
#define ENGINE_ARC_QUEUE_UNUSED_QID2	7

#ifdef ENGINE_ARC
struct arc_queue_ctxt_t {
	uintptr base;
	u32 size;
	u32 pi;
	u32 ci;
};
#endif

#define SCHED_ARC_QUEUE_MONITOR_RESPONSE_QID	0
#define SCHED_ARC_QUEUE_UNUSED_QID1		1
#define SCHED_ARC_QUEUE_UNUSED_QID2		2
#define SCHED_ARC_QUEUE_UNUSED_QID3		3
#define SCHED_ARC_QUEUE_UNUSED_QID4		4
#define SCHED_ARC_QUEUE_UNUSED_QID5		5
#define SCHED_ARC_QUEUE_UNUSED_QID6		6
#define SCHED_ARC_QUEUE_UNUSED_QID7		7

void arc_queue_local_push(u32 q_id, u32 data);

void arc_queue_local_update_ci(u32 q_id, u32 ci);

#ifndef CORAL_BFM_MODE
#include "arc_queue_local_fns.h"
#endif

#endif /* _ARC_QUEUE_LOCAL_H_ */
