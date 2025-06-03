/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef __ARC_QUEUE_LOCAL_FNS_H__
#define __ARC_QUEUE_LOCAL_FNS_H__

u32 arc_queue_grab_data(void *_dst, void *_src, u32 len, u32 pi, u32 ci, u32 qlen);
u32 arc_queue_data_length(u32 pi, u32 ci, u32 qlen);
u32 arc_queue_move_ci(u32 factor, u32 ci, u32 qlen);
void arc_queue_local_push(u32 q_id, u32 data);
u32 arc_queue_local_valid_entries(u32 q_id);
u32 arc_queue_local_pi(u32 q_id);
u32 arc_queue_local_ci(u32 q_id);
void arc_queue_local_update_ci(u32 q_id, u32 ci);

#endif
