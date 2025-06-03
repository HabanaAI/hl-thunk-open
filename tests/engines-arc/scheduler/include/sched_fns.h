/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef __SCHED_FNS_H__
#define __SCHED_FNS_H__

void pre_init();
void post_init();
int scheduler_main_init();
void sched_ctxt_pre_init();
void sched_ctxt_post_init();
void schedule();
u32 compute_process_host_queue(u32 qid, u32 pi, u32 ci);
void send_data_to_queue(void *_buffer, u32 len, u32 cpu_id, u32 qid);
u32 sched_cmd_process_dispatch_static_ecb(u32 qid, u32 pi, u32 ci);
u32 sched_cmd_process_nop(u32 qid, u32 pi, u32 ci);
void sched_queues_pre_init();
void sched_queues_post_init();

#endif
