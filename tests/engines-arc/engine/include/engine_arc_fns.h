/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef __ENGINE_ARC_FNS_H__
#define __ENGINE_ARC_FNS_H__

int engine_main_init();
void pre_init();
void post_init();

void eng_ctxt_pre_init();
void eng_ctxt_post_init();

void copy_command_from_queue(u32 local_q_id,
			     u32 *cmd_buffer, u8 cmd_size);
void copy_command_to_queue(u32 local_q_id,
			     u32 *cmd_buffer, u8 cmd_size);

void process_dispatch_static_ecb(u32 local_q_id);
void process_update_recipe_base(u32 local_q_id);
void process_so_set_alloc(u32 local_q_id);

void compute_process_sched_queue(u32 local_q_id);
void compute_process_sched_queues();

u32 arc_cq_fetcher_check_fifo_level(u32 blocking);
void arc_cq_fetcher_push_dynamic_desc(u32 addr_lo, u32 addr_hi, u32 size);

u32 get_qm_base();

#endif
