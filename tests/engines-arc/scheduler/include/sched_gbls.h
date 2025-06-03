/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef __SCHED_GBLS_H__
#define __SCHED_GBLS_H__

struct arc_sched_regs *sr;

#ifdef CORAL_BFM_MODE
struct sched_hbm_data_t &sched_hbm_data;
#else
struct sched_hbm_data_t sched_hbm_data __attribute__((section(".hbmdata")));
#endif

struct scheduler_config_t *sched_post_init_config;

struct firmware_ctxt_t firmware_ctxt;

struct firmware_ctxt_t *fw_ctxt;

#ifdef CORAL_BFM_MODE
std::function<u32(u32,u32,u32)> qman_cmds_api[SCHED_ARC_CMD_COUNT] = {
		std::bind(&SchedulerBFM::sched_cmd_process_dispatch_static_ecb, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
		std::bind(&SchedulerBFM::sched_cmd_process_nop, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3)
};
#else
u32 (*const qman_cmds_api[SCHED_ARC_CMD_COUNT]) (u32,u32,u32) = {
		sched_cmd_process_dispatch_static_ecb,
		sched_cmd_process_nop
};
#endif /* CORAL_BFM_MODE */

#ifdef CORAL_BFM_MODE
std::function<void(void)> sched_blocks_pre_init[SCHED_BLOCK_COUNT] = {
	std::bind(&SchedulerBFM::sched_ctxt_pre_init, this),
	std::bind(&SchedulerBFM::sched_queues_pre_init, this),
	std::bind(&SchedulerBFM::dma_pre_init, this),
};

std::function<void(void)> sched_blocks_post_init[SCHED_BLOCK_COUNT] = {
	std::bind(&SchedulerBFM::sched_ctxt_post_init, this),
	std::bind(&SchedulerBFM::sched_queues_post_init, this),
	std::bind(&SchedulerBFM::dma_post_init, this),
};
#else
void (*const sched_blocks_pre_init[SCHED_BLOCK_COUNT]) (void) = {
	sched_ctxt_pre_init,
	sched_queues_pre_init,
	dma_pre_init
};

void (*const sched_blocks_post_init[SCHED_BLOCK_COUNT]) (void) = {
	sched_ctxt_post_init,
	sched_queues_post_init,
	dma_post_init
};
#endif

#endif /* __SCHED_GBLS_H__ */
