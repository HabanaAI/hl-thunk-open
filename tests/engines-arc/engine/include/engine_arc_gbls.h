/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef __ENGINE_ARC_GBLS_H__
#define __ENGINE_ARC_GBLS_H__

struct arc_eng_regs *sr;
struct engine_ctxt_t engine_ctxt;

#ifdef CORAL_BFM_MODE
struct eng_hbm_data_t &eng_hbm_data;
#else
struct eng_hbm_data_t eng_hbm_data __attribute__((section(".hbmdata")));
extern u32 all_done;
#endif

struct engine_config_t *eng_post_init_config;

#ifdef CORAL_BFM_MODE

std::function<void(void)> eng_blocks_pre_init[ENG_BLOCK_COUNT] = {
		std::bind(&EngineBFM::eng_ctxt_pre_init, this),
		std::bind(&EngineBFM::eng_registers_pre_init, this),
		std::bind(&EngineBFM::eng_queues_pre_init, this),
		std::bind(&EngineBFM::dma_pre_init, this)
};

std::function<void(void)> eng_blocks_post_init[ENG_BLOCK_COUNT] = {
		std::bind(&EngineBFM::eng_ctxt_post_init, this),
		std::bind(&EngineBFM::eng_registers_post_init, this),
		std::bind(&EngineBFM::eng_queues_post_init, this),
		std::bind(&EngineBFM::dma_post_init, this)
};

#else
void (*const eng_blocks_pre_init[ENG_BLOCK_COUNT]) (void) = {
		eng_ctxt_pre_init,
		eng_registers_pre_init,
		eng_queues_pre_init,
		dma_pre_init
};

void (*const eng_blocks_post_init[ENG_BLOCK_COUNT]) (void) = {
		eng_ctxt_post_init,
		eng_registers_post_init,
		eng_queues_post_init,
		dma_post_init
};
#endif


#endif /* __ENGINE_ARC_GBLS_H__ */
