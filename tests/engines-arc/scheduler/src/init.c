/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "compile_target.h"

#ifdef CORAL_BFM_MODE
#include "scheduler_bfm.hpp"
#else
#include <arc_reg.h>
#include "dma_fns.h"
#endif

#include "cache.h"
#include "arc_types.h"
#include "arc_sched.h"
#include "dma.h"
#include "debug.h"
#include "utils.h"
#include "common_logs.h"
#include "logger.h"

#include "sched_asic_specific_data.h"
#include "comm_asic_specific_data.h"

#define DMA_CHANNEL_CONFIG	0
void CORAL_CLS_PREFIX pre_init()
{
	u32 i;
	u32 config_addr, config_size, handle;
	u32 *dst;

	LOG_TRACE(get_module_name(), "Pre-Init Started");
	for (i = 0; i < SCHED_BLOCK_COUNT; i++) {
		LOG_TRACE(get_module_name(), "initialising block {}", i);
		sched_blocks_pre_init[i]();
		LOG_TRACE(get_module_name(), "block {} initialised", i);
	}

	LOG_TRACE(get_module_name(), "Pre-Init blocks initialised");
	/*
	 * Wait until all the transactions are completed on LBU
	 * then update the status
	 */
	while (arc_aux_reg_read(ARC_AUX_ADDR(sr->inflight_lbu_wr_cnt))) {
		FW_WHILE(true);
	}
	FW_UPDATE_BOOT_STATUS(SCHED_PRE_INIT_COMPLETED);

	config_size = arc_aux_reg_read(ARC_AUX_ADDR(cr->sched_fw_config_size));
	config_addr = arc_aux_reg_read(ARC_AUX_ADDR(cr->sched_fw_config_addr));

	/*
	 * Note: Blob size is fixed and it should be equal to the size of the
	 * struct. But the mismatch can happen if scal and firmware are built
	 * using two different specs header
	 */
	LOG_TRACE(get_module_name(), "Initiate DMA expected size = {} actual size = {}",
		sizeof(struct scheduler_config_t), config_size);
	arc_assert(sizeof(struct scheduler_config_t) == config_size);

	dst = sched_hbm_data.init_config_buffer;
	handle = dma_start(DMA_CHANNEL_CONFIG, config_addr, ARC_HBM_ADDR(dst), config_size);
	dma_wait_for_completion(handle);

	LOG_TRACE(get_module_name(), "DMA Completed");

#ifndef CORAL_BFM_MODE
	/*
	 * Invalidate any cache accesses to the config buffer region.
	 * Set flush = 0, to discard any local changes in this region
	 */
	_dc_invalidate_block(sched_hbm_data.init_config_buffer, config_size, 0);
#endif

	sched_post_init_config = (struct scheduler_config_t *)sched_hbm_data.init_config_buffer;
	if (sched_post_init_config->common_cfg.version != ARC_FW_INIT_CONFIG_VER) {
		LOG_ERR(get_module_name(), "Version check failed");
		arc_assert(false);
		FW_UPDATE_BOOT_STATUS(SCHED_POST_INIT_SCHEMA_MISMATCH);
		FW_HALT();
	}

	/* starting here we can use arc_printf */
	arc_printf("scheduler: Version check passed\n");

}


void CORAL_CLS_PREFIX post_init()
{
	u32 i, sob_lbu_addr, sob_lbu_value;
	volatile u32 *scal_status =
		(volatile u32 *)&sched_interface_ctxt.sched_regs.common_regs.canary;

	arc_printf("Post Init Started\n");

	arc_printf("Post Init SCAL init completed\n");

	for (i = 0; i < SCHED_BLOCK_COUNT; i++) {
		sched_blocks_post_init[i]();
	}

	arc_printf("Post Init completed\n");
	/*
	 * Before updating the status, make sure all the transactions
	 * are actually completed.
	 */
	while (arc_aux_reg_read(ARC_AUX_ADDR(sr->inflight_lbu_wr_cnt))){FW_WHILE(true);};
	FW_UPDATE_BOOT_STATUS(SCHED_POST_INIT_COMPLETED);

	sob_lbu_addr = arc_aux_reg_read(ARC_AUX_ADDR(cr->sched_sob_lbu_addr));
	sob_lbu_value = arc_aux_reg_read(ARC_AUX_ADDR(cr->sched_sob_lbu_value));
	soc_reg_write(sob_lbu_value, sob_lbu_addr);

	/*
	 * Wait until host software updates the SCAL status
	 */
	while (*scal_status != SCAL_INIT_COMPLETED) {
#ifdef CORAL_BFM_MODE
		FW_WHILE(*scal_status == SCAL_INIT_COMPLETED);
		if (!yield(true))
			return;
#endif
	}
}
