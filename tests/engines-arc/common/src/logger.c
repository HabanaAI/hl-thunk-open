// SPDX-License-Identifier: MIT
/*
 *
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 */

#include "logger.h"
#include "dma.h"
#include "utils.h"
#include "arc_types.h"

#ifdef SCHED_ARC
#include "arc_sched.h"
#else
#include "engine_arc.h"
#endif

#ifdef CORAL_BFM_MODE

#ifdef SCHED_ARC
#include "scheduler_bfm.hpp"
#endif
#ifdef ENGINE_ARC
#include "engine_bfm.hpp"
#endif

#else /* CORAL_BFM_MODE */

#include <arc_reg.h>
#include "dma_fns.h"
#include "cache.h"

#endif /* CORAL_BFM_MODE */

#include "printf.h"

#define DMA_CHANNEL_CONFIG 0
u32 CORAL_CLS_PREFIX send_string(u32 src, u32 log_arc_va, u32 log_mem_size,
					u32 str_sz, u32 pi)
{
	u32 handle;

	if (str_sz == 0)
		return pi;
	if (pi + str_sz > log_mem_size) {
		handle = dma_start(DMA_CHANNEL_CONFIG, src,
			log_arc_va + pi, log_mem_size - pi);
		dma_wait_for_completion(handle);
		str_sz = str_sz - (log_mem_size - pi);
		src += (log_mem_size - pi);
		pi = 0;
	}

	handle = dma_start(DMA_CHANNEL_CONFIG, src, log_arc_va + pi, str_sz);
	dma_wait_for_completion(handle);
	return (pi + str_sz) & ~(log_mem_size);
}

void CORAL_CLS_PREFIX arc_printf(const char *format, ...)
{
	u32 *pi;
	static const char overflow_warn_str[] = "ARC LOG BUFFER OVERFLOW - logs might dropped\n";
	u32 ci, log_arc_va, str_sz, log_mem_size, free_mem, warn_str_size, src;
	char *log_str;
	va_list args;

	warn_str_size = sizeof(overflow_warn_str) - 1;

#ifdef SCHED_ARC
	if (!sched_post_init_config || !sched_post_init_config->common_cfg.log_enabled)
		return;
	log_arc_va = sched_post_init_config->common_cfg.log_arc_va;
	log_mem_size = sched_post_init_config->common_cfg.log_size;
	ci = sched_interface_ctxt.sched_regs.common_regs.log_buf_ci;
	log_str = sched_hbm_data.log_str;
	pi = &fw_ctxt->log_pi;
#else
	if (!eng_post_init_config || !eng_post_init_config->common_cfg.log_enabled)
		return;
	log_arc_va = eng_post_init_config->common_cfg.log_arc_va;
	log_mem_size = eng_post_init_config->common_cfg.log_size;
	ci = engine_interface_ctxt.regs.common_regs.log_buf_ci;
	log_str = eng_hbm_data.log_str;
	/* unaligned addresses are a bietch */
	pi = (u32 *)(((uintptr_t)&engine_ctxt) + offsetof(struct engine_ctxt_t, log_pi));
#endif
	va_start(args, format);
	str_sz = vsnprintf_(log_str, ARC_LOG_STR_BUF_SIZE, format, args);
	va_end(args);

	/* string truncated */
	str_sz = MIN(str_sz, ARC_LOG_STR_BUF_SIZE);
	free_mem = ci > *pi ? ci - *pi - 1 : log_mem_size - (*pi - ci) - 1;

	if (str_sz + warn_str_size > free_mem) {
		src = ARC_DCCM_ADDR(overflow_warn_str);
		*pi = send_string(src, log_arc_va, log_mem_size, MIN(warn_str_size, free_mem), *pi);
		free_mem = ci > *pi ? ci - *pi - 1 : log_mem_size - (*pi - ci) - 1;
	}

	str_sz = MIN(str_sz, free_mem);
	src = ARC_HBM_ADDR(log_str);
#ifndef CORAL_BFM_MODE
	/* flush into the hbm what we wrote to it */
	_dc_invalidate_block(log_str, ARC_LOG_STR_BUF_SIZE, 1);
#endif
	*pi = send_string(src, log_arc_va, log_mem_size, str_sz, *pi);
}
