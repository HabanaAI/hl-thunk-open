/*
 * Copyright (C) 2022 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __DMA_FNS_H__
#define __DMA_FNS_H__
#include "utils.h"

#include <dma.h>
#include "compile_target.h"

void dma_pre_init();
void dma_post_init();

u32 is_dma_completed(u8 handle);
u8 dma_start(u8 channel, u32 src, u32 dst, u32 len);
u8 dma_start_dccm_to_hbm(u8 channel, u32 src, u32 dst, u32 len);
void dma_wait_for_completion(u8 handle);
u8 dma_check_completion(u8 channel, u8 *handle);
void dma_wait_for_idle();

FW_STATIC inline u32 dma_get_completion_bitmap()
{
	return arc_reg_read(DMA_S_DONESTATD_AUX);
}

FW_STATIC inline void dma_clear_completion_bitmap(u32 handle_bitmap)
{
	arc_reg_write(handle_bitmap, DMA_S_DONESTATD_CLR_AUX);
}



#endif  /* __DMA_FNS_H__ */
