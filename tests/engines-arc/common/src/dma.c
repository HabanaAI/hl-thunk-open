/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "compile_target.h"

#ifdef CORAL_BFM_MODE
#ifdef SCHED_ARC
#include "scheduler_bfm.hpp"
#endif
#ifdef ENGINE_ARC
#include "engine_bfm.hpp"
#endif
#endif

#include <arc_reg.h>

#include "dma.h"
#include "utils.h"

#include "common_logs.h"

u32 dma_submitted;

void CORAL_CLS_PREFIX dma_pre_init()
{
	u32 aux_base, channel;

	FW_UPDATE_BOOT_STATUS(DMA_PRE_INIT_ENTRY);

	dma_submitted = 0;
	arc_reg_write((0 << 2) | (4 << 8), DMA_S_CTRL_AUX); // D = 1, MLEN = 4

	for (channel = 0; channel < DMA_NUM_CHANNEL; channel++) {

		aux_base = DMA_AUX_BASE + DMA_AUX_BASE_CH_OFFSET + 8 * channel;

		/* Set DMA channel priority */
		arc_reg_write(0, aux_base + DMA_S_PRIOC_AUX_OFFSET);

		/* Setup DMA descriptor queue */
		arc_reg_write((NUM_DESC_PER_CHANNEL * channel),
			aux_base + DMA_S_BASEC_AUX_OFFSET);

		arc_reg_write((NUM_DESC_PER_CHANNEL * channel + (NUM_DESC_PER_CHANNEL - 1)),
			aux_base + DMA_S_LASTC_AUX_OFFSET);

		/* Enable DMA channel */
		arc_reg_write(1, aux_base + DMA_S_STATC_AUX_OFFSET);

	}

	arc_reg_write(DMA_ATTR_SET_DONE, DMA_C_ATTR_AUX);

	FW_UPDATE_BOOT_STATUS(DMA_PRE_INIT_EXIT);
}

void CORAL_CLS_PREFIX dma_post_init()
{

}

u8 CORAL_CLS_PREFIX dma_check_completion(u8 channel, u8 *handle)
{
	u32 aux_base, done_status;
	u32 next_handle;

	aux_base = DMA_AUX_BASE + DMA_AUX_BASE_CH_OFFSET + 8 * channel;
	next_handle = arc_reg_read(aux_base + DMA_S_TAILC_AUX_OFFSET);
	*handle = next_handle;

	/*
	 * if the previous transfer is not cleared then clear it
	 * now.
	 */
	next_handle = 1 << next_handle;
	if (next_handle & dma_submitted) {

		do {
			done_status = arc_reg_read(DMA_S_DONESTATD_AUX);
		} while (!(done_status & next_handle));

		arc_reg_write(next_handle, DMA_S_DONESTATD_CLR_AUX);
		dma_submitted &= ~(next_handle);
		return 1;
	}
	return 0;
}

#define DMA_ADDR(x)	((x) - 0x80000000 + 0xA2000000)

u8 CORAL_CLS_PREFIX dma_start(u8 channel, u32 src, u32 dst, u32 len)
{
	u8 handle;

	/*
	 * Write will block iff busy i.e. DMA_C_STATUS_AUX.B bit is set
	 * This happens only when the descriptor is getting pushed into
	 * FIFO
	 */

	arc_reg_write(channel, DMA_C_CHAN_AUX);
	arc_reg_write(src, DMA_C_SRC_AUX);

	arc_reg_write(dst, DMA_C_DST_AUX);

	/*
 	 * the LENGTH register triggers the actual dma_push message so this
	 * should be the last register to be programmed
	 */
	arc_reg_write(len, DMA_C_LEN_AUX);

	/* return DMA handle */
	handle = arc_reg_read(DMA_C_HANDLE_AUX);
	dma_submitted |= (1 << handle);

	return handle;
}

void CORAL_CLS_PREFIX dma_wait_for_completion(u8 handle)
{
	u32 ch = 1 << handle;
	u32 st;

	do {
		st = arc_reg_read(DMA_S_DONESTATD_AUX);
	} while(!(st & ch));

	arc_reg_write(ch, DMA_S_DONESTATD_CLR_AUX);
	dma_submitted &= ~(ch);
}

u32 CORAL_CLS_PREFIX is_dma_completed(u8 handle)
{
	u32 ch = 1 << handle;
	u32 st;

	st = arc_reg_read(DMA_S_DONESTATD_AUX);
	if (st & ch) {
		arc_reg_write(ch, DMA_S_DONESTATD_CLR_AUX);
		dma_submitted &= ~(ch);
		return 1;
	}
	return 0;
}

void CORAL_CLS_PREFIX dma_wait_for_idle()
{
	u32 i, aux_base, status;

	for (i = 0; i < DMA_NUM_CHANNEL; i++) {
		aux_base = DMA_AUX_BASE + DMA_AUX_BASE_CH_OFFSET + 8 * i;
		do {
			status = arc_reg_read(aux_base + DMA_S_STATC_AUX_OFFSET) & (0x600);
		} while (status);
	}
}
