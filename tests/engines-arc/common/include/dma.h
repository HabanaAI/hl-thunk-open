/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __DMA_H__
#define __DMA_H__

#include "arc_types.h"
#include <arc_reg.h>

/**
 * \file    dma.h
 * \brief   ARC DMA Controller APIs
 */

enum dma_attribute {
	DMA_ATTR_SET_DONE = 0x1,
	DMA_ATTR_SET_INTR = 0x2,
	DMA_ATTR_SET_EVENT = 0x4,
	DMA_ATTR_NP_WRITE = 0x8,
	DMA_ATTR_SRC_COH = 0x10,
	DMA_ATTR_DST_DOH = 0x20,
	DMA_ATTR_LAST = 0x3F
};

#define DMA_HANDLE_INVALID		0xFF
#define DMA_HANDLE_COMPLETED	0xFE

#define DMA_NUM_CHANNEL 4
#define DMA_TOTAL_DESC 32
#define NUM_DESC_PER_CHANNEL	(DMA_TOTAL_DESC / DMA_NUM_CHANNEL)

#define DMA_S_DONESTATD_AUX (DMA_AUX_BASE+0x020)
#define DMA_S_DONESTATD_CLR_AUX (DMA_AUX_BASE+0x040)

#define DMA_S_BASEC0_AUX (DMA_AUX_BASE+0x083)
#define DMA_S_LASTC0_AUX (DMA_AUX_BASE+0x084)

#define DMA_AUX_BASE_CH_OFFSET (0x080)
#define DMA_S_TAILC_AUX_OFFSET (0)
#define DMA_S_MIDC_AUX_OFFSET  (1)
#define DMA_S_HEADC_AUX_OFFSET (2)
#define DMA_S_BASEC_AUX_OFFSET (3)
#define DMA_S_LASTC_AUX_OFFSET (4)
#define DMA_S_PRIOC_AUX_OFFSET (5)
#define DMA_S_STATC_AUX_OFFSET (6)

#endif /* __DMA_H__ */
