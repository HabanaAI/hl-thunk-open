/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __COMMON_LOGS_H__
#define __COMMON_LOGS_H__

#include "debug.h"

#ifdef SCHED_ARC
#include "sched_logs.h"
#endif
#ifdef ENGINE_ARC
#include "eng_logs.h"
#endif

#ifdef SCHED_ARC
#define DMA_PRE_INIT_ENTRY		SCHED_DMA_PRE_INIT_ENTRY
#define DMA_PRE_INIT_EXIT		SCHED_DMA_PRE_INIT_EXIT

#define FW_UPDATE_BOOT_STATUS(status) 	arc_log_error(status)
#endif

#ifdef ENGINE_ARC
#define DMA_PRE_INIT_ENTRY		ENG_DMA_PRE_INIT_ENTRY
#define DMA_PRE_INIT_EXIT		ENG_DMA_PRE_INIT_EXIT

#define FW_UPDATE_BOOT_STATUS(status) 	arc_log_error(status)
#endif

#endif /* __REGS_H__ */
