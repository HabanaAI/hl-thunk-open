/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifdef CORAL_BFM_MODE
#include "scheduler_bfm.hpp"
#else
#include <arc_reg.h>
#endif

#include "arc_types.h"
#include "arc_sched.h"
#include "dma.h"
#include "arc_queues.h"
#include "debug.h"
#include "utils.h"
#include "common_logs.h"
#include "logger.h"

#ifndef CORAL_BFM_MODE
void _init_jli()
{
	arc_reg_write(0x40000058, JLI_BASE);
}
#endif

#ifdef CORAL_BFM_MODE
int CORAL_CLS_PREFIX scheduler_main_init()
#else
int main()
#endif
{
	FW_UPDATE_BOOT_STATUS(SCHED_MAIN_ENTRY);

	pre_init();

	post_init();

	arc_printf("Starting Execution..\n");

	schedule();

#ifndef CORAL_BFM_CYCLIC_MODE
	FW_UPDATE_BOOT_STATUS(0xE0D);
#endif

	return 0;
}
