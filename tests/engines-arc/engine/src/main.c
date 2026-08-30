/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "compile_target.h"

#ifdef CORAL_BFM_MODE
#include "engine_bfm.hpp"
#else
#include <arc_reg.h>
#endif

#include "arc_types.h"
#include "engine_arc.h"
#include "arc_queue_pvt.h"
#include "qman_if.h"
#include "dma.h"
#include "utils.h"
#include "common_logs.h"

#include "main_gbls.h"
#include "logger.h"

#ifdef CORAL_BFM_MODE
int CORAL_CLS_PREFIX engine_main_init()
#else
int main()
#endif
{
	FW_UPDATE_BOOT_STATUS(ENG_MAIN_ENTRY);

	pre_init();

	post_init();


	arc_printf("Starting Execution..");

	compute_process_sched_queues();

	return 0;
}
