/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "compile_target.h"

#include "arc_types.h"
#include "arc_msgs.h"
#include "utils.h"

#include "common_logs.h"
#include "engine_arc.h"

#ifdef CORAL_BFM_MODE
#include "engine_bfm.hpp"
#else
#include "eng_regs_gbls.h"
#endif


void CORAL_CLS_PREFIX eng_registers_pre_init()
{
	FW_UPDATE_BOOT_STATUS(ENG_REGS_PRE_INIT_ENTRY);

	FW_UPDATE_BOOT_STATUS(ENG_REGS_PRE_INIT_EXIT);
}

void CORAL_CLS_PREFIX eng_registers_post_init()
{

}
