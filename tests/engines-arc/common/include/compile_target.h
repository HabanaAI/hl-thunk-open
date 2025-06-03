/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef __COMPILE_TARGET_H__
#define __COMPILE_TARGET_H__

#ifdef CORAL_BFM_MODE
    #define FW_STATIC
    #define PTR_TO_INT(x) (x)
    #ifdef ENGINE_ARC
        #define  CORAL_CLS_PREFIX EngineBFM::
    #else
        #define CORAL_CLS_PREFIX SchedulerBFM::
        #define CORAL_CLS_MTH_PTR_PREFIX &SchedulerBFM::
    #endif
    #define FW_WHILE(expr) while_yield([&]() {return expr;}); //suspends as long as cond is true
#else
    #define FW_STATIC static
    #define PTR_TO_INT(x) ((u32) x)
    #define CORAL_CLS_PREFIX
    #define FW_WHILE(expr) {}
#endif

#endif
