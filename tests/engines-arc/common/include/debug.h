/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __ARC_DEBUG_H__
#define __ARC_DEBUG_H__

#include "arc_types.h"

/**
 * \file    debug.h
 * \brief   Various debug related functions
 */

#define FW_HALT()		while(1)

#ifndef CORAL_BFM_MODE
#include "debug_fns.h"
#endif

#endif /* __ARC_DEBUG_H__ */
