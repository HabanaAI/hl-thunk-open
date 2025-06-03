/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "compile_target.h"

#ifdef CORAL_BFM_MODE
#include "engine_bfm.hpp"
#endif

#include "arc_types.h"
#include "engine_arc.h"
#include "debug.h"
#include "utils.h"

#ifndef CORAL_BFM_MODE
#include "qman_if_gbls.h"
#endif

void CORAL_CLS_PREFIX qman_interface_init()
{
}
