/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ARC_QUEUE_PVT_H_
#define _ARC_QUEUE_PVT_H_

#include "arc_types.h"

#define MAX_ENGINE_QUEUE_PRIORITY	0
#define MIN_ENGINE_QUEUE_PRIORITY	3

#ifndef CORAL_BFM_MODE
#include "arc_queue_pvt_fns.h"
#endif

#endif /* _ARC_QUEUE_PVT_H_ */
