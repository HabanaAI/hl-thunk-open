/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __CACHE_H__
#define __CACHE_H__

#include "arc_types.h"
#ifndef CORAL_BFM_MODE
#include <arc_reg.h>
#endif

int _dc_invalidate_block(void *addr, unsigned size, int flush_dirty);

#endif /* __CACHE_H__ */
