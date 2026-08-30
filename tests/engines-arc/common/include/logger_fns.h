/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __LOGGER_FNS_H__
#define __LOGGER_FNS_H__

#include "arc_types.h"

/*
 * in Coral mode, the arc_printf function is a class function so the first
 * argument is a pointer to the class object. Therefore it has different
 * indexes for the 'format' attribute.
 */
#ifdef CORAL_BFM_MODE
void arc_printf(const char *format, ...) __attribute__ ((format (printf, 2, 3)));
#else
void arc_printf(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
#endif

u32 send_string(u32 free_mem, u32 log_arc_va, u32 log_mem_size, u32 str_sz, u32 pi);

#endif // __LOGGER_FNS_H__