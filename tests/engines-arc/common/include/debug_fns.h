/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __ARC_DEBUG_FNS_H__
#define __ARC_DEBUG_FNS_H__

#include "arc_types.h"

#ifdef CORAL_BFM_MODE
#include <assert.h>
#include <stdio.h>
#endif

/**
 * \file    debug.h
 * \brief   Various debug related functions
 */

#ifdef ARC_DEBUG
#ifdef CORAL_BFM_MODE
#define arc_assert(flag)  assert(flag)
#define arc_assert_msg(expr, fmt, ...)                                                             \
	({                                                                                         \
		int ____flag____ = (expr);                                                         \
		if (!____flag____) {                                                               \
			fprintf(stderr, "%s:%d Assertion failed: " #expr " (" fmt ")\n", __FILE__,   \
				__LINE__, ##__VA_ARGS__);                                          \
			assert(0);                                                                 \
		}                                                                                  \
	})
#else
#define arc_assert(flag)  while(!(flag))
#define arc_assert_msg(flag, ...)  while(!(flag))
#endif /* CORAL_BFM_MODE */
#else
#ifdef CORAL_BFM_MODE
#define arc_assert(flag) assert(flag)
#define arc_assert_msg(expr, fmt, ...)                                                             \
	({                                                                                         \
		int ____flag____ = (expr);                                                         \
		if (!____flag____) {                                                               \
			fprintf(stderr, "%s:%d Assertion failed: " #expr " (" fmt ")\n", __FILE__,   \
				__LINE__, ##__VA_ARGS__);                                          \
			assert(0);                                                                 \
		}                                                                                  \
	})
#else
#define arc_assert(flag)
#define arc_assert_msg(expr, fmt, ...)
#endif /* CORAL_BFM_MODE */
#endif /* ARC_DEBUG */

void arc_log_error(u32 value);

#ifdef ARC_DEBUG
#define checkpoint(x) arc_log_error(x)
#else
#define checkpoint(value)
#endif

#endif /* __ARC_DEBUG_H__ */
