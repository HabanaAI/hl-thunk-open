/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#ifndef __ARC_TYPES_H__
#define __ARC_TYPES_H__

#include <stdint.h>

/**
 * \file    arc_types.h
 * \brief   Data types for firmware usage
 */

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#ifndef NULL
#define NULL	0
#endif

#define true	1
#define false	0

#endif /* __ARC_TYPES_H__ */
