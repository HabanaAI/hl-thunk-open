/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __UTILS_FNS_H__
#define __UTILS_FNS_H__

#include "arc_types.h"

u32 arc_strlen(const char *s);
void* arc_memset(void *s, s32 c, u32 n);
void* arc_memset32(void *s, s32 c, u32 n);
void* arc_memcpy(void *dst, const void *src, u32 n);
void arc_memcpy32(void *dst, const void *src, u32 n);
u32 count_bits(u32 input_bitmap);
#endif /* __UTILS_H__ */
