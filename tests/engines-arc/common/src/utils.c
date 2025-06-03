/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef CORAL_BFM_MODE
#include <arc_intrinsics.h>
#endif

#include "compile_target.h"

#ifdef CORAL_BFM_MODE
#ifdef SCHED_ARC
#include "scheduler_bfm.hpp"
#endif
#ifdef ENGINE_ARC
#include "engine_bfm.hpp"
#endif
#endif

#include "utils.h"
#include "debug.h"

#include "comm_asic_specific_data.h"

struct arc_comm_regs *cr;

u32 CORAL_CLS_PREFIX arc_strlen(const char *s)
{
	u32 len = 0;

	while (s[len])
		len++;
	return len;
}

void* CORAL_CLS_PREFIX arc_memset(void *s, s32 c, u32 n)
{
	u8 val = c;
	u8 *dst = (u8 *)s;

	while (n > 0) {
		*dst = val;
		dst++; n--;
	}
	return s;
}

void* CORAL_CLS_PREFIX arc_memset32(void *s, s32 c, u32 n)
{
	u32 val = c << 24 | c << 16 | c << 8 | c;
	u32 *dst = (u32 *)s;

	arc_assert(n % 4 == 0);

	n = n / 4;
	while (n > 0) {
		*dst = val;
		dst++; n--;
	}
	return s;
}

void* CORAL_CLS_PREFIX arc_memcpy(void *dst, const void *src, u32 n)
{
	u32 *dst32 = (u32 *)dst;
	u32 *src32 = (u32 *)src;
	u32 size = n / 4;
	u8 *src8, *dst8;

	while (size > 0) {
		*dst32 = *src32;
		dst32++; src32++;
		size--;
	}

	size = n % 4;
	src8 = (u8 *)src32;
	dst8 = (u8 *)dst32;

	while (size > 0) {
		*dst8 = *src8;
		dst8++; src8++;
		size--;
	}
	return dst;
}

void CORAL_CLS_PREFIX arc_memcpy32(void *dst, const void *src, u32 n)
{
	u32 *dst32 = (u32 *)dst;
	u32 *src32 = (u32 *)src;

	while (n > 0) {
		*dst32 = *src32;
		dst32++; src32++;
		n--;
	}
}

u32 CORAL_CLS_PREFIX count_bits(u32 input_bitmap)
{
	u32 count = 0;
	u32 position;

	while(input_bitmap) {
		position = _ffs(input_bitmap);
		input_bitmap &= ~(1 << position);
		count++;
	}
	return count;
}
