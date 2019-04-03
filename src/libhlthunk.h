/* SPDX-License-Identifier: MIT
 *
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef LIBHLTHUNK_H
#define LIBHLTHUNK_H

#include "hlthunk.h"

/* HL thunk logging usage */
extern int hlthunk_debug_level;

#define hlthunk_print(level, fmt, ...) \
do { \
	char *envvar; \
	int debug_level; \
	if (hlthunk_debug_level == HLTHUNK_DEBUG_LEVEL_NA) { \
		hlthunk_debug_level = HLTHUNK_DEBUG_LEVEL_DEFAULT; \
		envvar = getenv("HLTHUNK_DEBUG_LEVEL"); \
		if (envvar) { \
			debug_level = atoi(envvar); \
			if (debug_level >= HLTHUNK_DEBUG_LEVEL_ERR \
				&& debug_level <= HLTHUNK_DEBUG_LEVEL_DEBUG) \
				hlthunk_debug_level = debug_level; \
		} \
	} \
	if (level <= hlthunk_debug_level) \
		fprintf(stderr, fmt, ##__VA_ARGS__); \
} while (0)

#define HLTHUNK_DEBUG_LEVEL_NA		-1
#define HLTHUNK_DEBUG_LEVEL_DEFAULT	0
#define HLTHUNK_DEBUG_LEVEL_ERR		3
#define HLTHUNK_DEBUG_LEVEL_WARNING	4
#define HLTHUNK_DEBUG_LEVEL_INFO	6
#define HLTHUNK_DEBUG_LEVEL_DEBUG	7

#define pr_err(fmt, ...) \
	hlthunk_print(HLTHUNK_DEBUG_LEVEL_ERR, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) \
	hlthunk_print(HLTHUNK_DEBUG_LEVEL_WARNING, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) \
	hlthunk_print(HLTHUNK_DEBUG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) \
	hlthunk_print(HLTHUNK_DEBUG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)

#undef hlthunk_public
#define hlthunk_public

#endif /* LIBHLTHUNK_H */
