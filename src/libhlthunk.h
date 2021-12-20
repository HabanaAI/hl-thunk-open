/* SPDX-License-Identifier: MIT
 *
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef LIBHLTHUNK_H
#define LIBHLTHUNK_H

#include "hlthunk.h"
#include "specs/version.h"

#define _STRINGIFY(x)	#x
#define STRINGIFY(x)	_STRINGIFY(x)

/* \40 - hack for adding space char */
#ident STRINGIFY(hl-thunk version:\040 HL_DRIVER_MAJOR.HL_DRIVER_MINOR. \
			HL_DRIVER_PATCHLEVEL-HLTHUNK_GIT_SHA)

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


/**
 * Declerations of the original hlthunk functions implementations
 * to be set as default functions in the functions pointers table
 */
int hlthunk_command_submission_original(int fd, struct hlthunk_cs_in *in,
					struct hlthunk_cs_out *out);
int hlthunk_open_original(enum hlthunk_device_name device_name,
			  const char *busid);
int hlthunk_close_original(int fd);
int hlthunk_profiler_start_original(int fd);
int hlthunk_profiler_stop_original(int fd);
int hlthunk_profiler_get_trace_original(int fd, void *buffer, uint64_t *size);

#undef hlthunk_public
#define hlthunk_public

#endif /* LIBHLTHUNK_H */
