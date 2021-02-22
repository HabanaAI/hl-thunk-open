/* SPDX-License-Identifier: MIT
 *
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef LIBHLTHUNK_H
#define LIBHLTHUNK_H

#include "uapi/hlthunk.h"
#include "specs/common/version.h"

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
#define INIT_FUNCS_POINTERS_TABLE {\
	.fp_hlthunk_command_submission = hlthunk_command_submission_original,\
	.fp_hlthunk_command_submission_timeout =\
		hlthunk_command_submission_timeout_original,\
	.fp_hlthunk_signal_submission = hlthunk_signal_submission_original,\
	.fp_hlthunk_signal_submission_timeout =\
		hlthunk_signal_submission_timeout_original,\
	.fp_hlthunk_wait_for_signal = hlthunk_wait_for_signal_original,\
	.fp_hlthunk_wait_for_signal_timeout =\
		hlthunk_wait_for_signal_timeout_original,\
	.fp_hlthunk_open = hlthunk_open_original,\
	.fp_hlthunk_close = hlthunk_close_original,\
	.fp_hlthunk_profiler_start = hlthunk_profiler_start_original,\
	.fp_hlthunk_profiler_stop = hlthunk_profiler_stop_original,\
	.fp_hlthunk_profiler_get_trace = hlthunk_profiler_get_trace_original,\
	.fp_hlthunk_profiler_destroy = hlthunk_profiler_destroy_original,\
	.fp_hlthunk_debug = hlthunk_debug,\
	.fp_hlthunk_device_memory_alloc = hlthunk_device_memory_alloc,\
	.fp_hlthunk_device_memory_free = hlthunk_device_memory_free,\
	.fp_hlthunk_device_memory_map = hlthunk_device_memory_map,\
	.fp_hlthunk_host_memory_map = hlthunk_host_memory_map_original,\
	.fp_hlthunk_memory_unmap = hlthunk_memory_unmap_original,\
	.fp_hlthunk_request_command_buffer = hlthunk_request_command_buffer,\
	.fp_hlthunk_destroy_command_buffer = hlthunk_destroy_command_buffer,\
	.fp_hlthunk_get_cb_usage_count = hlthunk_get_cb_usage_count,\
	.fp_hlthunk_wait_for_cs = hlthunk_wait_for_cs,\
	.fp_hlthunk_get_device_name_from_fd = hlthunk_get_device_name_from_fd,\
	.fp_hlthunk_get_pci_bus_id_from_fd = hlthunk_get_pci_bus_id_from_fd,\
	.fp_hlthunk_get_device_index_from_pci_bus_id =\
		hlthunk_get_device_index_from_pci_bus_id,\
	.fp_hlthunk_malloc = hlthunk_malloc,\
	.fp_hlthunk_free = hlthunk_free,\
	.fp_hlthunk_get_time_sync_info = hlthunk_get_time_sync_info,\
	.fp_hlthunk_wait_for_collective_sig = \
		hlthunk_wait_for_collective_signal_original,\
	.fp_hlthunk_wait_for_collective_sig_timeout = \
		hlthunk_wait_for_collective_signal_timeout_original,\
	.fp_hlthunk_staged_command_submission = \
		hlthunk_staged_command_submission_original,\
	.fp_hlthunk_staged_cs_timeout = \
		hlthunk_staged_command_submission_timeout_original,\
	.fp_hlthunk_get_hw_block = hlthunk_get_hw_block_original,\
	.fp_hlthunk_wait_for_interrupt = hlthunk_wait_for_interrupt\
}

int hlthunk_command_submission_original(int fd, struct hlthunk_cs_in *in,
					struct hlthunk_cs_out *out);
int hlthunk_command_submission_timeout_original(int fd,
					struct hlthunk_cs_in *in,
					struct hlthunk_cs_out *out,
					uint32_t timeout);
int hlthunk_staged_command_submission_original(int fd, uint64_t sequence,
					struct hlthunk_cs_in *in,
					struct hlthunk_cs_out *out);
int hlthunk_staged_command_submission_timeout_original(int fd,
					uint64_t sequence,
					struct hlthunk_cs_in *in,
					struct hlthunk_cs_out *out,
					uint32_t timeout);
int hlthunk_signal_submission_original(int fd, struct hlthunk_signal_in *in,
					struct hlthunk_signal_out *out);
int hlthunk_signal_submission_timeout_original(int fd,
					struct hlthunk_signal_in *in,
					struct hlthunk_signal_out *out,
					uint32_t timeout);
int hlthunk_wait_for_signal_original(int fd, struct hlthunk_wait_in *in,
					struct hlthunk_wait_out *out);
int hlthunk_wait_for_signal_timeout_original(int fd, struct hlthunk_wait_in *in,
					struct hlthunk_wait_out *out,
					uint32_t timeout);
int hlthunk_wait_for_collective_signal_original(int fd,
					struct hlthunk_wait_in *in,
					struct hlthunk_wait_out *out);
int hlthunk_wait_for_collective_signal_timeout_original(int fd,
					struct hlthunk_wait_in *in,
					struct hlthunk_wait_out *out,
					uint32_t timeout);
int hlthunk_open_original(enum hlthunk_device_name device_name,
			  const char *busid);
int hlthunk_close_original(int fd);
int hlthunk_profiler_start_original(int fd);
int hlthunk_profiler_stop_original(int fd);
int hlthunk_profiler_get_trace_original(int fd, void *buffer, uint64_t *size,
					uint64_t *num_entries);
void hlthunk_profiler_destroy_original(void);
uint64_t hlthunk_host_memory_map_original(int fd, void *host_virt_addr,
					  uint64_t hint_addr,
					  uint64_t host_size);
int hlthunk_memory_unmap_original(int fd, uint64_t device_virt_addr);
int hlthunk_get_hw_block_original(int fd, uint64_t block_address,
					uint32_t *block_size, uint64_t *handle);

#undef hlthunk_public
#define hlthunk_public

#endif /* LIBHLTHUNK_H */
