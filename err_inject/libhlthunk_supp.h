// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#ifndef LIBHLTHUNK_SUPP_H
#define LIBHLTHUNK_SUPP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>

struct hlthunk_cb_obj {
	void *cb_ptr;
	uint64_t cb_handle;
	uint32_t cb_size;
};

/* Should be removed when a more appropriate enum is defined in habanalabs.h */
enum hlthunk_dcore_separation_mode {
	DCORE_MODE_FULL_CHIP,
	DCORE_MODE_HALF_CHIP,
	DCORE_MODE_ENUM_MAX
};

enum hlthunk_stream_id {
	STREAM0 = 0,
	STREAM1,
	STREAM2,
	STREAM3
};

struct hlthunk_pkt_info {
	bool eb;
	bool mb;
	union {
		struct {
			uint8_t dec_val;
			uint8_t gate_val;
			uint8_t fence_id;
		} fence;
	};
};

struct hlthunk_asic_funcs {
	uint32_t (*add_fence_pkt)(void *buffer, uint32_t buf_off,
					struct hlthunk_pkt_info *pkt_info);
	uint32_t (*get_dma_down_qid)(
			enum hlthunk_dcore_separation_mode dcore_sep_mode,
			enum hlthunk_stream_id stream);
	int (*generate_non_fatal_event)(int fd, int *event_num);
	int (*generate_fatal_event)(struct hlthunk_debugfs *debugfs,
					int *event_num);
	int (*halt_cpu)(struct hlthunk_debugfs *debugfs);
};

struct hlthunk_asic_funcs *hlthunk_get_asic_funcs(int fd);

struct hlthunk_cb_obj *hlthunk_create_cb_obj(int fd, uint32_t cb_size,
					uint64_t cb_internal_sram_address);

uint32_t hlthunk_add_packet_to_cb(void *ptr, uint32_t offset,
				  void *pkt, uint32_t pkt_size);

int hlthunk_submit_and_wait_cs(int fd, struct hlthunk_cb_obj *cb_obj,
			       uint32_t cb_size,
			       uint32_t queue_index,
			       int expected_val);

void hlthunk_destroy_cb(int fd, struct hlthunk_cb_obj *cb_obj);

#endif /* LIBHLTHUNK_SUPP_H */
