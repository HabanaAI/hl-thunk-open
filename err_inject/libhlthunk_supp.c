// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "hlthunk.h"
#include "hlthunk_err_inject.h"
#include "libhlthunk_supp.h"
#include "specs/pci_ids.h"

#define _GNU_SOURCE

#define WAIT_FOR_CS_DEFAULT_TIMEOUT	5000000 /* 5 sec */

#define CS_FLAGS_FORCE_RESTORE		0x1

#define PAGE_SHIFT_4KB			12
#define PAGE_SHIFT_64KB			16

#define PAGE_SIZE_4KB			(1UL << PAGE_SHIFT_4KB)
#define PAGE_SIZE_64KB			(1UL << PAGE_SHIFT_64KB)

struct hlthunc_allocated_memory {
	void *host_ptr;
	uint64_t device_virt_addr;
	uint64_t size;
	bool is_host;
};

struct hlthunk_cs_chunk {
	struct hlthunk_cb_obj *cb_obj;
	uint32_t cb_size;
	uint32_t queue_index;
};

struct hlthunk_asic_funcs *get_asic_funcs_goya(void);

struct hlthunk_asic_funcs *hlthunk_get_asic_funcs(int fd)
{
	switch (hlthunk_get_device_name_from_fd(fd)) {
	case HLTHUNK_DEVICE_GOYA:
		return get_asic_funcs_goya();
	default:
		return NULL;
	}
}

static void *hlthunk_cb_mmap(int fd, size_t length, off_t offset)
{
	return mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			offset);
}

static int hlthunk_cb_munmap(void *addr, size_t length)
{
	return munmap(addr, length);
}

static int fill_cs_chunk(struct hl_cs_chunk *chunk,
			 struct hlthunk_cb_obj *cb_obj,
			 uint32_t cb_size,
			 uint32_t queue_index)
{
	chunk->cb_handle = cb_obj->cb_handle;
	chunk->queue_index = queue_index;
	chunk->cb_size = cb_size;

	return 0;
}

static int hlthunk_submit_cs(int fd,
		struct hlthunk_cs_chunk restore_arr[],
		uint32_t restore_arr_size,
		struct hlthunk_cs_chunk execute_arr[],
		uint32_t execute_arr_size,
		uint32_t flags,
		uint64_t *seq)
{
	struct hl_cs_chunk *chunks_restore = NULL, *chunks_execute = NULL;
	struct hlthunk_cs_in cs_in;
	struct hlthunk_cs_out cs_out;
	uint32_t size, i;
	int rc = 0;

	if (!restore_arr_size && !execute_arr_size)
		return 0;

	if (restore_arr_size && restore_arr) {
		size = restore_arr_size * sizeof(*chunks_restore);
		chunks_restore = hlthunk_malloc(size);
		if (!chunks_restore) {
			rc = -ENOMEM;
			goto out;
		}

		for (i = 0 ; i < restore_arr_size ; i++) {
			rc = fill_cs_chunk(&chunks_restore[i],
					restore_arr[i].cb_obj,
					restore_arr[i].cb_size,
					restore_arr[i].queue_index);
			if (rc)
				goto free_chunks_restore;
		}

	}

	if (execute_arr_size && execute_arr) {
		size = execute_arr_size * sizeof(*chunks_execute);
		chunks_execute = hlthunk_malloc(size);
		if (!chunks_execute) {
			rc = -ENOMEM;
			goto free_chunks_restore;
		}

		for (i = 0 ; i < execute_arr_size ; i++) {
			rc = fill_cs_chunk(&chunks_execute[i],
					   execute_arr[i].cb_obj,
					   execute_arr[i].cb_size,
					   execute_arr[i].queue_index);
			if (rc)
				goto free_chunks_execute;
		}

	}

	memset(&cs_in, 0, sizeof(cs_in));
	cs_in.chunks_restore = chunks_restore;
	cs_in.chunks_execute = chunks_execute;
	cs_in.num_chunks_restore = restore_arr_size;
	cs_in.num_chunks_execute = execute_arr_size;
	if (flags & CS_FLAGS_FORCE_RESTORE)
		cs_in.flags |= HL_CS_FLAGS_FORCE_RESTORE;

	memset(&cs_out, 0, sizeof(cs_out));
	rc = hlthunk_command_submission(fd, &cs_in, &cs_out);
	if (rc)
		goto free_chunks_execute;

	if (cs_out.status != HL_CS_STATUS_SUCCESS) {
		rc = -EINVAL;
		goto free_chunks_execute;
	}

	*seq = cs_out.seq;

free_chunks_execute:
	hlthunk_free(chunks_execute);
free_chunks_restore:
	hlthunk_free(chunks_restore);
out:
	return rc;
}

static int hlthunk_err_inj_wait_for_cs(int fd, uint64_t seq,
					uint64_t timeout_us)
{
	uint32_t status;
	int rc;

	rc = hlthunk_wait_for_cs(fd, seq, timeout_us, &status);
	if (rc && errno != ETIMEDOUT && errno != EIO)
		return rc;

	return status;
}

static int hlthunk_wait_for_cs_until_not_busy(int fd, uint64_t seq)
{
	int status;

	do {
		status = hlthunk_err_inj_wait_for_cs(fd, seq,
						   WAIT_FOR_CS_DEFAULT_TIMEOUT);
	} while (status == HL_WAIT_CS_STATUS_BUSY);

	return status;
}

struct hlthunk_cb_obj *hlthunk_create_cb_obj(int fd, uint32_t cb_size,
					uint64_t cb_internal_sram_address)
{
	struct hlthunk_cb_obj *cb_obj;
	int rc;

	cb_obj = hlthunk_malloc(sizeof(*cb_obj));
	if (!cb_obj)
		return NULL;

	cb_obj->cb_size = cb_size;

	rc = hlthunk_request_command_buffer(fd, cb_obj->cb_size,
					    &cb_obj->cb_handle);
	if (rc)
		goto free_cb;

	cb_obj->cb_ptr = hlthunk_cb_mmap(fd,
					 cb_obj->cb_size, cb_obj->cb_handle);
	if (cb_obj->cb_ptr == MAP_FAILED)
		goto destroy_cb_obj;

	return cb_obj;

destroy_cb_obj:
	hlthunk_destroy_command_buffer(fd, cb_obj->cb_handle);
free_cb:
	hlthunk_free(cb_obj);
	return NULL;
}

uint32_t hlthunk_add_packet_to_cb(void *ptr, uint32_t offset,
				  void *pkt, uint32_t pkt_size)
{
	memcpy((uint8_t *) ptr + offset, pkt, pkt_size);

	return offset + pkt_size;
}

int hlthunk_submit_and_wait_cs(int fd, struct hlthunk_cb_obj *cb_obj,
			       uint32_t cb_size,
			       uint32_t queue_index,
			       int expected_val)
{
	struct hlthunk_cs_chunk execute_arr[1];
	uint64_t seq = 0;
	int rc;

	execute_arr[0].cb_obj = cb_obj;
	execute_arr[0].cb_size = cb_size;
	execute_arr[0].queue_index = queue_index;
	rc = hlthunk_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq);
	if (rc)
		return -EFAULT;

	rc = hlthunk_wait_for_cs_until_not_busy(fd, seq);
	if (rc == expected_val)
		return 0;
	else
		return -EFAULT;
}

void hlthunk_destroy_cb(int fd, struct hlthunk_cb_obj *cb_obj)
{
	hlthunk_cb_munmap(cb_obj->cb_ptr, cb_obj->cb_size);
	hlthunk_destroy_command_buffer(fd, cb_obj->cb_handle);
	hlthunk_free(cb_obj);
}
