// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#include "hlthunk_tests.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

/**
 * This test checks that a mapping of more than 4GB is successful. This big size
 * enforces the KMD to store it in a u64 variable rather than u32 variable.
 * In addition the test performs DMA transfers to verify that the mapping is
 * correct.
 * The DMA size shouldn't be too big to avoid too big command buffers.
 * @param state contains the open file descriptor.
 */
void test_map_bigger_than_4GB(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	void *device_addr, *src_ptr, *dst_ptr;
	uint64_t host_src_addr, host_dst_addr, total_size = (1ull << 30) * 5,
		dma_size = 1 << 26, offset = 0;
	uint32_t dma_dir_down, dma_dir_up;
	int rc, fd = tests_state->fd;

	/* Sanity and memory allocation */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	assert_int_equal(hw_ip.dram_enabled, 1);
	assert_in_range(dma_size, 1, hw_ip.dram_size);

	device_addr = hltests_allocate_device_mem(fd, dma_size);
	assert_non_null(device_addr);

	dma_dir_down = GOYA_DMA_HOST_TO_DRAM;
	dma_dir_up = GOYA_DMA_DRAM_TO_HOST;

	src_ptr = hltests_allocate_host_mem(fd, total_size, false);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, total_size);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, dma_size, false);
	assert_non_null(dst_ptr);
	memset(dst_ptr, 0, dma_size);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	/* We don't need to transfer the entire size.
	 * Do a sample DMA every 512MB
	 */
	while (offset < total_size) {
		/* DMA: host->device */
		hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, 0, 0), 0,
			1, (host_src_addr + offset),
			(uint64_t) (uintptr_t) device_addr, dma_size,
			dma_dir_down);

		/* DMA: device->host */
		hltests_dma_transfer(fd, hltests_get_dma_up_qid(fd, 0, 0), 0, 1,
			(uint64_t) (uintptr_t) device_addr, host_dst_addr,
			dma_size, dma_dir_up);

		/* Compare host memories */
		rc = hltests_mem_compare(
				(void *) ((uintptr_t) src_ptr + offset),
				dst_ptr, dma_size);
		assert_int_equal(rc, 0);

		offset += (1ull << 29);
	}

	/* Cleanup */
	rc = hltests_free_host_mem(fd, dst_ptr);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, src_ptr);
	assert_int_equal(rc, 0);

	rc = hltests_free_device_mem(fd, device_addr);
	assert_int_equal(rc, 0);
}

const struct CMUnitTest memory_tests[] = {
	cmocka_unit_test_setup(test_map_bigger_than_4GB,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"memory [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID, memory_tests,
			sizeof(memory_tests) / sizeof((memory_tests)[0]));

	return cmocka_run_group_tests(memory_tests, hltests_setup,
					hltests_teardown);
}
