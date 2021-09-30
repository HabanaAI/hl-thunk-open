// SPDX-License-Identifier: MIT

/*
 * Copyright 2021 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "ini.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>


VOID test_dmmu_debugfs(struct hltests_state *tests_state, uint64_t hint_addr)
{
	struct hlthunk_hw_ip_info hw_ip;
	uint64_t size, device_handle, device_va, host_va, sample, n_long;
	void *host_mem;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	size = 2 * hw_ip.dram_page_size;
	n_long = size / sizeof(uint64_t);

	host_mem = hltests_allocate_host_mem(fd, size, NOT_HUGE_MAP);
	assert_non_null(host_mem);
	host_va = hltests_get_device_va_for_host_ptr(fd, host_mem);
	hltests_fill_rand_values(host_mem, size);

	device_handle = hlthunk_device_memory_alloc(fd, size, NOT_CONTIGUOUS, false);
	assert_int_not_equal(device_handle, 0);
	device_va = hlthunk_device_memory_map(fd, device_handle, hint_addr);
	assert_int_not_equal(device_handle, 0);

	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, host_va, device_va,
			size, GOYA_DMA_HOST_TO_DRAM);

	sample = 0;
	assert_int_equal(RREG64(device_va + sample * sizeof(uint64_t)),
		((uint64_t *)host_mem)[sample]);

	sample = n_long / 4;
	assert_int_equal(RREG64(device_va + sample * sizeof(uint64_t)),
		((uint64_t *)host_mem)[sample]);

	sample = n_long / 2 - 1;
	assert_int_equal(RREG64(device_va + sample * sizeof(uint64_t)),
		((uint64_t *)host_mem)[sample]);

	sample = n_long / 2;
	assert_int_equal(RREG64(device_va + sample * sizeof(uint64_t)),
		((uint64_t *)host_mem)[sample]);

	sample = n_long / 2 + n_long / 4;
	assert_int_equal(RREG64(device_va + sample * sizeof(uint64_t)),
		((uint64_t *)host_mem)[sample]);

	sample = n_long - 1;
	assert_int_equal(RREG64(device_va + sample * sizeof(uint64_t)),
		((uint64_t *)host_mem)[sample]);

	hlthunk_memory_unmap(fd, device_va);
	hlthunk_device_memory_free(fd, device_handle);
	hltests_free_host_mem(fd, host_mem);

	END_TEST;
}

VOID test_dmmu_debugfs_low_addresses(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;

	END_TEST_FUNC(test_dmmu_debugfs(tests_state, 0));
}

VOID test_dmmu_debugfs_high_addresses(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	END_TEST_FUNC(test_dmmu_debugfs(tests_state, asic->get_dram_va_reserved_addr_start()));
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest debug_tests[] = {
		cmocka_unit_test(test_dmmu_debugfs_low_addresses),
		cmocka_unit_test(test_dmmu_debugfs_high_addresses)
};

static const char *const usage[] = {
	"debug [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(debug_tests) / sizeof((debug_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE, debug_tests,
			num_tests);

	if (access("/sys/kernel/debug", R_OK)) {
		printf("This executable need to be run with sudo\n");
		return 0;
	}

	return hltests_run_group_tests("debugfs", debug_tests, num_tests,
			hltests_root_setup, hltests_root_teardown);
}

#endif /* HLTESTS_LIB_MODE */
