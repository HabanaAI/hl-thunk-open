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

void test_tdr_deadlock(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[1];
	void *ptr;
	uint64_t seq = 0;
	uint32_t page_size = sysconf(_SC_PAGESIZE), offset = 0;
	int rc, fd = tests_state->fd;

	ptr = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(ptr, NULL);

	offset = hltests_add_fence_pkt(fd, ptr, offset, false, false, 1, 1, 0);

	execute_arr[0].cb_ptr = ptr;
	execute_arr[0].cb_size = offset;
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, 0, 0);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, false, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_not_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_destroy_cb(fd, ptr);
	assert_int_equal(rc, 0);
}

void test_endless_memory_ioctl(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t page_size = sysconf(_SC_PAGESIZE);
	void *src_ptr;
	int rc, fd = tests_state->fd;

	/* Don't check return value because we don't want the test to finish
	 * when the driver returns error
	 */

	while (1) {
		src_ptr = hltests_allocate_host_mem(fd, page_size, false);

		usleep(1000);

		rc = hltests_free_host_mem(fd, src_ptr);

		usleep(1000);
	}
}

void test_print_hw_ip_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	printf("\nDevice information:");
	printf("\n-----------------------");
	printf("\nDevice id        : 0x%x", hw_ip.device_id);
	printf("\nDRAM enabled     : %d", hw_ip.dram_enabled);
	printf("\nDRAM base address: 0x%lx", hw_ip.dram_base_address);
	printf("\nDRAM size        : %lu (0x%lx)", hw_ip.dram_size,
							hw_ip.dram_size);
	printf("\nSRAM base address: 0x%lx", hw_ip.sram_base_address);
	printf("\nSRAM size        : %u (0x%x)", hw_ip.sram_size,
							hw_ip.sram_size);
	printf("\n\n");
}

const struct CMUnitTest debug_tests[] = {
	cmocka_unit_test_setup(test_tdr_deadlock,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_endless_memory_ioctl,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_print_hw_ip_info,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"debug [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID, debug_tests,
			sizeof(debug_tests) / sizeof((debug_tests)[0]));

	if (!hltests_get_parser_run_disabled_tests())
		return 0;

	return cmocka_run_group_tests(debug_tests, hltests_setup,
					hltests_teardown);
}
