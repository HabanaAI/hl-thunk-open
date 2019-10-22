// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#include "hlthunk_tests.h"
#include "ini.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>

void test_print_hw_ip_info(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();
	struct hlthunk_hw_ip_info hw_ip;
	int rc, fd;

	fd = hlthunk_open_control(0, pciaddr);
	assert_in_range(fd, 0, INT_MAX);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	printf("\nDevice information:");
	printf("\n-----------------------");
	printf("\nPCI Device id    : 0x%x", hw_ip.device_id);
	printf("\nCard name        : %s", hw_ip.card_name);
	printf("\nDRAM enabled     : %d", hw_ip.dram_enabled);
	printf("\nDRAM base address: 0x%lx", hw_ip.dram_base_address);
	printf("\nDRAM size        : %lu (0x%lx)", hw_ip.dram_size,
							hw_ip.dram_size);
	printf("\nSRAM base address: 0x%lx", hw_ip.sram_base_address);
	printf("\nSRAM size        : %u (0x%x)", hw_ip.sram_size,
							hw_ip.sram_size);
	printf("\n\n");

	hlthunk_close(fd);
}

static void print_engine_name(enum hlthunk_device_name device_id,
					uint32_t engine_id)
{
	if (device_id == HLTHUNK_DEVICE_GOYA) {
		switch (engine_id) {
		case GOYA_ENGINE_ID_DMA_0 ... GOYA_ENGINE_ID_DMA_4:
			printf("  DMA%d\n", engine_id - GOYA_ENGINE_ID_DMA_0);
			break;
		case GOYA_ENGINE_ID_MME_0:
			printf("  MME\n");
			break;
		case GOYA_ENGINE_ID_TPC_0 ... GOYA_ENGINE_ID_TPC_7:
			printf("  TPC%d\n", engine_id - GOYA_ENGINE_ID_TPC_0);
			break;
		default:
			fail_msg("Unexpected engine id %d\n", engine_id);
		}
	} else {
		fail_msg("Unexpected device id %d\n", device_id);
	}
}

void test_print_hw_idle_info(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();
	enum hlthunk_device_name device_id;
	uint32_t busy_engines_mask, i;
	bool is_idle;
	int rc, fd;

	fd = hlthunk_open_control(0, pciaddr);
	assert_in_range(fd, 0, INT_MAX);

	printf("\n");
	printf("Idle status\n");
	printf("-----------\n");

	is_idle = hlthunk_is_device_idle(fd);
	if (is_idle) {
		printf("Device is idle\n");
		goto out;
	}

	rc = hlthunk_get_busy_engines_mask(fd, &busy_engines_mask);
	assert_int_equal(rc, 0);

	device_id = hlthunk_get_device_name_from_fd(fd);

	printf("Busy engine(s):\n");
	for (i = 0 ; i < 32; i++)
		if (busy_engines_mask & (1 << i))
			print_engine_name(device_id, i);
out:
	printf("\n");
	hlthunk_close(fd);
}

void test_print_dram_usage_info_no_stop(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();
	struct hlthunk_dram_usage_info dram_usage;
	int rc, fd;

	fd = hlthunk_open_control(0, pciaddr);
	assert_in_range(fd, 0, INT_MAX);

	printf("\n");

	while (1) {
		memset(&dram_usage, 0, sizeof(dram_usage));

		rc = hlthunk_get_dram_usage(fd, &dram_usage);
		assert_int_equal(rc, 0);

		printf("dram free memory: %"PRIu64"MB\n",
			dram_usage.dram_free_mem / 1024 / 1024);

		usleep(250 * 1000);
	}
}

void test_print_device_utilization_no_stop(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();
	uint32_t rate;
	int rc, fd;

	fd = hlthunk_open_control(0, pciaddr);
	assert_in_range(fd, 0, INT_MAX);

	printf("\n");

	while (1) {
		rc = hlthunk_get_device_utilization(fd, 500, &rate);
		assert_int_equal(rc, 0);

		printf("device utilization: %u%%\n", rate);

		usleep(450 * 1000);
	}
}

void test_print_clk_rate(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();
	uint32_t cur_clk, max_clk;
	int rc, fd;

	fd = hlthunk_open_control(0, pciaddr);
	assert_in_range(fd, 0, INT_MAX);

	rc = hlthunk_get_clk_rate(fd, &cur_clk, &max_clk);
	assert_int_equal(rc, 0);

	printf("\nCurrent clock rate: %dMHz\n", cur_clk);
	printf("Maximum clock rate: %dMHz\n\n", max_clk);

	hlthunk_close(fd);
}

const struct CMUnitTest control_tests[] = {
	cmocka_unit_test(test_print_hw_ip_info),
	cmocka_unit_test(test_print_hw_idle_info),
	cmocka_unit_test(test_print_dram_usage_info_no_stop),
	cmocka_unit_test(test_print_device_utilization_no_stop),
	cmocka_unit_test(test_print_clk_rate)
};

static const char *const usage[] = {
	"control_device [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(control_tests) / sizeof((control_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE,
			control_tests, num_tests);

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("This executable need to be run with -d flag\n");
		return 0;
	}

	return hltests_run_group_tests("control_device", control_tests,
					num_tests, NULL, NULL);
}
