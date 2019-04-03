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

DMA_1KB_INC_SRAM(test_dma_sram_size_1KB, state, 1 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_2KB, state, 2 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_3KB, state, 3 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_4KB, state, 4 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_5KB, state, 5 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_6KB, state, 6 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_7KB, state, 7 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_8KB, state, 8 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_9KB, state, 9 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_10KB, state, 10 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_11KB, state, 11 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_12KB, state, 12 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_13KB, state, 13 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_14KB, state, 14 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_15KB, state, 15 * 1024)

DMA_1KB_INC_DRAM(test_dma_dram_size_1KB, state, 1 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_2KB, state, 2 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_3KB, state, 3 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_4KB, state, 4 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_5KB, state, 5 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_6KB, state, 6 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_7KB, state, 7 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_8KB, state, 8 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_9KB, state, 9 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_10KB, state, 10 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_11KB, state, 11 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_12KB, state, 12 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_13KB, state, 13 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_14KB, state, 14 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_15KB, state, 15 * 1024)

const struct CMUnitTest dma_1KB_inc_tests[] = {
	cmocka_unit_test_setup(test_dma_sram_size_1KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_2KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_3KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_4KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_5KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_6KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_7KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_8KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_9KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_10KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_11KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_12KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_13KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_14KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_15KB,
			hltests_ensure_device_operational),

	cmocka_unit_test_setup(test_dma_dram_size_1KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_2KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_3KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_4KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_5KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_6KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_7KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_8KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_9KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_10KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_11KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_12KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_13KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_14KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_15KB,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"dma_1KB_inc [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID,
		dma_1KB_inc_tests,
		sizeof(dma_1KB_inc_tests) / sizeof((dma_1KB_inc_tests)[0]));

	return cmocka_run_group_tests(dma_1KB_inc_tests, hltests_setup,
					hltests_teardown);
}
