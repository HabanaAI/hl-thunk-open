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

DMA_1KB_INC_SRAM(test_dma_sram_size_2MB, state, 2 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_3MB, state, 3 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_4MB, state, 4 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_5MB, state, 5 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_6MB, state, 6 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_7MB, state, 7 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_8MB, state, 8 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_9MB, state, 9 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_10MB, state, 10 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_11MB, state, 11 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_12MB, state, 12 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_13MB, state, 13 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_14MB, state, 14 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_15MB, state, 15 * 1024 * 1024)

DMA_1KB_INC_DRAM(test_dma_dram_size_2MB, state, 2 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_3MB, state, 3 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_4MB, state, 4 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_5MB, state, 5 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_6MB, state, 6 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_7MB, state, 7 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_8MB, state, 8 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_9MB, state, 9 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_10MB, state, 10 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_11MB, state, 11 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_12MB, state, 12 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_13MB, state, 13 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_14MB, state, 14 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_15MB, state, 15 * 1024 * 1024)

const struct CMUnitTest dma_1MB_inc_tests[] = {
	cmocka_unit_test_setup(test_dma_sram_size_2MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_3MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_4MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_5MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_6MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_7MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_8MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_9MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_10MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_11MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_12MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_13MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_14MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_15MB,
			hltests_ensure_device_operational),

	cmocka_unit_test_setup(test_dma_dram_size_2MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_3MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_4MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_5MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_6MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_7MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_8MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_9MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_10MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_11MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_12MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_13MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_14MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_15MB,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"dma_1MB_inc [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID,
		dma_1MB_inc_tests,
		sizeof(dma_1MB_inc_tests) / sizeof((dma_1MB_inc_tests)[0]));

	return cmocka_run_group_tests(dma_1MB_inc_tests, hltests_setup,
					hltests_teardown);
}
