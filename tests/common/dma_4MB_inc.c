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

DMA_1KB_INC_SRAM(test_dma_sram_size_16MB, state, 16 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_20MB, state, 20 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_24MB, state, 24 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_28MB, state, 28 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_32MB, state, 32 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_36MB, state, 36 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_40MB, state, 40 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_44MB, state, 44 * 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_48MB, state, 48 * 1024 * 1024)

DMA_1KB_INC_DRAM(test_dma_dram_size_16MB, state, 16 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_20MB, state, 20 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_24MB, state, 24 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_28MB, state, 28 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_32MB, state, 32 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_36MB, state, 36 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_40MB, state, 40 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_44MB, state, 44 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_48MB, state, 48 * 1024 * 1024)

const struct CMUnitTest dma_4MB_inc_tests[] = {
	cmocka_unit_test_setup(test_dma_sram_size_16MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_20MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_24MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_28MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_32MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_36MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_40MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_44MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_48MB,
			hltests_ensure_device_operational),

	cmocka_unit_test_setup(test_dma_dram_size_16MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_20MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_24MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_28MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_32MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_36MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_40MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_44MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_48MB,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"dma_4MB_inc [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID,
		dma_4MB_inc_tests,
		sizeof(dma_4MB_inc_tests) / sizeof((dma_4MB_inc_tests)[0]));

	return cmocka_run_group_tests(dma_4MB_inc_tests, hltests_setup,
					hltests_teardown);
}
