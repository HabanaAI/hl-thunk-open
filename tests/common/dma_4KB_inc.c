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

DMA_1KB_INC_SRAM(test_dma_sram_size_16KB, state, 16 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_20KB, state, 20 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_24KB, state, 24 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_28KB, state, 28 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_32KB, state, 32 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_36KB, state, 36 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_40KB, state, 40 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_44KB, state, 44 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_48KB, state, 48 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_52KB, state, 52 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_56KB, state, 56 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_60KB, state, 60 * 1024)

DMA_1KB_INC_DRAM(test_dma_dram_size_16KB, state, 16 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_20KB, state, 20 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_24KB, state, 24 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_28KB, state, 28 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_32KB, state, 32 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_36KB, state, 36 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_40KB, state, 40 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_44KB, state, 44 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_48KB, state, 48 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_52KB, state, 52 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_56KB, state, 56 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_60KB, state, 60 * 1024)

const struct CMUnitTest dma_4KB_inc_tests[] = {
	cmocka_unit_test_setup(test_dma_sram_size_16KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_20KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_24KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_28KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_32KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_36KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_40KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_44KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_48KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_52KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_56KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_60KB,
			hltests_ensure_device_operational),

	cmocka_unit_test_setup(test_dma_dram_size_16KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_20KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_24KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_28KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_32KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_36KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_40KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_44KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_48KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_52KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_56KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_60KB,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"dma_4KB_inc [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID,
		dma_4KB_inc_tests,
		sizeof(dma_4KB_inc_tests) / sizeof((dma_4KB_inc_tests)[0]));

	return cmocka_run_group_tests(dma_4KB_inc_tests, hltests_setup,
					hltests_teardown);
}
