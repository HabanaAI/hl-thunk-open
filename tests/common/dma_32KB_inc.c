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

DMA_1KB_INC_SRAM(test_dma_sram_size_64KB, state, 64 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_96KB, state, 96 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_128KB, state, 128 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_160KB, state, 160 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_192KB, state, 192 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_224KB, state, 224 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_256KB, state, 256 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_288KB, state, 288 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_320KB, state, 320 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_352KB, state, 352 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_384KB, state, 384 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_416KB, state, 416 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_448KB, state, 448 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_480KB, state, 480 * 1024)

DMA_1KB_INC_DRAM(test_dma_dram_size_64KB, state, 64 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_96KB, state, 96 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_128KB, state, 128 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_160KB, state, 160 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_192KB, state, 192 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_224KB, state, 224 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_256KB, state, 256 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_288KB, state, 288 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_320KB, state, 320 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_352KB, state, 352 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_384KB, state, 384 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_416KB, state, 416 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_448KB, state, 448 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_480KB, state, 480 * 1024)

const struct CMUnitTest dma_32KB_inc_tests[] = {
	cmocka_unit_test_setup(test_dma_sram_size_64KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_96KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_128KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_160KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_192KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_224KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_256KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_288KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_320KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_352KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_384KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_416KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_448KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_480KB,
			hltests_ensure_device_operational),

	cmocka_unit_test_setup(test_dma_dram_size_64KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_96KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_128KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_160KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_192KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_224KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_256KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_288KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_320KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_352KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_384KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_416KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_448KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_480KB,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"dma_32KB_inc [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID,
		dma_32KB_inc_tests,
		sizeof(dma_32KB_inc_tests) / sizeof((dma_32KB_inc_tests)[0]));

	return cmocka_run_group_tests(dma_32KB_inc_tests, hltests_setup,
					hltests_teardown);
}
