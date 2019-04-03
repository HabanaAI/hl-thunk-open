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

DMA_1KB_INC_DRAM(test_dma_dram_size_64MB, state, 64 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_128MB, state, 128 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_192MB, state, 192 * 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_256MB, state, 256 * 1024 * 1024)

const struct CMUnitTest dma_64MB_inc_tests[] = {
	cmocka_unit_test_setup(test_dma_dram_size_64MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_128MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_192MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_256MB,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"dma_64MB_inc [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID,
		dma_64MB_inc_tests,
		sizeof(dma_64MB_inc_tests) / sizeof((dma_64MB_inc_tests)[0]));

	return cmocka_run_group_tests(dma_64MB_inc_tests, hltests_setup,
					hltests_teardown);
}
