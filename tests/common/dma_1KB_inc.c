/*
 * Copyright (c) 2019 HabanaLabs Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
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
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_2KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_3KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_4KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_5KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_6KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_7KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_8KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_9KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_10KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_11KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_12KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_13KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_14KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_15KB,
			hl_tests_ensure_device_operational),

	cmocka_unit_test_setup(test_dma_dram_size_1KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_2KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_3KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_4KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_5KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_6KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_7KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_8KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_9KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_10KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_11KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_12KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_13KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_14KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_15KB,
			hl_tests_ensure_device_operational),
};

static const char *const usage[] = {
    "dma_1KB_inc [options]",
    NULL,
};

int main(int argc, const char **argv)
{
	char *test_names_to_run;

	test_names_to_run = getenv("HLTHUNK_TESTS_NAMES");
	if (test_names_to_run)
		cmocka_set_test_filter(test_names_to_run);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID,
		dma_1KB_inc_tests,
		sizeof(dma_1KB_inc_tests) / sizeof((dma_1KB_inc_tests)[0]));

	return cmocka_run_group_tests(dma_1KB_inc_tests, hltests_setup,
					hltests_teardown);
}
