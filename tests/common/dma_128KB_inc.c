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

DMA_1KB_INC_SRAM(test_dma_sram_size_512KB, state, 512 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_640KB, state, 640 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_768KB, state, 768 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_896KB, state, 896 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_1024KB, state, 1024 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_1152KB, state, 1152 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_1280KB, state, 1280 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_1408KB, state, 1408 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_1536KB, state, 1536 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_1664KB, state, 1664 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_1792KB, state, 1792 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_1920KB, state, 1920 * 1024)

DMA_1KB_INC_DRAM(test_dma_dram_size_512KB, state, 512 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_640KB, state, 640 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_768KB, state, 768 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_896KB, state, 896 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_1024KB, state, 1024 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_1152KB, state, 1152 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_1280KB, state, 1280 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_1408KB, state, 1408 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_1536KB, state, 1536 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_1664KB, state, 1664 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_1792KB, state, 1792 * 1024)
DMA_1KB_INC_DRAM(test_dma_dram_size_1920KB, state, 1920 * 1024)

const struct CMUnitTest dma_128KB_inc_tests[] = {
	cmocka_unit_test_setup(test_dma_sram_size_512KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_640KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_768KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_896KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1024KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1152KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1280KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1408KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1536KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1664KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1792KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_1920KB,
			hltests_ensure_device_operational),

	cmocka_unit_test_setup(test_dma_dram_size_512KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_640KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_768KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_896KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1024KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1152KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1280KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1408KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1536KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1664KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1792KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1920KB,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"dma_128KB_inc [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID,
		dma_128KB_inc_tests,
		sizeof(dma_128KB_inc_tests) / sizeof((dma_128KB_inc_tests)[0]));

	return cmocka_run_group_tests(dma_128KB_inc_tests, hltests_setup,
					hltests_teardown);
}
