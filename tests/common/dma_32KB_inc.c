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
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_96KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_128KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_160KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_192KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_224KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_256KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_288KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_320KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_352KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_384KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_416KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_448KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_sram_size_480KB,
			hl_tests_ensure_device_operational),

	cmocka_unit_test_setup(test_dma_dram_size_64KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_96KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_128KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_160KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_192KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_224KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_256KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_288KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_320KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_352KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_384KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_416KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_448KB,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_480KB,
			hl_tests_ensure_device_operational),
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
