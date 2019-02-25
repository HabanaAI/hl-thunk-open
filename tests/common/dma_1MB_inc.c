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

DMA_1KB_INC_SRAM(test_dma_sram_size_2048KB, state, 2048 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_3072KB, state, 3072 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_4096KB, state, 4096 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_5120KB, state, 5120 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_6144KB, state, 6144 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_7168KB, state, 7168 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_8192KB, state, 8192 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_9216KB, state, 9216 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_10240KB, state, 10240 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_11264KB, state, 11264 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_12288KB, state, 12288 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_13312KB, state, 13312 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_14336KB, state, 14336 * 1024)
DMA_1KB_INC_SRAM(test_dma_sram_size_15360KB, state, 15360 * 1024)

DMA_1KB_INC_DDR(test_dma_ddr_size_2048KB, state, 2048 * 1024)
DMA_1KB_INC_DDR(test_dma_ddr_size_3072KB, state, 3072 * 1024)
DMA_1KB_INC_DDR(test_dma_ddr_size_4096KB, state, 4096 * 1024)
DMA_1KB_INC_DDR(test_dma_ddr_size_5120KB, state, 5120 * 1024)
DMA_1KB_INC_DDR(test_dma_ddr_size_6144KB, state, 6144 * 1024)
DMA_1KB_INC_DDR(test_dma_ddr_size_7168KB, state, 7168 * 1024)
DMA_1KB_INC_DDR(test_dma_ddr_size_8192KB, state, 8192 * 1024)
DMA_1KB_INC_DDR(test_dma_ddr_size_9216KB, state, 9216 * 1024)
DMA_1KB_INC_DDR(test_dma_ddr_size_10240KB, state, 10240 * 1024)
DMA_1KB_INC_DDR(test_dma_ddr_size_11264KB, state, 11264 * 1024)
DMA_1KB_INC_DDR(test_dma_ddr_size_12288KB, state, 12288 * 1024)
DMA_1KB_INC_DDR(test_dma_ddr_size_13312KB, state, 13312 * 1024)
DMA_1KB_INC_DDR(test_dma_ddr_size_14336KB, state, 14336 * 1024)
DMA_1KB_INC_DDR(test_dma_ddr_size_15360KB, state, 15360 * 1024)

const struct CMUnitTest dma_1MB_inc_tests[] = {
	cmocka_unit_test(test_dma_sram_size_2048KB),
	cmocka_unit_test(test_dma_sram_size_3072KB),
	cmocka_unit_test(test_dma_sram_size_4096KB),
	cmocka_unit_test(test_dma_sram_size_5120KB),
	cmocka_unit_test(test_dma_sram_size_6144KB),
	cmocka_unit_test(test_dma_sram_size_7168KB),
	cmocka_unit_test(test_dma_sram_size_8192KB),
	cmocka_unit_test(test_dma_sram_size_9216KB),
	cmocka_unit_test(test_dma_sram_size_10240KB),
	cmocka_unit_test(test_dma_sram_size_11264KB),
	cmocka_unit_test(test_dma_sram_size_12288KB),
	cmocka_unit_test(test_dma_sram_size_13312KB),
	cmocka_unit_test(test_dma_sram_size_14336KB),
	cmocka_unit_test(test_dma_sram_size_15360KB),

	cmocka_unit_test(test_dma_ddr_size_2048KB),
	cmocka_unit_test(test_dma_ddr_size_3072KB),
	cmocka_unit_test(test_dma_ddr_size_4096KB),
	cmocka_unit_test(test_dma_ddr_size_5120KB),
	cmocka_unit_test(test_dma_ddr_size_6144KB),
	cmocka_unit_test(test_dma_ddr_size_7168KB),
	cmocka_unit_test(test_dma_ddr_size_8192KB),
	cmocka_unit_test(test_dma_ddr_size_9216KB),
	cmocka_unit_test(test_dma_ddr_size_10240KB),
	cmocka_unit_test(test_dma_ddr_size_11264KB),
	cmocka_unit_test(test_dma_ddr_size_12288KB),
	cmocka_unit_test(test_dma_ddr_size_13312KB),
	cmocka_unit_test(test_dma_ddr_size_14336KB),
	cmocka_unit_test(test_dma_ddr_size_15360KB),
};

int main(void)
{
	char *test_names_to_run;
	int rc;

	test_names_to_run = getenv("HLTHUNK_TESTS_NAMES");
	if (test_names_to_run)
		cmocka_set_test_filter(test_names_to_run);

	rc = cmocka_run_group_tests(dma_1MB_inc_tests, hltests_setup,
					hltests_teardown);

	return rc;
}
