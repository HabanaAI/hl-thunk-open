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

#define DMA_1KB_INC_SRAM(name, state, size) \
	void name(void **state) \
	{ \
		hlthunk_tests_dma_test(state, false, size, false); \
	}

#define DMA_1KB_INC_SRAM_HUGE_PAGES(name, state, size) \
	void name(void **state) \
	{ \
		hlthunk_tests_dma_test(state, false, size, true); \
	}

#define DMA_1KB_INC_DDR(name, state, size) \
	void name(void **state) \
	{ \
		hlthunk_tests_dma_test(state, true, size, false); \
	}

#define DMA_1KB_INC_DDR_HUGE_PAGES(name, state, size) \
	void name(void **state) \
	{ \
		hlthunk_tests_dma_test(state, true, size, true); \
	}

DMA_1KB_INC_SRAM(test_dma_sram_size_1kb, state, 0x400)
DMA_1KB_INC_SRAM(test_dma_sram_size_2kb, state, 0x800)
DMA_1KB_INC_SRAM(test_dma_sram_size_3kb, state, 0xc00)
DMA_1KB_INC_SRAM(test_dma_sram_size_4kb, state, 0x1000)
DMA_1KB_INC_SRAM(test_dma_sram_size_5kb, state, 0x1400)
DMA_1KB_INC_SRAM(test_dma_sram_size_6kb, state, 0x1800)
DMA_1KB_INC_SRAM(test_dma_sram_size_7kb, state, 0x1c00)
DMA_1KB_INC_SRAM(test_dma_sram_size_8kb, state, 0x2000)
DMA_1KB_INC_SRAM(test_dma_sram_size_9kb, state, 0x2400)
DMA_1KB_INC_SRAM(test_dma_sram_size_10kb, state, 0x2800)
DMA_1KB_INC_SRAM(test_dma_sram_size_11kb, state, 0x2c00)
DMA_1KB_INC_SRAM(test_dma_sram_size_12kb, state, 0x3000)
DMA_1KB_INC_SRAM(test_dma_sram_size_13kb, state, 0x3400)
DMA_1KB_INC_SRAM(test_dma_sram_size_14kb, state, 0x3800)
DMA_1KB_INC_SRAM(test_dma_sram_size_15kb, state, 0x3c00)

DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_1kb_huge_pages, state, 0x400)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_2kb_huge_pages, state, 0x800)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_3kb_huge_pages, state, 0xc00)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_4kb_huge_pages, state, 0x1000)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_5kb_huge_pages, state, 0x1400)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_6kb_huge_pages, state, 0x1800)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_7kb_huge_pages, state, 0x1c00)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_8kb_huge_pages, state, 0x2000)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_9kb_huge_pages, state, 0x2400)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_10kb_huge_pages, state, 0x2800)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_11kb_huge_pages, state, 0x2c00)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_12kb_huge_pages, state, 0x3000)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_13kb_huge_pages, state, 0x3400)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_14kb_huge_pages, state, 0x3800)
DMA_1KB_INC_SRAM_HUGE_PAGES(test_dma_sram_size_15kb_huge_pages, state, 0x3c00)

DMA_1KB_INC_DDR(test_dma_ddr_size_1kb, state, 0x400)
DMA_1KB_INC_DDR(test_dma_ddr_size_2kb, state, 0x800)
DMA_1KB_INC_DDR(test_dma_ddr_size_3kb, state, 0xc00)
DMA_1KB_INC_DDR(test_dma_ddr_size_4kb, state, 0x1000)
DMA_1KB_INC_DDR(test_dma_ddr_size_5kb, state, 0x1400)
DMA_1KB_INC_DDR(test_dma_ddr_size_6kb, state, 0x1800)
DMA_1KB_INC_DDR(test_dma_ddr_size_7kb, state, 0x1c00)
DMA_1KB_INC_DDR(test_dma_ddr_size_8kb, state, 0x2000)
DMA_1KB_INC_DDR(test_dma_ddr_size_9kb, state, 0x2400)
DMA_1KB_INC_DDR(test_dma_ddr_size_10kb, state, 0x2800)
DMA_1KB_INC_DDR(test_dma_ddr_size_11kb, state, 0x2c00)
DMA_1KB_INC_DDR(test_dma_ddr_size_12kb, state, 0x3000)
DMA_1KB_INC_DDR(test_dma_ddr_size_13kb, state, 0x3400)
DMA_1KB_INC_DDR(test_dma_ddr_size_14kb, state, 0x3800)
DMA_1KB_INC_DDR(test_dma_ddr_size_15kb, state, 0x3c00)

DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_1kb_huge_pages, state, 0x400)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_2kb_huge_pages, state, 0x800)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_3kb_huge_pages, state, 0xc00)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_4kb_huge_pages, state, 0x1000)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_5kb_huge_pages, state, 0x1400)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_6kb_huge_pages, state, 0x1800)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_7kb_huge_pages, state, 0x1c00)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_8kb_huge_pages, state, 0x2000)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_9kb_huge_pages, state, 0x2400)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_10kb_huge_pages, state, 0x2800)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_11kb_huge_pages, state, 0x2c00)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_12kb_huge_pages, state, 0x3000)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_13kb_huge_pages, state, 0x3400)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_14kb_huge_pages, state, 0x3800)
DMA_1KB_INC_DDR_HUGE_PAGES(test_dma_ddr_size_15kb_huge_pages, state, 0x3c00)

const struct CMUnitTest dma_1kb_inc_tests[] = {
	cmocka_unit_test(test_dma_sram_size_1kb),
	cmocka_unit_test(test_dma_sram_size_2kb),
	cmocka_unit_test(test_dma_sram_size_3kb),
	cmocka_unit_test(test_dma_sram_size_4kb),
	cmocka_unit_test(test_dma_sram_size_5kb),
	cmocka_unit_test(test_dma_sram_size_6kb),
	cmocka_unit_test(test_dma_sram_size_7kb),
	cmocka_unit_test(test_dma_sram_size_8kb),
	cmocka_unit_test(test_dma_sram_size_9kb),
	cmocka_unit_test(test_dma_sram_size_10kb),
	cmocka_unit_test(test_dma_sram_size_11kb),
	cmocka_unit_test(test_dma_sram_size_12kb),
	cmocka_unit_test(test_dma_sram_size_13kb),
	cmocka_unit_test(test_dma_sram_size_14kb),
	cmocka_unit_test(test_dma_sram_size_15kb),

	cmocka_unit_test(test_dma_sram_size_1kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_2kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_3kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_4kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_5kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_6kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_7kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_8kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_9kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_10kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_11kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_12kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_13kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_14kb_huge_pages),
	cmocka_unit_test(test_dma_sram_size_15kb_huge_pages),

	cmocka_unit_test(test_dma_ddr_size_1kb),
	cmocka_unit_test(test_dma_ddr_size_2kb),
	cmocka_unit_test(test_dma_ddr_size_3kb),
	cmocka_unit_test(test_dma_ddr_size_4kb),
	cmocka_unit_test(test_dma_ddr_size_5kb),
	cmocka_unit_test(test_dma_ddr_size_6kb),
	cmocka_unit_test(test_dma_ddr_size_7kb),
	cmocka_unit_test(test_dma_ddr_size_8kb),
	cmocka_unit_test(test_dma_ddr_size_9kb),
	cmocka_unit_test(test_dma_ddr_size_10kb),
	cmocka_unit_test(test_dma_ddr_size_11kb),
	cmocka_unit_test(test_dma_ddr_size_12kb),
	cmocka_unit_test(test_dma_ddr_size_13kb),
	cmocka_unit_test(test_dma_ddr_size_14kb),
	cmocka_unit_test(test_dma_ddr_size_15kb),

	cmocka_unit_test(test_dma_ddr_size_1kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_2kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_3kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_4kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_5kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_6kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_7kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_8kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_9kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_10kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_11kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_12kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_13kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_14kb_huge_pages),
	cmocka_unit_test(test_dma_ddr_size_15kb_huge_pages),
};

int main(void)
{
	char *test_names_to_run;
	int rc;

	test_names_to_run = getenv("HLTHUNK_TESTS_NAMES");
	if (test_names_to_run)
		cmocka_set_test_filter(test_names_to_run);

	rc = cmocka_run_group_tests(dma_1kb_inc_tests, hlthunk_tests_setup,
					hlthunk_tests_teardown);

	return rc;
}
