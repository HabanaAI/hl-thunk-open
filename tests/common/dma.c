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

void test_dma_ddr(void **state)
{
	hlthunk_tests_dma_test(state, true, 0x1000, false);
}

void test_dma_ddr_huge_pages(void **state)
{
	hlthunk_tests_dma_test(state, true, 0x1000, true);
}

void test_dma_sram(void **state)
{
	hlthunk_tests_dma_test(state, false, 0x1000, false);
}

void test_dma_sram_huge_pages(void **state)
{
	hlthunk_tests_dma_test(state, false, 0x1000, true);
}

const struct CMUnitTest dma_tests[] = {
	cmocka_unit_test(test_dma_ddr),
	cmocka_unit_test(test_dma_ddr_huge_pages),
	cmocka_unit_test(test_dma_sram),
	cmocka_unit_test(test_dma_sram_huge_pages),
};

int main(void)
{
	char *test_names_to_run;
	int rc;

	test_names_to_run = getenv("HLTHUNK_TESTS_NAMES");
	if (test_names_to_run)
		cmocka_set_test_filter(test_names_to_run);

	rc = cmocka_run_group_tests(dma_tests, hlthunk_tests_setup,
					hlthunk_tests_teardown);

	return rc;
}
