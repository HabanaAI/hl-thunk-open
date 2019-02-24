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

static int _test_dma(void **state, bool is_ddr, uint64_t size, bool is_huge)
{
	struct hlthunk_tests_state *tests_state =
			(struct hlthunk_tests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	void *device_addr, *src_ptr, *dst_ptr;
	uint64_t host_src_addr, host_dst_addr;
	uint32_t dma_dir_down, dma_dir_up;
	int rc, fd = tests_state->fd;

	/* Sanity and memory allocation */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_ddr) {
		assert_int_equal(hw_ip.dram_enabled, 1);
		assert_in_range(size, 1, hw_ip.dram_size);

		device_addr = hlthunk_tests_allocate_device_mem(tests_state->fd,
								size);
		assert_non_null(device_addr);

		dma_dir_down = GOYA_DMA_HOST_TO_DRAM;
		dma_dir_up = GOYA_DMA_DRAM_TO_HOST;
	} else {
		assert_in_range(size, 1, hw_ip.sram_size);
		device_addr = (void *) (uintptr_t) hw_ip.sram_base_address;

		dma_dir_down = GOYA_DMA_HOST_TO_SRAM;
		dma_dir_up = GOYA_DMA_SRAM_TO_HOST;
	}

	src_ptr = hlthunk_tests_allocate_host_mem(fd, size, is_huge);
	assert_non_null(src_ptr);
	hlthunk_tests_fill_rand_values(src_ptr, size);
	host_src_addr = hlthunk_tests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hlthunk_tests_allocate_host_mem(fd, size, is_huge);
	assert_non_null(dst_ptr);
	hlthunk_tests_fill_rand_values(dst_ptr, size);
	host_dst_addr = hlthunk_tests_get_device_va_for_host_ptr(fd, dst_ptr);

	/* DMA: host->device */
	rc = hlthunk_tests_dma_transfer(fd, hlthunk_tests_get_dma_down_qid(fd),
					0, 1, host_src_addr,
					(uint64_t) (uintptr_t) device_addr,
					size, dma_dir_down,
					WAIT_FOR_CS_DEFAULT_TIMEOUT);
	assert_int_equal(rc, 0);

	/* DMA: device->host */
	rc = hlthunk_tests_dma_transfer(fd, hlthunk_tests_get_dma_up_qid(fd),
					0, 1,
					(uint64_t) (uintptr_t) device_addr,
					host_dst_addr, size, dma_dir_up,
					WAIT_FOR_CS_DEFAULT_TIMEOUT);
	assert_int_equal(rc, 0);

	/* Compare host memories */
	rc = hlthunk_tests_mem_compare(src_ptr, dst_ptr, size);
	assert_int_equal(rc, 0);

	/* Cleanup */
	rc = hlthunk_tests_free_host_mem(fd, dst_ptr);
	assert_int_equal(rc, 0);
	rc = hlthunk_tests_free_host_mem(fd, src_ptr);
	assert_int_equal(rc, 0);

	if (is_ddr) {
		rc = hlthunk_tests_free_device_mem(fd, device_addr);
		assert_int_equal(rc, 0);
	}

	return 0;
}

void test_dma_ddr(void **state)
{
	_test_dma(state, true, 0x1000, false);
}

void test_dma_ddr_huge_pages(void **state)
{
	_test_dma(state, true, 0x1000, true);
}

void test_dma_sram(void **state)
{
	_test_dma(state, false, 0x1000, false);
}

void test_dma_sram_huge_pages(void **state)
{
	_test_dma(state, false, 0x1000, true);
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
