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
#include <pthread.h>

struct dma_thread_params {
	void *host_src;
	void *host_dst;
	uint64_t host_src_device_va;
	uint64_t host_dst_device_va;
	uint64_t device_addr;
	uint32_t size;
	int fd;
};

static void *dma_thread_start(void *args)
{
	struct dma_thread_params *params = (struct dma_thread_params *) args;
	uint32_t page_size = sysconf(_SC_PAGESIZE), offset = 0;
	void *ptr;
	int rc;

	ptr = hltests_create_cb(params->fd, page_size, true, 0);
	if (!ptr)
		return NULL;

	offset = hltests_add_dma_pkt(params->fd, ptr, offset, true, true,
					params->host_src_device_va,
					params->device_addr, params->size,
					GOYA_DMA_HOST_TO_DRAM);
	offset = hltests_add_dma_pkt(params->fd, ptr, offset, true, true,
					params->device_addr,
					params->host_dst_device_va,
					params->size, GOYA_DMA_DRAM_TO_HOST);

	/* DMA DOWN queue ID is used here also for UP */
	hltests_submit_and_wait_cs(params->fd, ptr, offset,
			hltests_get_dma_down_qid(params->fd, 0, 0), true);

	/* Compare host memories */
	rc = hltests_mem_compare(params->host_src, params->host_dst,
					params->size);
	if (rc)
		return NULL;

	return args;
}

static void test_dma_threads(void **state, uint32_t num_of_threads)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct dma_thread_params *thread_params;
	pthread_t *thread_id;
	void *dram_addr, *retval;
	uint32_t i, dma_size = 28;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	assert_int_equal(hw_ip.dram_enabled, 1);
	assert_in_range(num_of_threads * dma_size, 1, hw_ip.dram_size);

	/* Allocate arrays for threads management */
	thread_id = (pthread_t *) hlthunk_malloc(num_of_threads *
							sizeof(*thread_id));
	assert_non_null(thread_id);

	thread_params = (struct dma_thread_params *)
			hlthunk_malloc(num_of_threads * sizeof(*thread_params));
	assert_non_null(thread_params);

	/* Allocate memory on DRAM */
	dram_addr = hltests_allocate_device_mem(fd, dma_size);
	assert_non_null(dram_addr);

	/* Allocate memory on host and initiate threads parameters */
	for (i = 0 ; i < num_of_threads ; i++) {
		thread_params[i].host_src =
			hltests_allocate_host_mem(fd, dma_size, false);
		assert_non_null(thread_params[i].host_src);
		hltests_fill_rand_values(thread_params[i].host_src, dma_size);
		thread_params[i].host_src_device_va =
			hltests_get_device_va_for_host_ptr(fd,
						thread_params[i].host_src);

		thread_params[i].host_dst =
			hltests_allocate_host_mem(fd, dma_size, false);
		assert_non_null(thread_params[i].host_dst);
		memset(thread_params[i].host_dst, 0, dma_size);
		thread_params[i].host_dst_device_va =
			hltests_get_device_va_for_host_ptr(fd,
						thread_params[i].host_dst);

		thread_params[i].device_addr = (uint64_t) (uintptr_t) dram_addr;
		thread_params[i].size = dma_size;
		thread_params[i].fd = fd;
	}

	/* Create and execute threads */
	for (i = 0 ; i < num_of_threads ; i++) {
		rc = pthread_create(&thread_id[i], NULL, dma_thread_start,
					&thread_params[i]);
		assert_int_equal(rc, 0);
	}

	/* Waits for the termination of the threads */
	for (i = 0 ; i < num_of_threads ; i++) {
		rc = pthread_join(thread_id[i], &retval);
		assert_int_equal(rc, 0);
		assert_non_null(retval);
	}

	/* Cleanup */
	for (i = 0 ; i < num_of_threads ; i++) {
		rc = hltests_free_host_mem(fd, thread_params[i].host_dst);
		assert_int_equal(rc, 0);
		rc = hltests_free_host_mem(fd, thread_params[i].host_src);
		assert_int_equal(rc, 0);
	}

	rc = hltests_free_device_mem(fd, dram_addr);
	assert_int_equal(rc, 0);

	hlthunk_free(thread_params);
	hlthunk_free(thread_id);
}

void test_dma_entire_sram_random(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	int rc;

	rc = hlthunk_get_hw_ip_info(tests_state->fd, &hw_ip);
	assert_int_equal(rc, 0);

	hltests_dma_test(state, false, hw_ip.sram_size);
}

void test_dma_8_threads(void **state)
{
	test_dma_threads(state, 8);
}

void test_dma_64_threads(void **state)
{
	test_dma_threads(state, 64);
}

void test_dma_512_threads(void **state)
{
	test_dma_threads(state, 512);
}

const struct CMUnitTest dma_tests[] = {
	cmocka_unit_test_setup(test_dma_entire_sram_random,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_8_threads,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_64_threads,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_512_threads,
			hl_tests_ensure_device_operational),
};

int main(void)
{
	char *test_names_to_run;
	int rc;

	test_names_to_run = getenv("HLTHUNK_TESTS_NAMES");
	if (test_names_to_run)
		cmocka_set_test_filter(test_names_to_run);

	rc = cmocka_run_group_tests(dma_tests, hltests_setup, hltests_teardown);

	return rc;
}
