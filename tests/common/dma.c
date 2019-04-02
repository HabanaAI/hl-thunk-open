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
#include "kvec.h"

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

typedef struct {
	void *input;
	void *output;
	uint64_t input_device_va;
	uint64_t output_device_va;
	uint64_t dram_addr;
} dma_chunk;

static void *dma_thread_start(void *args)
{
	struct dma_thread_params *params = (struct dma_thread_params *) args;
	struct hltests_cs_chunk execute_arr[2];
	uint32_t page_size = sysconf(_SC_PAGESIZE), cb_size[2] = {0};
	uint64_t seq;
	void *cb[2];
	int rc, i, fd = params->fd;

	for (i = 0 ; i < 2 ; i++) {
		cb[i] = hltests_create_cb(fd, page_size, true, 0);
		if (!cb[i])
			return NULL;
	}

	/* fence on SOB0, clear it, do DMA down and write to SOB1 */
	cb_size[0] = hltests_add_monitor_and_fence(fd, cb[0], cb_size[0], 0,
					hltests_get_dma_down_qid(fd, 0, 0),
					false, 0, 0, 0);

	cb_size[0] = hltests_add_set_sob_pkt(fd, cb[0], cb_size[0], true,
					true, 0, 0, 0);

	cb_size[0] = hltests_add_dma_pkt(fd, cb[0], cb_size[0], true, true,
					params->host_src_device_va,
					params->device_addr, params->size,
					GOYA_DMA_HOST_TO_DRAM);

	cb_size[0] = hltests_add_write_to_sob_pkt(fd, cb[0], cb_size[0], true,
					true, 1, 1, 1);

	/* fence on SOB1, clear it, do DMA up and write to SOB0 */
	cb_size[1] = hltests_add_monitor_and_fence(fd, cb[1], cb_size[1], 0,
					hltests_get_dma_up_qid(fd, 0, 0),
					false, 1, 1, 0);

	cb_size[1] = hltests_add_set_sob_pkt(fd, cb[1], cb_size[1], true,
					true, 0, 1, 0);

	cb_size[1] = hltests_add_dma_pkt(fd, cb[1], cb_size[1], true, true,
					params->device_addr,
					params->host_dst_device_va,
					params->size, GOYA_DMA_DRAM_TO_HOST);

	cb_size[1] = hltests_add_write_to_sob_pkt(fd, cb[1], cb_size[1], true,
					true, 0, 1, 1);

	execute_arr[0].cb_ptr = cb[0];
	execute_arr[0].cb_size = cb_size[0];
	execute_arr[0].queue_index = hltests_get_dma_down_qid(params->fd, 0, 0);

	execute_arr[1].cb_ptr = cb[1];
	execute_arr[1].cb_size = cb_size[1];
	execute_arr[1].queue_index = hltests_get_dma_up_qid(params->fd, 0, 0);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2, false, &seq);
	if (rc)
		return NULL;

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_destroy_cb(fd, cb[i]);
		if (rc)
			return NULL;
	}

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
	void *dram_addr, *retval, *cb;
	uint32_t i, dma_size = 28, cb_size = 0;
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

	/* clear SOB1 and set SOB0 to 1 so the first DMA thread will run */
	cb = hltests_create_cb(fd, getpagesize(), true, 0);
	assert_non_null(cb);

	cb_size = hltests_add_set_sob_pkt(fd, cb, cb_size, true, true, 0, 0, 1);

	cb_size = hltests_add_set_sob_pkt(fd, cb, cb_size, true, true, 0, 1, 0);

	hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, 0, 0), true);

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

void test_dma_entire_dram_random(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[1];
	struct hlthunk_hw_ip_info hw_ip;
	void *buf[2], *cb;
	uint64_t dram_addr, dram_addr_end, device_va[2], seq;
	uint32_t dma_size = 1 << 14; /* 16KB */
	uint32_t zone_size = 1 << 23; /* 8MB */
	uint32_t dram_size, offset, cb_size = 0, vec_len, packets_size;
	kvec_t(dma_chunk) array;
	dma_chunk chunk;
	int i, rc, fd = tests_state->fd;

	/*
	 * This test uses specific DRAM addresses, hence needs MMU to be
	 * disabled
	 */
	if (tests_state->mmu)
		return;

	kv_init(array);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	assert_true(hw_ip.dram_enabled);

	/* check alignment to 8B */
	assert_int_equal(dma_size & 0x7, 0);
	assert_int_equal(zone_size & 0x7, 0);

	assert_true(2 * dma_size <= zone_size);

	/* align to zone_size */
	dram_size = hw_ip.dram_size & ~(zone_size - 1);
	assert_true(zone_size < dram_size);

	dram_addr = hw_ip.dram_base_address;
	dram_addr_end = hw_ip.dram_base_address + dram_size - 1;

	while (dram_addr < (dram_addr_end - dma_size))
	{
		buf[0] = hltests_allocate_host_mem(fd, dma_size, false);
		assert_non_null(buf[0]);
		hltests_fill_rand_values(buf[0], dma_size);
		device_va[0] = hltests_get_device_va_for_host_ptr(fd, buf[0]);

		buf[1] = hltests_allocate_host_mem(fd, dma_size, false);
		assert_non_null(buf[1]);
		memset(buf[1], 0, dma_size);
		device_va[1] = hltests_get_device_va_for_host_ptr(fd, buf[1]);

		hltests_fill_rand_values(&offset, sizeof(offset));

		/* need an offset inside a zone and aligned to 8B */
		offset = (offset & (zone_size - 1)) & ~0x7;
	        if (offset > (zone_size - dma_size - 1))
	            offset -= dma_size;

	        chunk.input = buf[0];
	        chunk.output = buf[1];
	        chunk.input_device_va = device_va[0];
	        chunk.output_device_va = device_va[1];
	        chunk.dram_addr = dram_addr + offset;

		kv_push(dma_chunk, array, chunk);

		dram_addr += zone_size;
	}

	vec_len = kv_size(array);
	packets_size = 24 * vec_len;

	/* DMA down */
	cb = hltests_create_cb(fd, packets_size, true, 0);
	assert_non_null(cb);

	for (i = 0 ; i < vec_len ; i++) {
		chunk = kv_A(array, i);
		cb_size = hltests_add_dma_pkt(fd, cb, cb_size, false, true,
					chunk.input_device_va,
					(uint64_t) (uintptr_t) chunk.dram_addr,
					dma_size, GOYA_DMA_HOST_TO_DRAM);
	}

	execute_arr[0].cb_ptr = cb;
	execute_arr[0].cb_size = cb_size;
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, 0, 0);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, true, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	cb_size = 0;

	/* DMA up */
	cb = hltests_create_cb(fd, packets_size, true, 0);
	assert_non_null(cb);

	for (i = 0 ; i < vec_len ; i++) {
		chunk = kv_A(array, i);
		cb_size = hltests_add_dma_pkt(fd, cb, cb_size, false, true,
					(uint64_t) (uintptr_t) chunk.dram_addr,
					chunk.output_device_va,
					dma_size, GOYA_DMA_DRAM_TO_HOST);
	}

	execute_arr[0].cb_ptr = cb;
	execute_arr[0].cb_size = cb_size;
	execute_arr[0].queue_index = hltests_get_dma_up_qid(fd, 0, 0);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, true, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	cb_size = 0;

	/* compare host memories */
	for (i = 0 ; i < vec_len ; i++) {
		chunk = kv_A(array, i);
		rc = hltests_mem_compare(chunk.input, chunk.output, dma_size);
		assert_int_equal(rc, 0);
	}

	/* cleanup */
	for (i = 0 ; i < vec_len ; i++) {
		chunk = kv_A(array, i);
		rc = hltests_free_host_mem(fd, chunk.input);
		assert_int_equal(rc, 0);

		rc = hltests_free_host_mem(fd, chunk.output);
		assert_int_equal(rc, 0);
	}

	kv_destroy(array);
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
	cmocka_unit_test_setup(test_dma_entire_dram_random,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_8_threads,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_64_threads,
			hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_512_threads,
			hl_tests_ensure_device_operational),
};

static const char *const usage[] = {
	"dma [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID, dma_tests,
			sizeof(dma_tests) / sizeof((dma_tests)[0]));

	return cmocka_run_group_tests(dma_tests, hltests_setup,
					hltests_teardown);
}
