// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
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

static void *dma_thread_start(void *args)
{
	struct dma_thread_params *params = (struct dma_thread_params *) args;
	struct hltests_cs_chunk execute_arr[2];
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t page_size = sysconf(_SC_PAGESIZE), cb_size[2] = {0};
	uint64_t seq;
	void *cb[2];
	int rc, i, fd = params->fd;

	assert_in_range(page_size, PAGE_SIZE_4KB, PAGE_SIZE_64KB);

	for (i = 0 ; i < 2 ; i++) {
		cb[i] = hltests_create_cb(fd, page_size, EXTERNAL, 0);
		if (!cb[i])
			return NULL;
	}

	/* fence on SOB0, clear it, do DMA down and write to SOB8 */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_down_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = 0;
	mon_and_fence_info.mon_id = 0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.target_val = 1;
	mon_and_fence_info.dec_val = 1;
	cb_size[0] = hltests_add_monitor_and_fence(fd, cb[0], cb_size[0],
							&mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = 0;
	pkt_info.write_to_sob.value = 0;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_size[0] = hltests_add_write_to_sob_pkt(fd, cb[0],
						cb_size[0], &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = params->host_src_device_va;
	pkt_info.dma.dst_addr = params->device_addr;
	pkt_info.dma.size = params->size;
	pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_DRAM;
	cb_size[0] = hltests_add_dma_pkt(fd, cb[0], cb_size[0], &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = 8;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_size[0] = hltests_add_write_to_sob_pkt(fd, cb[0],
					cb_size[0], &pkt_info);

	/* fence on SOB8, clear it, do DMA up and write to SOB0 */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = 8;
	mon_and_fence_info.mon_id = 1;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.target_val = 1;
	mon_and_fence_info.dec_val = 1;
	cb_size[1] = hltests_add_monitor_and_fence(fd, cb[1], cb_size[1],
							&mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = 8;
	pkt_info.write_to_sob.value = 0;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_size[1] = hltests_add_write_to_sob_pkt(fd, cb[1],
						cb_size[1], &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = params->device_addr;
	pkt_info.dma.dst_addr = params->host_dst_device_va;
	pkt_info.dma.size = params->size;
	pkt_info.dma.dma_dir = GOYA_DMA_DRAM_TO_HOST;
	cb_size[1] = hltests_add_dma_pkt(fd, cb[1], cb_size[1], &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = 0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_size[1] = hltests_add_write_to_sob_pkt(fd, cb[1],
					cb_size[1], &pkt_info);

	execute_arr[0].cb_ptr = cb[0];
	execute_arr[0].cb_size = cb_size[0];
	execute_arr[0].queue_index = hltests_get_dma_down_qid(params->fd,
								STREAM0);

	execute_arr[1].cb_ptr = cb[1];
	execute_arr[1].cb_size = cb_size[1];
	execute_arr[1].queue_index = hltests_get_dma_up_qid(params->fd,
								STREAM0);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2,
					FORCE_RESTORE_FALSE, &seq);
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
	struct hltests_pkt_info pkt_info;
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
	dram_addr = hltests_allocate_device_mem(fd, dma_size, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	/* Allocate memory on host and initiate threads parameters */
	for (i = 0 ; i < num_of_threads ; i++) {
		thread_params[i].host_src =
			hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
		assert_non_null(thread_params[i].host_src);
		hltests_fill_rand_values(thread_params[i].host_src, dma_size);
		thread_params[i].host_src_device_va =
			hltests_get_device_va_for_host_ptr(fd,
						thread_params[i].host_src);

		thread_params[i].host_dst =
			hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
		assert_non_null(thread_params[i].host_dst);
		memset(thread_params[i].host_dst, 0, dma_size);
		thread_params[i].host_dst_device_va =
			hltests_get_device_va_for_host_ptr(fd,
						thread_params[i].host_dst);

		thread_params[i].device_addr = (uint64_t) (uintptr_t) dram_addr;
		thread_params[i].size = dma_size;
		thread_params[i].fd = fd;
	}

	/* clear SOB8 and set SOB0 to 1 so the first DMA thread will run */
	cb = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = 0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = 8;
	pkt_info.write_to_sob.value = 0;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

	hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);

	/* Create and execute threads */
	for (i = 0 ; i < num_of_threads ; i++) {
		rc = pthread_create(&thread_id[i], NULL, dma_thread_start,
					&thread_params[i]);
		assert_int_equal(rc, 0);
	}

	/* Wait for the termination of the threads */
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
	cmocka_unit_test_setup(test_dma_8_threads,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_64_threads,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_512_threads,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"dma [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(dma_tests) / sizeof((dma_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE, dma_tests,
			num_tests);

	return hltests_run_group_tests("dma", dma_tests, num_tests,
					hltests_setup, hltests_teardown);
}
