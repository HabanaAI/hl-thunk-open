// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "common/hlthunk_tests.h"
#include "gaudi/gaudi.h"

#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>

#define NUM_OF_INT_Q 6

struct dma_thread_params {
	double test_duration;
	void *input;
	void *output;
	void *restore_arr;
	void *execute_arr;
	int execute_arr_len;
	int size;
	int fd;
};

static void *dma_thread_func_int(void *args)
{
	struct dma_thread_params *params = (struct dma_thread_params *) args;
	uint64_t seq;
	struct timespec begin, curr;
	double time_diff = 0.0;
	int rc, fd = params->fd;

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	while (time_diff < params->test_duration) {
		rc = hltests_submit_cs(fd, params->restore_arr, 1,
					params->execute_arr,
					params->execute_arr_len,
					CS_FLAGS_FORCE_RESTORE, &seq);
		if (rc)
			return NULL;

		if (seq % 16)
			continue;

		rc = hltests_wait_for_cs_until_not_busy(fd, seq);
		if (rc)
			return NULL;

		clock_gettime(CLOCK_MONOTONIC_RAW, &curr);
		time_diff = (curr.tv_nsec - begin.tv_nsec) / 1000000000.0 +
						(curr.tv_sec  - begin.tv_sec);
	}

	return args;
}

static void *dma_thread_func_ext(void *args)
{
	struct dma_thread_params *params = (struct dma_thread_params *) args;
	uint64_t seq;
	struct timespec begin, end;
	double time_diff = 0.0;
	int rc, fd = params->fd;

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	while (time_diff < params->test_duration) {
		memset(params->output, 0, params->size);

		rc = hltests_submit_cs(fd, params->restore_arr, 1,
					params->execute_arr,
					params->execute_arr_len,
					CS_FLAGS_FORCE_RESTORE, &seq);
		if (rc)
			return NULL;

		rc = hltests_wait_for_cs_until_not_busy(fd, seq);
		if (rc)
			return NULL;

		rc = hltests_mem_compare(params->input, params->output,
						params->size);
		if (rc)
			return NULL;

		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		time_diff = (end.tv_nsec - begin.tv_nsec) / 1000000000.0 +
						(end.tv_sec  - begin.tv_sec);
	}

	return args;
}

void test_dma_all2all(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_cs_chunk int_restore_arr[1], ext_restore_arr[1],
		int_execute_arr[NUM_OF_INT_Q + 1], ext_execute_arr[2];
	struct dma_thread_params *thread_params;
	pthread_t *thread_id;
	char *run_disabled_tests;
	void *int_restore_cb, *nop_cb, *ext_restore_cb, *ext_dma_cb[2],
		*common_cb_buf[NUM_OF_INT_Q], *cp_dma_cb[NUM_OF_INT_Q],
		*ext_buf[2], *retval, *dma5_cb = NULL;
	uint64_t common_cb_device_va[NUM_OF_INT_Q], int_dram_addr[NUM_OF_INT_Q],
		cp_dma_cb_device_va[NUM_OF_INT_Q], ext_buf_va[NUM_OF_INT_Q],
		sram_base, sram_addr, ext_dram_addr, src_addr, dst_addr,
		cp_dma_sram_addr;
	double test_duration = 60.0; /* seconds */
	uint32_t cp_dma_cb_size[NUM_OF_INT_Q] = {0},
		common_cb_buf_size[NUM_OF_INT_Q] = {0},
		ext_dma_cb_size[2] = {0}, ext_buf_size[2] = {0},
		nop_cb_size = 0, restore_cb_size = 0, ext_restore_cb_size = 0,
		int_dma_size = 1 << 21, ext_dma_size = 1 << 20, page_size,
		queue, dma5_cb_size;
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	enum hltests_goya_dma_direction dma_dir;
	int rc, fd = tests_state->fd, i;

	memset(&pkt_info, 0, sizeof(pkt_info));

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("Test is skipped because it is disabled by default\n");
		skip();
	}

	/* This test can't run if mmu is disabled */
	if (!tests_state->mmu) {
		printf("Test is skipped. MMU must be enabled\n");
		skip();
	}

	/* Allocate arrays for threads management */
	thread_id = (pthread_t *) hlthunk_malloc(2 * sizeof(*thread_id));
	assert_non_null(thread_id);

	thread_params = (struct dma_thread_params *)
				hlthunk_malloc(2 * sizeof(*thread_params));
	assert_non_null(thread_params);

	/* SRAM MAP (base + ):
	 * - 0x0000 - CB of common CP [DMA2]
	 * - 0x1000 - CB of common CP [DMA3]
	 * - 0x2000 - CB of common CP [DMA4]
	 * - 0x3000 - (not in use)
	 * - 0x4000 - CB of common CP [DMA6]
	 * - 0x5000 - CB of common CP [DMA7]
	 * - 0x6000 - CB of upper CP [DMA2]
	 * - 0x6020 - CB of upper CP [DMA3]
	 * - 0x6040 - CB of upper CP [DMA4]
	 * - 0x6060 - (not in use)
	 * - 0x6080 - CB of upper CP [DMA6]
	 * - 0x60A0 - CB of upper CP [DMA7]
	 * - 0x7000 - Data
	 *
	 * Test description:
	 * - Two threads running concurrently and independently for 60 seconds.
	 * Internal thread:
	 * - On each of the available internal queues a DMA will take place.
	 * - Even queues transfer data from DRAM to SRAM, odd queues do the
	 *   opposite direction.
	 * - All of the above DMA transfers happen concurrently.
	 * - Each queue signals to SOB when upon completion.
	 * - An external CB with NOP packet waits for all queues to finish in
	 *   order to signal the user that the CS has finished.
	 * External thread:
	 * - Simple DMA from host to DRAM and reverse + compare in order to
	 *   create noise in the system.
	 */

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	assert_true(hw_ip.dram_enabled);

	assert_true(ext_dma_size < hw_ip.dram_size);
	assert_true(int_dma_size * NUM_OF_INT_Q < hw_ip.sram_size);

	sram_base = hw_ip.sram_base_address;

	page_size = sysconf(_SC_PAGESIZE);
	assert_in_range(page_size, PAGE_SIZE_4KB, PAGE_SIZE_64KB);

	int_restore_cb = hltests_create_cb(fd, page_size, EXTERNAL, 0);
	assert_non_null(int_restore_cb);

	nop_cb = hltests_create_cb(fd, page_size, EXTERNAL, 0);
	assert_non_null(nop_cb);

	queue = GAUDI_QUEUE_ID_DMA_2_0;

	for (i = 0 ; i < NUM_OF_INT_Q ; i++, queue += 4) {
		int_dram_addr[i] = (uint64_t) hltests_allocate_device_mem(fd,
						int_dma_size, NOT_CONTIGUOUS);
		assert_int_not_equal(int_dram_addr[i], 0);

		sram_addr = sram_base + (NUM_OF_INT_Q + 1) * 0x1000 +
							i * int_dma_size;

		if (i & 1) {
			src_addr = sram_addr;
			dst_addr = int_dram_addr[i];
			dma_dir = GOYA_DMA_SRAM_TO_DRAM;
		} else {
			src_addr = int_dram_addr[i];
			dst_addr = sram_addr;
			dma_dir = GOYA_DMA_DRAM_TO_SRAM;
		}

		common_cb_buf[i] = hltests_allocate_host_mem(fd,
						int_dma_size, NOT_HUGE);
		assert_non_null(common_cb_buf[i]);
		memset(common_cb_buf[i], 0, int_dma_size);
		common_cb_buf_size[i] = 0;
		common_cb_device_va[i] =
			hltests_get_device_va_for_host_ptr(fd,
						common_cb_buf[i]);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = src_addr;
		pkt_info.dma.dst_addr = dst_addr;
		pkt_info.dma.size = int_dma_size;
		pkt_info.dma.dma_dir = dma_dir;
		common_cb_buf_size[i] = hltests_add_dma_pkt(fd,
						common_cb_buf[i],
						common_cb_buf_size[i],
						&pkt_info);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.sob_id = i * 8;
		pkt_info.write_to_sob.value = 0;
		pkt_info.write_to_sob.mode = SOB_SET;
		common_cb_buf_size[i] = hltests_add_write_to_sob_pkt(fd,
						common_cb_buf[i],
						common_cb_buf_size[i],
						&pkt_info);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.sob_id = i * 8;
		pkt_info.write_to_sob.value = 1;
		pkt_info.write_to_sob.mode = SOB_ADD;
		common_cb_buf_size[i] = hltests_add_write_to_sob_pkt(fd,
						common_cb_buf[i],
						common_cb_buf_size[i],
						&pkt_info);

		cp_dma_sram_addr = sram_base + (NUM_OF_INT_Q * 0x1000) +
					(i * 0x20);

		cp_dma_cb[i] = hltests_create_cb(fd, page_size,
					INTERNAL, cp_dma_sram_addr);
		assert_non_null(cp_dma_cb[i]);
		cp_dma_cb_device_va[i] =
			hltests_get_device_va_for_host_ptr(fd,
							cp_dma_cb[i]);

		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.cp_dma.src_addr = sram_base + i * 0x1000;
		pkt_info.cp_dma.size = common_cb_buf_size[i];
		cp_dma_cb_size[i] =
				hltests_add_cp_dma_pkt(fd, cp_dma_cb[i],
					cp_dma_cb_size[i], &pkt_info);

		int_execute_arr[i].cb_ptr = cp_dma_cb[i];
		int_execute_arr[i].cb_size = cp_dma_cb_size[i];
		int_execute_arr[i].queue_index = queue;

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = cp_dma_cb_device_va[i];
		pkt_info.dma.dst_addr = cp_dma_sram_addr;
		pkt_info.dma.size = cp_dma_cb_size[i];
		pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_SRAM;
		restore_cb_size =
				hltests_add_dma_pkt(fd, int_restore_cb,
							restore_cb_size,
							&pkt_info);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = common_cb_device_va[i];
		pkt_info.dma.dst_addr = sram_base + i * 0x1000;
		pkt_info.dma.size = common_cb_buf_size[i];
		pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_SRAM;
		restore_cb_size =
				hltests_add_dma_pkt(fd, int_restore_cb,
							restore_cb_size,
							&pkt_info);

		memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
		mon_and_fence_info.queue_id =
					hltests_get_dma_down_qid(fd, STREAM0);
		mon_and_fence_info.cmdq_fence = false;
		mon_and_fence_info.sob_id = i * 8;
		mon_and_fence_info.mon_id = i;
		mon_and_fence_info.mon_address = 0;
		mon_and_fence_info.sob_val = 1;
		mon_and_fence_info.dec_fence = true;
		mon_and_fence_info.mon_payload = 1;
		nop_cb_size = hltests_add_monitor_and_fence(fd, nop_cb,
					nop_cb_size, &mon_and_fence_info);

		nop_cb_size = hltests_add_nop_pkt(fd, nop_cb, nop_cb_size,
							EB_TRUE, MB_TRUE);
	}

	int_restore_arr[0].cb_ptr = int_restore_cb;
	int_restore_arr[0].cb_size = restore_cb_size;
	int_restore_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	int_execute_arr[NUM_OF_INT_Q].cb_ptr = nop_cb;
	int_execute_arr[NUM_OF_INT_Q].cb_size = nop_cb_size;
	int_execute_arr[NUM_OF_INT_Q].queue_index =
					hltests_get_dma_down_qid(fd, STREAM0);

	thread_params[0].restore_arr = int_restore_arr;
	thread_params[0].execute_arr = int_execute_arr;
	thread_params[0].execute_arr_len = NUM_OF_INT_Q + 1;
	thread_params[0].fd = fd;
	thread_params[0].test_duration = test_duration;

	ext_restore_cb = hltests_create_cb(fd, page_size, EXTERNAL, 0);
	assert_non_null(ext_restore_cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = NUM_OF_INT_Q * 8;
	pkt_info.write_to_sob.value = 0;
	pkt_info.write_to_sob.mode = SOB_SET;
	ext_restore_cb_size = hltests_add_write_to_sob_pkt(fd, ext_restore_cb,
							ext_restore_cb_size,
							&pkt_info);

	for (i = 0 ; i < 2 ; i++) {
		ext_dma_cb[i] = hltests_create_cb(fd, page_size, EXTERNAL, 0);
		assert_non_null(ext_dma_cb[i]);
	}

	for (i = 0 ; i < 2 ; i++) {
		ext_buf[i] = hltests_allocate_host_mem(fd,
						ext_dma_size, NOT_HUGE);
		assert_non_null(ext_buf[i]);
		ext_buf_size[i] = 0;
		ext_buf_va[i] = hltests_get_device_va_for_host_ptr(fd,
								ext_buf[i]);
	}

	hltests_fill_rand_values(ext_buf[0], ext_dma_size);
	memset(ext_buf[1], 0, ext_dma_size);

	ext_dram_addr = (uint64_t) hltests_allocate_device_mem(fd,
						ext_dma_size, NOT_CONTIGUOUS);
	assert_int_not_equal(ext_dram_addr, 0);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = ext_buf_va[0];
	pkt_info.dma.dst_addr = ext_dram_addr;
	pkt_info.dma.size = ext_dma_size;
	pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_DRAM;
	ext_dma_cb_size[0] = hltests_add_dma_pkt(fd, ext_dma_cb[0],
						ext_dma_cb_size[0], &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = NUM_OF_INT_Q * 8;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	ext_dma_cb_size[0] = hltests_add_write_to_sob_pkt(fd, ext_dma_cb[0],
						ext_dma_cb_size[0], &pkt_info);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = NUM_OF_INT_Q * 8;
	mon_and_fence_info.mon_id = NUM_OF_INT_Q;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	ext_dma_cb_size[1] = hltests_add_monitor_and_fence(fd, ext_dma_cb[1],
				ext_dma_cb_size[1], &mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = ext_dram_addr;
	pkt_info.dma.dst_addr = ext_buf_va[1];
	pkt_info.dma.size = ext_dma_size;
	pkt_info.dma.dma_dir = GOYA_DMA_DRAM_TO_HOST;
	ext_dma_cb_size[1] = hltests_add_dma_pkt(fd, ext_dma_cb[1],
						ext_dma_cb_size[1], &pkt_info);

	ext_restore_arr[0].cb_ptr = ext_restore_cb;
	ext_restore_arr[0].cb_size = ext_restore_cb_size;
	ext_restore_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	ext_execute_arr[0].cb_ptr = ext_dma_cb[0];
	ext_execute_arr[0].cb_size = ext_dma_cb_size[0];
	ext_execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	ext_execute_arr[1].cb_ptr = ext_dma_cb[1];
	ext_execute_arr[1].cb_size = ext_dma_cb_size[1];
	ext_execute_arr[1].queue_index = hltests_get_dma_up_qid(fd, STREAM0);

	thread_params[1].restore_arr = ext_restore_arr;
	thread_params[1].execute_arr = ext_execute_arr;
	thread_params[1].execute_arr_len = 2;
	thread_params[1].input = ext_buf[0];
	thread_params[1].output = ext_buf[1];
	thread_params[1].size = ext_dma_size;
	thread_params[1].fd = fd;
	thread_params[1].test_duration = test_duration;

	/* Create and execute threads */
	rc = pthread_create(&thread_id[0], NULL, dma_thread_func_int,
				&thread_params[0]);
	assert_int_equal(rc, 0);

	rc = pthread_create(&thread_id[1], NULL, dma_thread_func_ext,
				&thread_params[1]);
	assert_int_equal(rc, 0);

	/* Waits for the termination of the threads */
	for (i = 0 ; i < 2 ; i++) {
		rc = pthread_join(thread_id[i], &retval);
		assert_int_equal(rc, 0);
		assert_non_null(retval);
	}

	rc = hltests_free_device_mem(fd, (void *) ext_dram_addr);
	assert_int_equal(rc, 0);

	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_free_host_mem(fd, ext_buf[i]);
		assert_int_equal(rc, 0);
	}

	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_destroy_cb(fd, ext_dma_cb[i]);
		assert_int_equal(rc, 0);
	}

	rc = hltests_destroy_cb(fd, ext_restore_cb);
	assert_int_equal(rc, 0);

	for (i = 0 ; i < NUM_OF_INT_Q ; i++) {
		rc = hltests_free_device_mem(fd, (void *) int_dram_addr[i]);
		assert_int_equal(rc, 0);
		rc = hltests_destroy_cb(fd, cp_dma_cb[i]);
		assert_int_equal(rc, 0);
		rc = hltests_free_host_mem(fd, common_cb_buf[i]);
		assert_int_equal(rc, 0);
	}

	rc = hltests_destroy_cb(fd, nop_cb);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, int_restore_cb);
	assert_int_equal(rc, 0);

	hlthunk_free(thread_params);
	hlthunk_free(thread_id);
}

const struct CMUnitTest gaudi_dma_tests[] = {
	cmocka_unit_test_setup(test_dma_all2all,
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"gaudi_dma [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(gaudi_dma_tests) / sizeof((gaudi_dma_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_GAUDI, gaudi_dma_tests,
			num_tests);

	return hltests_run_group_tests("gaudi_dma", gaudi_dma_tests, num_tests,
					hltests_setup, hltests_teardown);
}
