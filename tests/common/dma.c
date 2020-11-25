// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

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
	uint32_t cb_size[2] = {0};
	uint64_t seq;
	uint16_t sob0, sob8, mon0, mon1;
	void *cb[2];
	int rc, i, fd = params->fd;

	for (i = 0 ; i < 2 ; i++) {
		cb[i] = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
		if (!cb[i])
			return NULL;
	}

	sob0 = hltests_get_first_avail_sob(fd);
	sob8 = hltests_get_first_avail_sob(fd) + 8;
	mon0 = hltests_get_first_avail_mon(fd);
	mon1 = hltests_get_first_avail_mon(fd) + 1;

	/* fence on SOB0, clear it, do DMA down and write to SOB8 */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_down_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_size[0] = hltests_add_monitor_and_fence(fd, cb[0], cb_size[0],
							&mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob0;
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
	pkt_info.write_to_sob.sob_id = sob8;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_size[0] = hltests_add_write_to_sob_pkt(fd, cb[0],
					cb_size[0], &pkt_info);

	/* fence on SOB8, clear it, do DMA up and write to SOB0 */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob8;
	mon_and_fence_info.mon_id = mon1;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_size[1] = hltests_add_monitor_and_fence(fd, cb[1], cb_size[1],
							&mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob8;
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
	pkt_info.write_to_sob.sob_id = sob0;
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

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2, 0, &seq);
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
	uint16_t sob0, sob8;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

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

	sob0 = hltests_get_first_avail_sob(fd);
	sob8 = hltests_get_first_avail_sob(fd) + 8;

	/* clear SOB8 and set SOB0 to 1 so the first DMA thread will run */
	cb = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob8;
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
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;

	if (hltests_is_pldm(fd))
		skip();

	test_dma_threads(state, 64);
}

void test_dma_512_threads(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;

	/* This test can't run on func-sim due to SW-10059 */
	if ((hltests_is_simulator(fd)) || (hltests_is_pldm(fd))) {
		printf("Test is disabled on func-sim or PLDM\n");
		skip();
	}

	test_dma_threads(state, 512);
}

void dma_4_queues(void **state, bool sram_only)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_cs_chunk restore_arr[1], execute_arr[4];
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	void *host_src, *host_dst, *dram_addr[2], *restore_cb, *dma_cb[2],
		*common_cb_buf[2], *cp_dma_cb[2];
	uint64_t host_src_device_va, host_dst_device_va, sram_addr, seq,
		common_cb_device_va[2], cp_dma_cb_device_va[2];
	uint32_t dma_size = 128, restore_cb_size = 0,
		dma_cb_size[2] = {0}, common_cb_buf_size[2] = {0},
		cp_dma_cb_size[2] = {0};
	uint16_t sob[3], mon[3];
	int rc, fd = tests_state->fd, i;

	/* This test can't run on Goya, we have a similar test in goya_dma */
	if (hlthunk_get_device_name_from_fd(fd) == HLTHUNK_DEVICE_GOYA) {
		printf("Test is skipped. Run same test from goya_dma\n");
		skip();
	}

	memset(&pkt_info, 0, sizeof(pkt_info));

	/* SRAM MAP (base + ):
	 * - 0x0000 - DMA 2.0 - CB of common CP
	 * - 0x1000 - DMA 3.0 - CB of common CP
	 * - 0x2000 - DMA 2.0 - CB of upper CP
	 * - 0x2020 - DMA 3.0 - CB of upper CP
	 * - 0x2200 - Data
	 *
	 * Test has an option to only use SRAM. In that case, all places where
	 * DRAM is mentioned, it is actually SRAM.
	 *
	 * In that case, the SRAM map also contains:
	 * - 0x2400 - DRAM source location
	 * - 0x2600 - DRAM destination location
	 *
	 * Test Description:
	 * - First DMA QMAN transfers data from host to DRAM and then signals
	 *   SOB0.
	 * - Second DMA QMAN fences on SOB0, transfers data from DRAM to SRAM,
	 *   and then signals SOB1.
	 * - Third DMA QMAN fences on SOB1, transfers data from SRAM to DRAM,
	 *   and then signals SOB2.
	 * - Forth DMA QMAN fences on SOB2 and then transfers data from DRAM to
	 *   host.
	 * - Setup CB is used to clear SOB0, 1 and 2 and to copy all internal
	 *   CBs to SRAM.
	 */

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if ((!sram_only) && (!hw_ip.dram_enabled)) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	sram_addr = hw_ip.sram_base_address;

	/* Allocate memory on host and DRAM and set the SRAM address */
	host_src = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
	assert_non_null(host_src);
	hltests_fill_rand_values(host_src, dma_size);
	host_src_device_va = hltests_get_device_va_for_host_ptr(fd, host_src);

	host_dst = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
	assert_non_null(host_dst);
	memset(host_dst, 0, dma_size);
	host_dst_device_va = hltests_get_device_va_for_host_ptr(fd, host_dst);

	if (sram_only) {
		dram_addr[0] = (void *) (sram_addr + 0x2400);
		dram_addr[1] = (void *) (sram_addr + 0x2600);
	} else {
		for (i = 0 ; i < 2 ; i++) {
			dram_addr[i] = hltests_allocate_device_mem(fd, dma_size,
								NOT_CONTIGUOUS);
			assert_non_null(dram_addr[i]);
		}
	}

	sob[0] = hltests_get_first_avail_sob(fd);
	sob[1] = hltests_get_first_avail_sob(fd) + 1;
	sob[2] = hltests_get_first_avail_sob(fd) + 2;
	mon[0] = hltests_get_first_avail_mon(fd);
	mon[1] = hltests_get_first_avail_mon(fd) + 1;
	mon[2] = hltests_get_first_avail_mon(fd) + 2;

	/* clear SOB 0-2  */
	hltests_clear_sobs(fd, 3);
	for (i = 0 ; i < 2 ; i++) {
		common_cb_buf[i] = hltests_allocate_host_mem(fd, SZ_4K,
								NOT_HUGE);
		assert_non_null(common_cb_buf[i]);
		memset(common_cb_buf[i], 0, SZ_4K);
		common_cb_buf_size[i] = 0;
		common_cb_device_va[i] = hltests_get_device_va_for_host_ptr(fd,
							common_cb_buf[i]);
	}

	/* Start to prepare restore CB to run before execution to copy CB of
	 * device DMA QMANs to SRAM. We will fill this CB throughout this
	 * function
	 */
	restore_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(restore_cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = common_cb_device_va[0];
	pkt_info.dma.dst_addr = sram_addr;
	pkt_info.dma.size = SZ_4K;
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb, restore_cb_size,
						&pkt_info);

	/* Fence on SOB0 + DMA from DRAM to SRAM */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id =
				hltests_get_ddma_qid(fd, 0, STREAM0);
	mon_and_fence_info.cmdq_fence = true;
	mon_and_fence_info.sob_id = sob[0];
	mon_and_fence_info.mon_id = mon[0];
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	common_cb_buf_size[0] = hltests_add_monitor_and_fence(fd,
				common_cb_buf[0], common_cb_buf_size[0],
				&mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = (uint64_t) (uintptr_t) dram_addr[0];
	pkt_info.dma.dst_addr = sram_addr + 0x2200;
	pkt_info.dma.size = dma_size;
	common_cb_buf_size[0] = hltests_add_dma_pkt(fd, common_cb_buf[0],
					common_cb_buf_size[0], &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob[1];
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	common_cb_buf_size[0] = hltests_add_write_to_sob_pkt(fd,
					common_cb_buf[0], common_cb_buf_size[0],
					&pkt_info);

	/* Internal CB for CP_DMA */
	cp_dma_cb[0] = hltests_create_cb(fd, SZ_4K, INTERNAL,
						sram_addr + 0x2000);
	assert_non_null(cp_dma_cb[0]);
	cp_dma_cb_device_va[0] = hltests_get_device_va_for_host_ptr(fd,
							cp_dma_cb[0]);

	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.cp_dma.src_addr = sram_addr;
	pkt_info.cp_dma.size = common_cb_buf_size[0];
	cp_dma_cb_size[0] = hltests_add_cp_dma_pkt(fd, cp_dma_cb[0],
					cp_dma_cb_size[0], &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = cp_dma_cb_device_va[0];
	pkt_info.dma.dst_addr = sram_addr + 0x2000;
	pkt_info.dma.size = cp_dma_cb_size[0];
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb, restore_cb_size,
						&pkt_info);

	/* Fence on SOB1 + DMA from SRAM to DRAM */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = common_cb_device_va[1];
	pkt_info.dma.dst_addr = sram_addr + 0x1000;
	pkt_info.dma.size = SZ_4K;
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb, restore_cb_size,
								&pkt_info);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_ddma_qid(fd, 1, STREAM0);
	mon_and_fence_info.cmdq_fence = true;
	mon_and_fence_info.sob_id = sob[1];
	mon_and_fence_info.mon_id = mon[1];
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	common_cb_buf_size[1] = hltests_add_monitor_and_fence(fd,
				common_cb_buf[1], common_cb_buf_size[1],
				&mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = sram_addr + 0x2200;
	pkt_info.dma.dst_addr = (uint64_t) (uintptr_t) dram_addr[1];
	pkt_info.dma.size = dma_size;
	common_cb_buf_size[1] = hltests_add_dma_pkt(fd, common_cb_buf[1],
					common_cb_buf_size[1], &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob[2];
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	common_cb_buf_size[1] = hltests_add_write_to_sob_pkt(fd,
					common_cb_buf[1], common_cb_buf_size[1],
					&pkt_info);

	/* Internal CB for CP_DMA */
	cp_dma_cb[1] = hltests_create_cb(fd, SZ_4K, INTERNAL,
					sram_addr + 0x2020);
	assert_non_null(cp_dma_cb[1]);
	cp_dma_cb_device_va[1] = hltests_get_device_va_for_host_ptr(fd,
							cp_dma_cb[1]);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.cp_dma.src_addr = sram_addr + 0x1000;
	pkt_info.cp_dma.size = common_cb_buf_size[1];
	cp_dma_cb_size[1] = hltests_add_cp_dma_pkt(fd, cp_dma_cb[1],
					cp_dma_cb_size[1], &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = cp_dma_cb_device_va[1];
	pkt_info.dma.dst_addr = sram_addr + 0x2020;
	pkt_info.dma.size = cp_dma_cb_size[1];
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb, restore_cb_size,
						&pkt_info);

	/* DMA from host to DRAM + signal SOB0 */
	dma_cb[0] = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(dma_cb[0]);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = host_src_device_va;
	pkt_info.dma.dst_addr = (uint64_t) (uintptr_t) dram_addr[0];
	pkt_info.dma.size = dma_size;
	dma_cb_size[0] = hltests_add_dma_pkt(fd, dma_cb[0],
					dma_cb_size[0],	&pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = sob[0];
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	dma_cb_size[0] = hltests_add_write_to_sob_pkt(fd, dma_cb[0],
					dma_cb_size[0], &pkt_info);

	/* Fence on SOB2 + DMA from DRAM to host */
	dma_cb[1] = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(dma_cb[1]);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob[2];
	mon_and_fence_info.mon_id = mon[2];
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	dma_cb_size[1] = hltests_add_monitor_and_fence(fd, dma_cb[1],
					dma_cb_size[1], &mon_and_fence_info);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = (uint64_t) (uintptr_t) dram_addr[1];
	pkt_info.dma.dst_addr = host_dst_device_va;
	pkt_info.dma.size = dma_size;
	dma_cb_size[1] = hltests_add_dma_pkt(fd, dma_cb[1], dma_cb_size[1],
						&pkt_info);

	/* Submit CS and wait for completion */
	restore_arr[0].cb_ptr = restore_cb;
	restore_arr[0].cb_size = restore_cb_size;
	restore_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	execute_arr[0].cb_ptr = dma_cb[0];
	execute_arr[0].cb_size = dma_cb_size[0];
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	execute_arr[1].cb_ptr = cp_dma_cb[0];
	execute_arr[1].cb_size = cp_dma_cb_size[0];
	execute_arr[1].queue_index = hltests_get_ddma_qid(fd, 0, STREAM0);

	execute_arr[2].cb_ptr = cp_dma_cb[1];
	execute_arr[2].cb_size = cp_dma_cb_size[1];
	execute_arr[2].queue_index = hltests_get_ddma_qid(fd, 1, STREAM0);

	execute_arr[3].cb_ptr = dma_cb[1];
	execute_arr[3].cb_size = dma_cb_size[1];
	execute_arr[3].queue_index = hltests_get_dma_up_qid(fd, STREAM0);

	rc = hltests_submit_cs(fd, restore_arr, 1, execute_arr, 4,
						CS_FLAGS_FORCE_RESTORE, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Compare host memories */
	rc = hltests_mem_compare(host_src, host_dst, dma_size);
	assert_int_equal(rc, 0);

	/* Cleanup */
	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_destroy_cb(fd, dma_cb[i]);
		assert_int_equal(rc, 0);
	}

	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_destroy_cb(fd, cp_dma_cb[i]);
		assert_int_equal(rc, 0);
	}

	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_free_host_mem(fd, common_cb_buf[i]);
		assert_int_equal(rc, 0);
	}

	rc = hltests_destroy_cb(fd, restore_cb);
	assert_int_equal(rc, 0);

	if (!sram_only)
		for (i = 0 ; i < 2 ; i++) {
			rc = hltests_free_device_mem(fd, dram_addr[i]);
			assert_int_equal(rc, 0);
		}

	rc = hltests_free_host_mem(fd, host_dst);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, host_src);
	assert_int_equal(rc, 0);
}

void test_dma_4_queues(void **state)
{
	dma_4_queues(state, false);
}

void test_dma_4_queues_sram_only(void **state)
{
	dma_4_queues(state, true);
}

const struct CMUnitTest dma_tests[] = {
	cmocka_unit_test_setup(test_dma_8_threads,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_64_threads,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_512_threads,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_4_queues,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_4_queues_sram_only,
			hltests_ensure_device_operational)
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
