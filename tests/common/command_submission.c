// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

#define ARB_MST_QUIET_PER_DEFAULT 0x10
#define ARB_MST_QUIET_PER_SIMULATOR 0x186A0
#define PLDM_MAX_NUM_PQE_FOR_TESTING 32

static VOID measure_cs_nop(struct hltests_state *tests_state,
			struct hltests_cs_chunk *execute_arr, int num_of_pqe,
			uint16_t wait_after_submit_cnt)
{
	int rc, i, j, loop_cnt, wait_after_cs_cnt, fd = tests_state->fd;
	struct timespec begin, end;
	double time_diff;
	uint64_t seq = 0;

	loop_cnt = 500000;
	wait_after_cs_cnt = wait_after_submit_cnt;

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	for (i = 0, j = wait_after_cs_cnt ; i < loop_cnt ; i++) {
		rc = hltests_submit_cs(fd, NULL, 0, execute_arr,
					num_of_pqe, 0, &seq);
		assert_int_equal(rc, 0);

		if (!--j) {
			rc = hltests_wait_for_cs_until_not_busy(fd, seq);
			assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);
			j = wait_after_cs_cnt;
		}
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	time_diff = get_timediff_sec(&begin, &end);

	printf("time = %.3fus\n", (time_diff / loop_cnt) * 1000000);

	END_TEST;
}


VOID submit_cs_nop(void **state, int num_of_pqe,
				uint16_t wait_after_submit_cnt)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[64];
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size = 0, dma_qid;
	uint64_t seq = 0;
	void *cb[64];
	int rc, i, fd = tests_state->fd;

	if (hltests_is_pldm(fd) && (num_of_pqe > PLDM_MAX_NUM_PQE_FOR_TESTING))
		skip();

	assert_in_range(num_of_pqe, 1, 64);

	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	for (i = 0 ; i < num_of_pqe ; i++) {
		cb[i] = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
		assert_non_null(cb[i]);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = dma_qid;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		cb_size = hltests_add_nop_pkt(fd, cb[i], 0, &pkt_info);

		execute_arr[i].cb_ptr = cb[i];
		execute_arr[i].cb_size = cb_size;
		execute_arr[i].queue_index = dma_qid;

	}

	if (!wait_after_submit_cnt) {
		rc = hltests_submit_cs(fd, NULL, 0, execute_arr, num_of_pqe, 0,
					&seq);
		assert_int_equal(rc, 0);

		rc = hltests_wait_for_cs_until_not_busy(fd, seq);
		assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);
	} else {
		measure_cs_nop(tests_state, execute_arr, num_of_pqe,
				wait_after_submit_cnt);
	}

	for (i = 0 ; i < num_of_pqe ; i++) {
		rc = hltests_destroy_cb(fd, cb[i]);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_cs_nop(void **state)
{
	END_TEST_FUNC(submit_cs_nop(state, 1, 0));
}

VOID test_cs_nop_16PQE(void **state)
{
	END_TEST_FUNC(submit_cs_nop(state, 16, 0));
}

VOID test_cs_nop_32PQE(void **state)
{
	END_TEST_FUNC(submit_cs_nop(state, 32, 0));
}

VOID test_cs_nop_48PQE(void **state)
{
	END_TEST_FUNC(submit_cs_nop(state, 48, 0));
}

VOID test_cs_nop_64PQE(void **state)
{
	END_TEST_FUNC(submit_cs_nop(state, 64, 0));
}

VOID test_and_measure_wait_after_submit_cs_nop(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;

	if (hltests_is_simulator(fd) || hltests_is_pldm(fd))
		skip();

	END_TEST_FUNC(submit_cs_nop(state, 1, 1));
}

VOID test_and_measure_wait_after_64_submit_cs_nop(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;

	if (hltests_is_simulator(fd) || hltests_is_pldm(fd))
		skip();
	/* Since we have up to 64 cq and driver uses one of them, we can't run test in ARC mode*/
	if (!hltests_is_legacy_mode_enabled(fd))
		skip();

	END_TEST_FUNC(submit_cs_nop(state, 1, 64));
}

VOID test_and_measure_wait_after_256_submit_cs_nop(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;

	if (hltests_is_simulator(fd) || hltests_is_pldm(fd))
		skip();
	/* Since we have up to 64 cq and driver uses one of them, we can't run test in ARC mode*/
	if (!hltests_is_legacy_mode_enabled(fd))
		skip();

	END_TEST_FUNC(submit_cs_nop(state, 1, 256));
}

VOID test_cs_msg_long(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size = 0;
	void *cb;
	int rc, fd = tests_state->fd;

	cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = hw_ip.sram_base_address + 0x1000;
	pkt_info.msg_long.value = 0xbaba0ded;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	END_TEST_FUNC(hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED));
}

#define NUM_OF_MSGS	2000

VOID test_cs_msg_long_2000(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info hw_ip;
	int rc, fd = tests_state->fd, i;
	uint32_t cb_size = 0;
	void *cb;

	/* Largest packet is 24 bytes, so 32 is a good number */
	cb = hltests_create_cb(fd, NUM_OF_MSGS * 32, EXTERNAL, 0);
	assert_non_null(cb);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	for (i = 0 ; i < NUM_OF_MSGS ; i++) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.msg_long.address = hw_ip.sram_base_address +
							0x1000 + i * 4;
		pkt_info.msg_long.value = 0x0ded0000 + i;
		cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);
	}

	END_TEST_FUNC(hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED));
}

enum complete_multi_cs_qid {
	QID_MULTI_CS,
	QID_SIGNALING_THREAD,
	QID_MULTI_CS_NUM
};

struct complete_multi_cs_params {
	uint64_t *seq;
	uint32_t seq_len;
	uint32_t qid;
	int fd;
	uint16_t sob0;
	unsigned int sleep_us;
};

static void *multi_cs_complete_first_cs(void *data)
{
	struct complete_multi_cs_params *params =
			(struct complete_multi_cs_params *) data;
	struct hltests_pkt_info pkt_info;
	uint32_t signal_cb_size = 0;
	void *signal_cb;
	int rc;

	signal_cb = hltests_create_cb(params->fd, 0x1000, EXTERNAL, 0);
	assert_non_null_ret_ptr(signal_cb);

	/* signal first CS on the list */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = params->qid;
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = params->sob0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_SET;
	signal_cb_size = hltests_add_write_to_sob_pkt(params->fd, signal_cb,
						signal_cb_size, &pkt_info);

	/*
	 * make best effort to signal CS while "wait-for-multi-CS" is already
	 * waiting (i.e. test the signal path and not the poll path)
	 */
	if (params->sleep_us)
		usleep(params->sleep_us);

	rc = hltests_submit_and_wait_cs(params->fd, signal_cb, signal_cb_size,
						params->qid, DESTROY_CB_TRUE,
						HL_WAIT_CS_STATUS_COMPLETED);
	assert_int_equal_ret_ptr(rc, 0);

	return data;
}

VOID test_wait_for_multi_cs_common(void **state, bool do_complete)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t mon_cb_size[HL_WAIT_MULTI_CS_LIST_MAX_LEN] = {0};
	void *signal_cb, *mon_cb[HL_WAIT_MULTI_CS_LIST_MAX_LEN];
	uint64_t timestamp, seq[HL_WAIT_MULTI_CS_LIST_MAX_LEN];
	struct hltests_monitor_and_fence mon_and_fence_info;
	struct complete_multi_cs_params mcs_params = {0};
	struct hlthunk_wait_multi_cs_out mcs_out = {0};
	uint32_t signal_cb_size, *stream_master_tbl;
	struct hlthunk_wait_multi_cs_in mcs_in;
	struct hltests_cs_chunk execute_arr[1];
	struct hltests_pkt_info pkt_info;
	int rc, i, fd = tests_state->fd;
	uint16_t mon_base, sob0, sob1;
	pthread_t thread_id;
	void *retval;

	if (!hltests_is_gaudi(fd)) {
		printf("Test is skipped. Goya doesn't support multi-CS\n");
		skip();
	}

	/*
	 * test structure: complete mode
	 * STEP 1: HL_WAIT_MULTI_CS_LIST_MAX_LEN CSs are submitted to the
	 *         same stream master QID (in the main thread)
	 *    where:
	 *    - CS0: fence on SOB0
	 *    - CS1-END: fence on SOB1
	 *
	 * STEP 2: another CS is submitted by different thread which set SOB0
	 *         to the value that will signals CS0 on the CS list. this on
	 *         has to be submitted to stream master QID which is different
	 *         from the one used for the CS list. that is in order to
	 *         avoid completing the multi-CS call by itself.
	 *
	 * STEP 3: wait for multi CS in the main thread (expect to see only
	 *         CS0 returning the wait call)
	 *
	 * SETP 4: signal SOB 1 to signal all other CSs
	 *
	 *
	 * test structure: poll mode
	 * STEP 1: HL_WAIT_MULTI_CS_LIST_MAX_LEN CSs are submitted to the
	 *         same stream master QID (in the main thread)
	 *    where:
	 *    - CS0: no fence
	 *    - CS1-END: fence on SOB1
	 *
	 * STEP 2: wait for CS0 to complete (to make sure the poll will succeed)
	 *
	 * STEP 3: wait for multi CS in the main thread (expect to see only
	 *         CS0 returning the wait call)
	 *
	 * SETP 4: signal SOB 1 to signal all other CSs
	 */

	sob0 = hltests_get_first_avail_sob(fd);
	sob1 = sob0 + 1;
	hltests_clear_sobs(fd, 2);
	mon_base = hltests_get_first_avail_mon(fd);

	assert_true(hltests_get_stream_master_qid_arr(fd, &stream_master_tbl) > QID_MULTI_CS_NUM);

	/*
	 * init all CSs to wait on SOBs:
	 * 1. CS0 waits on SOB0
	 * 2. all other CSs waits on SOB1
	 */
	for (i = 0; i < HL_WAIT_MULTI_CS_LIST_MAX_LEN; i++) {
		mon_cb[i] = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
		assert_non_null(mon_cb[i]);

		/*
		 * In case we want to get completion by polling we do not hold
		 * CS0 on a fence.
		 * all other CSs are waiting on a fence
		 * In any case, if we want to get actual completion the first
		 * CS fences on different monitor than other CSs on the list
		 */
		if (!((i == 0) && !do_complete)) {
			memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
			mon_and_fence_info.queue_id = stream_master_tbl[QID_MULTI_CS];
			mon_and_fence_info.cmdq_fence = false;
			mon_and_fence_info.sob_id = (i == 0) ? sob0 : sob1;
			mon_and_fence_info.mon_id = mon_base + i;
			mon_and_fence_info.mon_address = 0;
			mon_and_fence_info.sob_val = 1;
			mon_and_fence_info.dec_fence = true;
			mon_and_fence_info.mon_payload = 1;
			mon_cb_size[i] = hltests_add_monitor_and_fence(fd, mon_cb[i],
							0, &mon_and_fence_info);
		}

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		mon_cb_size[i] = hltests_add_nop_pkt(fd, mon_cb[i],
						mon_cb_size[i], &pkt_info);

		/* First CS: Submit CB of stream 0 */
		execute_arr[0].cb_ptr = mon_cb[i];
		execute_arr[0].cb_size = mon_cb_size[i];
		execute_arr[0].queue_index = stream_master_tbl[QID_MULTI_CS];
		rc = hltests_submit_cs_timeout(fd, NULL, 0, execute_arr, 1, 0,
								30, &seq[i]);
		assert_int_equal(rc, 0);
	}

	if (do_complete) {
		/* in case we want the multi-CS to complete with completion
		 * (not by polling) we use thread that wait (hopefully) till
		 * CS0 is waiting on the fence and then wake the call by
		 * completion
		 */

		/* update multi-CS params */
		mcs_params.seq = seq;
		mcs_params.seq_len = HL_WAIT_MULTI_CS_LIST_MAX_LEN;
		mcs_params.qid = stream_master_tbl[QID_SIGNALING_THREAD];
		mcs_params.sob0 = sob0;
		mcs_params.fd = fd;
		mcs_params.sleep_us = 500000;
		rc = pthread_create(&thread_id, NULL, multi_cs_complete_first_cs,
									&mcs_params);
		assert_int_equal(rc, 0);
	} else {
		/*
		 * in case we want to test the poll flow we make sure CS0 is
		 * completed before waiting on multi CS
		 */
		rc = hltests_wait_for_cs_until_not_busy(fd, seq[0]);
		assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);
	}

	mcs_in.seq = seq;
	mcs_in.timeout_us = WAIT_FOR_CS_DEFAULT_TIMEOUT;
	mcs_in.seq_len = HL_WAIT_MULTI_CS_LIST_MAX_LEN;
	rc = hlthunk_wait_for_multi_cs_with_timestamp(fd, &mcs_in, &mcs_out,
								&timestamp);

	/* we expect only CS0 to be completed */
	assert_int_equal(rc, 0);
	assert_int_equal(mcs_out.completed, 1);
	assert_int_equal(mcs_out.seq_set, (uint32_t)(0x1));
	assert_int_equal(mcs_out.status, HL_WAIT_CS_STATUS_COMPLETED);

	/* wait for thread completion only if we do completion */
	if (do_complete) {
		rc = pthread_join(thread_id, &retval);
		assert_int_equal(rc, 0);
		assert_non_null(retval);
	}

	signal_cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(signal_cb);
	signal_cb_size = 0;

	/* signal the reset of CSs on the list */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = hltests_get_dma_up_qid(fd, STREAM0);
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob1;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_SET;
	signal_cb_size = hltests_add_write_to_sob_pkt(fd, signal_cb,
					signal_cb_size, &pkt_info);

	rc = hltests_submit_and_wait_cs(fd, signal_cb, signal_cb_size, pkt_info.qid,
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
	assert_int_equal(rc, 0);

	/* wait for all other CSs */
	for (i = 1; i < HL_WAIT_MULTI_CS_LIST_MAX_LEN; i++) {
		rc = hltests_wait_for_cs_until_not_busy(fd, seq[i]);
		assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);
	}

	for (i = 0; i < HL_WAIT_MULTI_CS_LIST_MAX_LEN; i++) {
		rc = hltests_destroy_cb(fd, mon_cb[i]);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_wait_for_multi_cs_complete(void **state)
{
	END_TEST_FUNC(test_wait_for_multi_cs_common(state, true));
}

VOID test_wait_for_multi_cs_poll(void **state)
{
	END_TEST_FUNC(test_wait_for_multi_cs_common(state, false));
}

VOID test_cs_two_streams_with_fence(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	struct hltests_cs_chunk execute_arr[1];
	uint32_t dma_size = 4, cb_stream0_size = 0, cb_stream3_size = 0;
	uint64_t src_data_device_va, device_data_address, seq;
	uint16_t sob0, mon0, dma_down_qid_s0, dma_down_qid_s3;
	void *src_data, *cb_stream0, *cb_stream3;
	int rc, fd = tests_state->fd;

	if (hltests_is_gaudi2(fd) && !hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is irrelevant when running Gaudi2 in ARC mode, skipping\n");
		skip();
	}

	/* This test can't run on Goya because it doesn't have streams */
	if (hltests_is_goya(fd)) {
		printf("Test is skipped. Goya doesn't have streams\n");
		skip();
	}

	/* SRAM MAP (base + )
	 * 0x1000 : data
	 */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	dma_down_qid_s0 = hltests_get_dma_down_qid(fd, STREAM0);
	dma_down_qid_s3 = hltests_get_dma_down_qid(fd, STREAM3);

	device_data_address = hw_ip.sram_base_address + 0x1000;

	/* Allocate buffer on host for data transfer */
	src_data = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
	assert_non_null(src_data);
	hltests_fill_rand_values(src_data, dma_size);
	src_data_device_va = hltests_get_device_va_for_host_ptr(fd, src_data);

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);

	/* Clear SOB0 */
	hltests_clear_sobs(fd, 1);

	/* Stream 0: Fence on SOB0 + LIN_DMA from host to SRAM */
	cb_stream0 = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb_stream0);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = dma_down_qid_s0;
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_stream0_size = hltests_add_monitor_and_fence(fd, cb_stream0,
					cb_stream0_size, &mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_down_qid_s0;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = src_data_device_va;
	pkt_info.dma.dst_addr = device_data_address;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;
	cb_stream0_size = hltests_add_dma_pkt(fd, cb_stream0, cb_stream0_size,
						&pkt_info);

	/* Stream 3: Signal SOB0 */
	cb_stream3 = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb_stream3);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_down_qid_s3;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = sob0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_stream3_size = hltests_add_write_to_sob_pkt(fd, cb_stream3,
						cb_stream3_size, &pkt_info);

	/* First CS: Submit CB of stream 0 */
	execute_arr[0].cb_ptr = cb_stream0;
	execute_arr[0].cb_size = cb_stream0_size;
	execute_arr[0].queue_index = dma_down_qid_s0;
	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq);
	assert_int_equal(rc, 0);

	/* Second CS: Submit CB of stream 3 and wait for completion */
	hltests_submit_and_wait_cs(fd, cb_stream3, cb_stream3_size, dma_down_qid_s3,
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);

	/* First CS: Wait for completion */
	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Cleanup */
	rc = hltests_destroy_cb(fd, cb_stream3);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, cb_stream0);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, src_data);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID hltests_cs_two_streams_arb_point(int fd,
					     struct hltests_arb_info *arb_info,
					     uint64_t *host_data_va,
					     uint64_t *device_data_addr,
					     uint16_t sob_id,
					     uint16_t *mon_id,
					     uint32_t dma_size,
					     bool ds_direction)
{
	struct hltests_monitor_and_fence mon_and_fence_info;
	struct hltests_pkt_info pkt_info;
	struct hltests_cs_chunk execute_arr[2];
	void *cb_stream[3], *cb_arbiter;
	int i, rc;
	uint32_t cb_stream_size[3], qid[3], cb_arbiter_size = 0;
	uint64_t seq, src_addr, dst_addr, dma_pkt_bytes;

	qid[0] = ds_direction ? hltests_get_dma_down_qid(fd, STREAM0) :
			hltests_get_dma_up_qid(fd, STREAM0);
	qid[1] = ds_direction ? hltests_get_dma_down_qid(fd, STREAM1) :
			hltests_get_dma_up_qid(fd, STREAM1);

	/* Enable QMANs arbiter */
	cb_arbiter = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb_arbiter);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	cb_arbiter_size = hltests_add_arb_en_pkt(fd, cb_arbiter,
			cb_arbiter_size, &pkt_info, arb_info, qid[0], true);

	hltests_submit_and_wait_cs(fd, cb_arbiter, cb_arbiter_size, qid[0],
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);

	memset(cb_stream_size, 0, sizeof(cb_stream_size));
	cb_stream[0] = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb_stream[0]);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = qid[0];
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob_id;
	mon_and_fence_info.mon_id = mon_id[0];
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_stream_size[0] = hltests_add_monitor_and_fence(fd, cb_stream[0],
			cb_stream_size[0], &mon_and_fence_info);

	/*
	 * Stream 0
	 * Add arb point packet - lock
	 * Use a lock-unlock-lock sequence in order for
	 * both stream to start simultaneously
	 */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;

	if (arb_info->arb == ARB_PRIORITY)
		pkt_info.arb_point.priority = arb_info->priority[STREAM0];

	pkt_info.arb_point.release = 0;

	cb_stream_size[0] = hltests_add_arb_point_pkt(fd, cb_stream[0],
			cb_stream_size[0], &pkt_info);

	pkt_info.arb_point.release = 1;

	cb_stream_size[0] = hltests_add_arb_point_pkt(fd, cb_stream[0],
			cb_stream_size[0], &pkt_info);

	pkt_info.arb_point.release = 0;

	cb_stream_size[0] = hltests_add_arb_point_pkt(fd, cb_stream[0],
			cb_stream_size[0], &pkt_info);

	/* Add dma packets */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	src_addr = ds_direction ? host_data_va[0] : device_data_addr[0];
	dst_addr = ds_direction ? device_data_addr[0] : host_data_va[0];

	/* Split to 32 dma transactions */
	dma_pkt_bytes = dma_size / 32;

	for (i = 0 ; i < 32 ; i++) {
		pkt_info.dma.src_addr = src_addr + (i * dma_pkt_bytes);
		pkt_info.dma.dst_addr = dst_addr + (i * dma_pkt_bytes);
		pkt_info.dma.size = dma_pkt_bytes;

		cb_stream_size[0] = hltests_add_dma_pkt(fd, cb_stream[0],
				cb_stream_size[0], &pkt_info);
	}

	/* Add arb point packet - release */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.arb_point.release = 1;

	if (arb_info->arb == ARB_PRIORITY)
		pkt_info.arb_point.priority = arb_info->priority[STREAM0];

	cb_stream_size[0] = hltests_add_arb_point_pkt(fd, cb_stream[0],
			cb_stream_size[0], &pkt_info);

	/* Stream 1 */
	cb_stream[1] = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb_stream[1]);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = qid[1];
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob_id;
	mon_and_fence_info.mon_id = mon_id[1];
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_stream_size[1] = hltests_add_monitor_and_fence(fd, cb_stream[1],
				cb_stream_size[1], &mon_and_fence_info);

	/*
	 * Add arb point packet - lock
	 * Use a lock-unlock-lock sequence in order for
	 * both stream to start simultaneously
	 */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;

	if (arb_info->arb == ARB_PRIORITY)
		pkt_info.arb_point.priority = arb_info->priority[STREAM1];

	pkt_info.arb_point.release = 0;

	cb_stream_size[1] = hltests_add_arb_point_pkt(fd, cb_stream[1],
			cb_stream_size[1], &pkt_info);

	pkt_info.arb_point.release = 1;

	cb_stream_size[1] = hltests_add_arb_point_pkt(fd, cb_stream[1],
			cb_stream_size[1], &pkt_info);

	pkt_info.arb_point.release = 0;

	cb_stream_size[1] = hltests_add_arb_point_pkt(fd, cb_stream[1],
			cb_stream_size[1], &pkt_info);

	/* Add dma packets */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	src_addr = ds_direction ? host_data_va[1] : device_data_addr[1];
	dst_addr = ds_direction ? device_data_addr[1] : host_data_va[1];

	/* Split to 32 dma transactions */
	for (i = 0 ; i < 32 ; i++) {
		pkt_info.dma.src_addr = src_addr + (i * dma_pkt_bytes);
		pkt_info.dma.dst_addr = dst_addr + (i * dma_pkt_bytes);
		pkt_info.dma.size = dma_pkt_bytes;

		cb_stream_size[1] = hltests_add_dma_pkt(fd, cb_stream[1],
				cb_stream_size[1], &pkt_info);
	}

	/* Add arb point packet - release */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.arb_point.release = 1;

	if (arb_info->arb == ARB_PRIORITY)
		pkt_info.arb_point.priority = arb_info->priority[STREAM1];

	cb_stream_size[1] = hltests_add_arb_point_pkt(fd, cb_stream[1],
			cb_stream_size[1], &pkt_info);

	/* Stream 2: Signal SOB */
	cb_stream[2] = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb_stream[2]);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = sob_id;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_stream_size[2] = hltests_add_write_to_sob_pkt(fd, cb_stream[2],
				cb_stream_size[2], &pkt_info);

	/* First CS: Submit CB of first 2 streams */
	execute_arr[0].cb_ptr = cb_stream[0];
	execute_arr[0].cb_size = cb_stream_size[0];
	execute_arr[0].queue_index = qid[0];
	execute_arr[1].cb_ptr = cb_stream[1];
	execute_arr[1].cb_size = cb_stream_size[1];
	execute_arr[1].queue_index = qid[1];

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2, 0, &seq);
	assert_int_equal(rc, 0);

	if (hltests_is_gaudi2(fd)) {
		qid[2] = hltests_get_dma_down_qid(fd, STREAM2);
	} else {
		qid[2] = ds_direction ? hltests_get_dma_down_qid(fd, STREAM2) :
				hltests_get_dma_up_qid(fd, STREAM2);
	}

	/* Second CS: Submit CB of stream 2 and wait for completion */
	hltests_submit_and_wait_cs(fd, cb_stream[2], cb_stream_size[2], qid[2],
			DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);

	/* First CS: Wait for completion */
	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Cleanup */
	rc = hltests_destroy_cb(fd, cb_stream[0]);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, cb_stream[1]);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, cb_stream[2]);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_cs_two_streams_with_arb(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_arb_info arb_info;
	uint64_t data_va[4], src_data_device_va[2], dst_data_device_va[2];
	uint64_t device_data_address[2];
	uint32_t dma_size = 128;
	uint16_t sob[2], mon[4];
	void *data[4], *src_data[2], *dst_data[2];
	int i, rc, fd = tests_state->fd;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is irrelevant when running in ARC mode, skipping\n");
		skip();
	}

	/* This test can't run on Goya because it doesn't have streams */
	if (hlthunk_get_device_name_from_fd(fd) == HLTHUNK_DEVICE_GOYA) {
		printf("Test is skipped. Goya doesn't have streams\n");
		skip();
	}

	/* SRAM MAP (base + )
	 * 0x0    : data1
	 * 0x1000 : data2
	 */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	device_data_address[0] = hw_ip.sram_base_address;
	device_data_address[1] = hw_ip.sram_base_address + 0x1000;

	/* Allocate buffers on host for data transfer */
	for (i = 0 ; i < 4 ; i++) {
		data[i] = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
		assert_non_null(data[i]);
		memset(data[i], 0, dma_size);
		data_va[i] = hltests_get_device_va_for_host_ptr(fd, data[i]);
	}

	src_data[0] = data[0];
	src_data[1] = data[1];
	dst_data[0] = data[2];
	dst_data[1] = data[3];
	hltests_fill_rand_values(src_data[0], dma_size);
	hltests_fill_rand_values(src_data[1], dma_size);

	src_data_device_va[0] = data_va[0];
	src_data_device_va[1] = data_va[1];
	dst_data_device_va[0] = data_va[2];
	dst_data_device_va[1] = data_va[3];

	sob[0] = hltests_get_first_avail_sob(fd);
	sob[1] = hltests_get_first_avail_sob(fd) + 1;
	mon[0] = hltests_get_first_avail_mon(fd);
	mon[1] = hltests_get_first_avail_mon(fd) + 1;
	mon[2] = hltests_get_first_avail_mon(fd) + 2;
	mon[3] = hltests_get_first_avail_mon(fd) + 3;

	/* Clear SOB0 & SOB1 */
	hltests_clear_sobs(fd, 2);

	arb_info.arb = ARB_PRIORITY;
	arb_info.priority[STREAM0] = 1;
	arb_info.priority[STREAM1] = 2;
	arb_info.priority[STREAM2] = 3;
	arb_info.arb_mst_quiet_val = ARB_MST_QUIET_PER_DEFAULT;

	/* Stream 0: Fence on SOB0 + LIN_DMA from host src0 to SRAM dst0 */
	/* Stream 1: Fence on SOB0 + LIN_DMA from host src1 to SRAM dst1 */
	/* Stream 2: signal SOB0 */
	hltests_cs_two_streams_arb_point(fd, &arb_info, src_data_device_va,
					 device_data_address,
					 sob[0], &mon[0], dma_size, true);

	/* Stream 0: Fence on SOB1 + LIN_DMA from SRAM dst0 to host dst0 */
	/* Stream 1: Fence on SOB1 + LIN_DMA from SRAM dst1 to host dst1 */
	/* Stream 2: signal SOB1 */
	hltests_cs_two_streams_arb_point(fd, &arb_info, dst_data_device_va,
					 device_data_address,
					 sob[1], &mon[2], dma_size, false);

	rc = hltests_mem_compare(src_data[0], dst_data[0], dma_size);
	assert_int_equal(rc, 0);

	rc = hltests_mem_compare(src_data[1], dst_data[1], dma_size);
	assert_int_equal(rc, 0);

	for (i = 0 ; i < 4 ; i++) {
		rc = hltests_free_host_mem(fd, data[i]);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_cs_two_streams_with_priority_arb(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_arb_info arb_info;
	struct hltests_pkt_info pkt_info;
	uint64_t data_va[3], src_data_device_va[2], dst_data_device_va;
	uint64_t device_data_address[2];
	uint32_t dma_size = 128, cb_upstream_size = 0;
	uint16_t sob, mon[4];
	void *data[3], *src_data[2], *dst_data, *cb_upstream;
	int i, rc, fd = tests_state->fd;

	/* Test intermittently fails on Greco and Gaudi2 */
	if (!hltests_is_gaudi(fd)) {
		printf("Test is relevant for Gaudi only, skipping\n");
		skip();
	}

	/* SRAM MAP (base + )
	 * 0x0    : data1
	 * 0x1000 : data2
	 */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	device_data_address[0] = hw_ip.sram_base_address;
	device_data_address[1] = hw_ip.sram_base_address;

	/* Allocate buffers on host for data transfer */
	for (i = 0 ; i < 3 ; i++) {
		data[i] = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
		assert_non_null(data[i]);
		memset(data[i], 0, dma_size);
		data_va[i] = hltests_get_device_va_for_host_ptr(fd, data[i]);
	}

	src_data[0] = data[0];
	src_data[1] = data[1];
	dst_data = data[2];
	hltests_fill_rand_values(src_data[0], dma_size);
	hltests_fill_rand_values(src_data[1], dma_size);

	src_data_device_va[0] = data_va[0];
	src_data_device_va[1] = data_va[1];
	dst_data_device_va = data_va[2];

	sob = hltests_get_first_avail_sob(fd);
	mon[0] = hltests_get_first_avail_mon(fd);
	mon[1] = hltests_get_first_avail_mon(fd) + 1;

	/* Clear SOB0 */
	hltests_clear_sobs(fd, 1);

	/* Test #1 - Stream 1 with lower priority */
	arb_info.arb = ARB_PRIORITY;
	arb_info.priority[STREAM0] = 2;
	arb_info.priority[STREAM1] = 1;
	arb_info.priority[STREAM2] = 3;

	if (hltests_is_simulator(fd) || hltests_is_pldm(fd))
		arb_info.arb_mst_quiet_val = ARB_MST_QUIET_PER_SIMULATOR;
	else
		arb_info.arb_mst_quiet_val = ARB_MST_QUIET_PER_DEFAULT;

	/* Stream 0: Fence on SOB0 + LIN_DMA from host src0 to SRAM */
	/* Stream 1: Fence on SOB0 + LIN_DMA from host src1 to SRAM */
	/* Stream 2: signal SOB0 */
	hltests_cs_two_streams_arb_point(fd, &arb_info, src_data_device_va,
					 device_data_address,
					 sob, &mon[0], dma_size, true);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = device_data_address[0];
	pkt_info.dma.dst_addr = dst_data_device_va;
	pkt_info.dma.size = dma_size;

	cb_upstream = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb_upstream);

	cb_upstream_size = hltests_add_dma_pkt(fd, cb_upstream,
			cb_upstream_size, &pkt_info);

	hltests_submit_and_wait_cs(fd, cb_upstream, cb_upstream_size,
			hltests_get_dma_up_qid(fd, STREAM0),
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
	cb_upstream_size = 0;

	rc = hltests_mem_compare(src_data[1], dst_data, dma_size);
	assert_int_equal(rc, 0);

	/* Test #2 - Stream 0 with lower priority */
	memset(dst_data, 0, dma_size);

	/* Clear SOB0 */
	hltests_clear_sobs(fd, 1);

	arb_info.arb = ARB_PRIORITY;
	arb_info.priority[STREAM0] = 1;
	arb_info.priority[STREAM1] = 2;
	arb_info.priority[STREAM2] = 3;

	/* Stream 0: Fence on SOB0 + LIN_DMA from host src0 to SRAM */
	/* Stream 1: Fence on SOB0 + LIN_DMA from host src1 to SRAM */
	/* Stream 2: signal SOB0 */
	hltests_cs_two_streams_arb_point(fd, &arb_info, src_data_device_va,
					 device_data_address,
					 sob, &mon[0], dma_size, true);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = device_data_address[0];
	pkt_info.dma.dst_addr = dst_data_device_va;
	pkt_info.dma.size = dma_size;

	cb_upstream = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb_upstream);

	cb_upstream_size = hltests_add_dma_pkt(fd, cb_upstream,
			cb_upstream_size, &pkt_info);

	hltests_submit_and_wait_cs(fd, cb_upstream, cb_upstream_size,
			hltests_get_dma_up_qid(fd, STREAM0),
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_mem_compare(src_data[0], dst_data, dma_size);
	assert_int_equal(rc, 0);

	if (hltests_is_simulator(fd) || hltests_is_pldm(fd)) {
		void *cb_arbiter;
		uint32_t cb_arbiter_size = 0;

		/* Restore arb_mst_quiet register value */
		cb_arbiter = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
		assert_non_null(cb_arbiter);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		arb_info.arb_mst_quiet_val = ARB_MST_QUIET_PER_DEFAULT;
		cb_arbiter_size = hltests_add_arb_en_pkt(fd, cb_arbiter,
				cb_arbiter_size, &pkt_info, &arb_info,
				hltests_get_dma_down_qid(fd, STREAM0), true);

		hltests_submit_and_wait_cs(fd, cb_arbiter, cb_arbiter_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
	}

	for (i = 0 ; i < 3 ; i++) {
		rc = hltests_free_host_mem(fd, data[i]);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_cs_two_streams_with_wrr_arb(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_arb_info arb_info;
	uint64_t data_va[4], src_data_device_va[2], dst_data_device_va[2];
	uint64_t device_data_address[2];
	uint32_t dma_size = 128;
	uint16_t sob[2], mon[4];
	void *data[4], *src_data[2], *dst_data[2];
	int i, rc, fd = tests_state->fd;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is irrelevant when running in ARC mode, skipping\n");
		skip();
	}

	/* This test can't run on Goya because it doesn't have streams */
	if (hlthunk_get_device_name_from_fd(fd) == HLTHUNK_DEVICE_GOYA) {
		printf("Test is skipped. Goya doesn't have streams\n");
		skip();
	}

	/* SRAM MAP (base + )
	 * 0x0    : data1
	 * 0x1000 : data2
	 */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	device_data_address[0] = hw_ip.sram_base_address;
	device_data_address[1] = hw_ip.sram_base_address + 0x1000;

	/* Allocate buffers on host for data transfer */
	for (i = 0 ; i < 4 ; i++) {
		data[i] = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
		assert_non_null(data[i]);
		memset(data[i], 0, dma_size);
		data_va[i] = hltests_get_device_va_for_host_ptr(fd, data[i]);
	}

	src_data[0] = data[0];
	src_data[1] = data[1];
	dst_data[0] = data[2];
	dst_data[1] = data[3];
	hltests_fill_rand_values(src_data[0], dma_size);
	hltests_fill_rand_values(src_data[1], dma_size);

	src_data_device_va[0] = data_va[0];
	src_data_device_va[1] = data_va[1];
	dst_data_device_va[0] = data_va[2];
	dst_data_device_va[1] = data_va[3];

	sob[0] = hltests_get_first_avail_sob(fd);
	sob[1] = hltests_get_first_avail_sob(fd) + 1;
	mon[0] = hltests_get_first_avail_mon(fd);
	mon[1] = hltests_get_first_avail_mon(fd) + 1;
	mon[2] = hltests_get_first_avail_mon(fd) + 2;
	mon[3] = hltests_get_first_avail_mon(fd) + 3;

	/* Clear SOB0 & SOB1 */
	hltests_clear_sobs(fd, 2);

	arb_info.arb = ARB_WRR;
	arb_info.weight[STREAM0] = 1;
	arb_info.weight[STREAM1] = 1;
	arb_info.weight[STREAM2] = 1;
	arb_info.weight[STREAM3] = 1;
	arb_info.arb_mst_quiet_val = ARB_MST_QUIET_PER_DEFAULT;

	/* Stream 0: Fence on SOB0 + LIN_DMA from host src0 to SRAM dst0 */
	/* Stream 1: Fence on SOB0 + LIN_DMA from host src1 to SRAM dst1 */
	/* Stream 2: signal SOB0 */
	hltests_cs_two_streams_arb_point(fd, &arb_info, src_data_device_va,
					 device_data_address,
					 sob[0], &mon[0], dma_size, true);

	/* Stream 0: Fence on SOB1 + LIN_DMA from SRAM dst0 to host dst0 */
	/* Stream 1: Fence on SOB1 + LIN_DMA from SRAM dst1 to host dst1 */
	/* Stream 2: signal SOB1 */
	hltests_cs_two_streams_arb_point(fd, &arb_info, dst_data_device_va,
					 device_data_address,
					 sob[1], &mon[2], dma_size, false);

	rc = hltests_mem_compare(src_data[0], dst_data[0], dma_size);
	assert_int_equal(rc, 0);

	rc = hltests_mem_compare(src_data[1], dst_data[1], dma_size);
	assert_int_equal(rc, 0);

	for (i = 0 ; i < 4 ; i++) {
		rc = hltests_free_host_mem(fd, data[i]);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_cs_cq_wrap_around(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t cq_wrap_around_num_of_cs = 1000;
	int i;

	if (hltests_is_pldm(tests_state->fd))
		skip();

	for (i = 0 ; i < cq_wrap_around_num_of_cs ; i++)
		test_cs_nop(state);

	END_TEST;
}

static uint32_t load_predicates_and_test_msg_long(int fd,
						uint64_t pred_buf_sram_addr,
						uint64_t pred_buf_device_va,
						uint64_t msg_long_dst_sram_addr,
						uint64_t host_data_device_va,
						uint8_t pred_id,
						bool is_consecutive_map)
{
	struct hltests_pkt_info pkt_info;
	enum hl_tests_predicates_map pred_map;
	uint32_t cb_size, value;
	void *cb;

	pred_map = is_consecutive_map ? PMAP_CONSECUTIVE : PMAP_NON_CONSECUTIVE;

	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(cb);
	cb_size = 0;

	/* DMA predicates buffer from host to SRAM */
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_FALSE, pred_buf_device_va,
				pred_buf_sram_addr, 128, DMA_DIR_HOST_TO_SRAM);

	/* Initialize the MSG_LONG destination in SRAM */
	hltests_fill_rand_values(&value, 4);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_long.address = msg_long_dst_sram_addr;
	pkt_info.msg_long.value = value;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	/* Load predicates */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.load_and_exe.src_addr = pred_buf_sram_addr;
	pkt_info.load_and_exe.load = 1;
	pkt_info.load_and_exe.exe = 0;
	pkt_info.load_and_exe.load_dst = DST_PREDICATES;
	pkt_info.load_and_exe.pred_map = pred_map;
	pkt_info.load_and_exe.exe_type = 0;
	cb_size = hltests_add_load_and_exe_pkt(fd, cb, cb_size, &pkt_info);

	/* MSG_LONG that depends on "pred_id" */
	hltests_fill_rand_values(&value, 4);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.pred = pred_id;
	pkt_info.msg_long.address = msg_long_dst_sram_addr;
	pkt_info.msg_long.value = value;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);

	/* DMA MSG_LONG destination from SRAM to host */
	hltests_dma_transfer(fd, hltests_get_dma_up_qid(fd, STREAM0),
				EB_FALSE, MB_FALSE, msg_long_dst_sram_addr,
				host_data_device_va, 4, DMA_DIR_SRAM_TO_HOST);

	return value;
}

VOID test_cs_load_predicates(void **state, bool is_consecutive_map)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint64_t pred_buf_sram_addr, pred_buf_device_va, msg_long_dst_sram_addr,
			host_data_device_va;
	uint32_t *host_data, pred_buf_byte_idx, pred_buf_relative_bit, value;
	uint8_t *pred_buf, pred_id = 10;
	int rc, fd = tests_state->fd;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is not relevant in ARC mode, skipping\n");
		skip();
	}

	/* Goya doesn't support LOAD_AND_EXE packets */
	if (hltests_is_goya(fd)) {
		printf("Test is not relevant for Goya, skipping\n");
		skip();
	}

	/* Gaudi doesn't support LOAD_PRED with consecutive mapping */
	if (hltests_is_gaudi(fd) && is_consecutive_map) {
		printf("Test is not relevant for Gaudi, skipping\n");
		skip();
	}

	/* SRAM MAP (base + )
	 * 0x0    : 128 bytes for predicates data [P0-P31]
	 * 0x1000 : MSG_LONG destination
	 *
	 * Test description:
	 * 1. Load predicates with "pred_id" clear and verify that a dependent
	 *    MSG_LONG packet is NOT performed.
	 * 2. Load predicates with "pred_id" set and verify that a dependent
	 *    MSG_LONG packet is performed.
	 */

	/* Only P1-P31 are valid because LOAD_PRED command doesn't update P0 */
	assert_in_range(pred_id, 1, 31);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	pred_buf_sram_addr = hw_ip.sram_base_address;
	msg_long_dst_sram_addr = hw_ip.sram_base_address + 0x1000;

	/* Check alignment of predicates address to 128B */
	assert_int_equal((pred_buf_sram_addr & 0x7f), 0);

	pred_buf = hltests_allocate_host_mem(fd, 128, NOT_HUGE_MAP);
	assert_non_null(pred_buf);
	pred_buf_device_va = hltests_get_device_va_for_host_ptr(fd, pred_buf);

	host_data = hltests_allocate_host_mem(fd, 4, NOT_HUGE_MAP);
	assert_non_null(host_data);
	host_data_device_va = hltests_get_device_va_for_host_ptr(fd, host_data);

	if (is_consecutive_map) {
		pred_buf_byte_idx = pred_id / 8;
		pred_buf_relative_bit = pred_id % 8;
	} else {
		pred_buf_byte_idx = pred_id * 4;
		pred_buf_relative_bit = 0;
	}

	/* Load predicates with "pred_id" clear and verify that a dependent
	 * MSG_LONG packet is NOT performed.
	 */
	memset(pred_buf, 0, 128);
	value = load_predicates_and_test_msg_long(fd, pred_buf_sram_addr,
						pred_buf_device_va,
						msg_long_dst_sram_addr,
						host_data_device_va, pred_id,
						is_consecutive_map);
	assert_int_not_equal(*host_data, value);

	/* Load predicates with "pred_id" set and verify that a dependent
	 * MSG_LONG packet is performed.
	 */
	pred_buf[pred_buf_byte_idx] = 1 << pred_buf_relative_bit;
	value = load_predicates_and_test_msg_long(fd, pred_buf_sram_addr,
						pred_buf_device_va,
						msg_long_dst_sram_addr,
						host_data_device_va, pred_id,
						is_consecutive_map);
	assert_int_equal(*host_data, value);

	/* Cleanup */
	hltests_free_host_mem(fd, host_data);
	hltests_free_host_mem(fd, pred_buf);

	END_TEST;
}

VOID test_cs_load_pred_non_consecutive_map(void **state)
{
	END_TEST_FUNC(test_cs_load_predicates(state, false));
}

VOID test_cs_load_pred_consecutive_map(void **state)
{
	END_TEST_FUNC(test_cs_load_predicates(state, true));
}

VOID load_scalars_and_exe_4_rfs(int fd, uint64_t scalar_buf_sram_addr,
					uint64_t cb_sram_addr,
					uint64_t msg_long_dst_sram_addr,
					uint64_t host_data_device_va,
					bool is_separate_exe)
{
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t ddma_cb_size, dma_down_cb_size, value;
	struct hltests_cs_chunk execute_arr[2];
	struct hltests_pkt_info pkt_info;
	uint64_t ddma_cb_device_va, seq;
	void *ddma_cb, *dma_down_cb;
	uint16_t sob0, mon0;
	int rc;

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);

	/* Clear SOB0 */
	hltests_clear_sobs(fd, 1);

	/* DDMA CB: MSG_LONG + {1,2} x LOAD_AND_EXE + signal SOB0 */
	ddma_cb = hltests_create_cb(fd, SZ_4K, INTERNAL, cb_sram_addr);
	assert_non_null(ddma_cb);
	ddma_cb_device_va = hltests_get_device_va_for_host_ptr(fd, ddma_cb);
	ddma_cb_size = 0;

	/* Initialize the MSG_LONG destination in SRAM */
	hltests_fill_rand_values(&value, 4);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_long.address = msg_long_dst_sram_addr;
	pkt_info.msg_long.value = value;
	ddma_cb_size = hltests_add_msg_long_pkt(fd, ddma_cb, ddma_cb_size,
						&pkt_info);

	/* Load scalars data and execute the instruction with ETYPE=0 */

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.load_and_exe.src_addr = scalar_buf_sram_addr;
	pkt_info.load_and_exe.load = 1;
	pkt_info.load_and_exe.exe = is_separate_exe ? 0 : 1;
	pkt_info.load_and_exe.load_dst = DST_SCALARS;
	pkt_info.load_and_exe.pred_map = 0;
	pkt_info.load_and_exe.exe_type = ETYPE_ALL_OR_LOWER_RF;
	ddma_cb_size = hltests_add_load_and_exe_pkt(fd, ddma_cb, ddma_cb_size,
							&pkt_info);

	if (is_separate_exe) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.load_and_exe.src_addr = 0;
		pkt_info.load_and_exe.load = 0;
		pkt_info.load_and_exe.exe = 1;
		pkt_info.load_and_exe.load_dst = 0;
		pkt_info.load_and_exe.pred_map = 0;
		pkt_info.load_and_exe.exe_type = ETYPE_ALL_OR_LOWER_RF;
		ddma_cb_size = hltests_add_load_and_exe_pkt(fd, ddma_cb,
								ddma_cb_size,
								&pkt_info);
	}

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_SET;
	ddma_cb_size = hltests_add_write_to_sob_pkt(fd, ddma_cb, ddma_cb_size,
							&pkt_info);

	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_FALSE, ddma_cb_device_va,
				cb_sram_addr, ddma_cb_size,
				DMA_DIR_HOST_TO_SRAM);

	/* DMA DOWN CB: Fence on SOB0 */
	dma_down_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(dma_down_cb);
	dma_down_cb_size = 0;

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_down_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	dma_down_cb_size = hltests_add_monitor_and_fence(fd, dma_down_cb,
							dma_down_cb_size,
							&mon_and_fence_info);

	execute_arr[0].cb_ptr = ddma_cb;
	execute_arr[0].cb_size = ddma_cb_size;
	execute_arr[0].queue_index = hltests_get_ddma_qid(fd, 0, STREAM0);

	execute_arr[1].cb_ptr = dma_down_cb;
	execute_arr[1].cb_size = dma_down_cb_size;
	execute_arr[1].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Cleanup */
	hltests_destroy_cb(fd, dma_down_cb);
	hltests_destroy_cb(fd, ddma_cb);

	/* DMA MSG_LONG destination from SRAM to host */
	END_TEST_FUNC(hltests_dma_transfer(fd,
				hltests_get_dma_up_qid(fd, STREAM0),
				EB_FALSE, MB_FALSE, msg_long_dst_sram_addr,
				host_data_device_va, 4,
				DMA_DIR_SRAM_TO_HOST));
}

VOID test_cs_load_scalars_exe_4_rfs(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	uint64_t scalar_buf_sram_addr, scalar_buf_device_va, cb_sram_addr,
			msg_long_dst_sram_addr, host_data_device_va;
	uint32_t *host_data, value;
	uint8_t *scalar_buf;
	int rc, fd = tests_state->fd;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is not relevant in ARC mode, skipping\n");
		skip();
	}

	/* Goya doesn't support LOAD_AND_EXE packets */
	if (hltests_is_goya(fd)) {
		printf("Test is not relevant for Goya, skipping\n");
		skip();
	}

	/* Skip for Gaudi due to failures which are under debug [H3-2092] */
	if (hltests_is_gaudi(fd) && !hltests_is_simulator(fd)) {
		printf("Test currently doesn't support Gaudi ASIC, skipping\n");
		skip();
	}

	/* SRAM MAP (base + )
	 * 0x0    : 4 x 4 bytes for scalars data [R0-R3]
	 * 0x1000 : MSG_LONG destination
	 * 0x2000 : Internal CB
	 *
	 * Test description:
	 * 1. In a single LOAD_AND_EXE packet, load scalars data that include a
	 *    MSG_LONG packet (16B), and execute the instruction with ETYPE=0
	 *    (4 RFs).
	 * 2. Verify that the MSG_LONG destination is updated as expected.
	 * 3. Load scalars data that includes a MSG_LONG packet (16B).
	 * 4. In a different LOAD_AND_EXE packet, execute the instruction with
	 *    ETYPE=0 (4 RFs).
	 * 5. Verify that the MSG_LONG destination is updated as expected.
	 */

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	scalar_buf_sram_addr = hw_ip.sram_base_address;
	msg_long_dst_sram_addr = hw_ip.sram_base_address + 0x1000;
	cb_sram_addr = hw_ip.sram_base_address + 0x2000;

	/* Check alignment of scalars address to 128B */
	assert_int_equal((scalar_buf_sram_addr & 0x7f), 0);

	scalar_buf = hltests_allocate_host_mem(fd, 16, NOT_HUGE_MAP);
	assert_non_null(scalar_buf);
	scalar_buf_device_va =
			hltests_get_device_va_for_host_ptr(fd, scalar_buf);

	host_data = hltests_allocate_host_mem(fd, 4, NOT_HUGE_MAP);
	assert_non_null(host_data);
	host_data_device_va = hltests_get_device_va_for_host_ptr(fd, host_data);

	/* Prepare scalars buffer and DMA it from host to SRAM */
	hltests_fill_rand_values(&value, 4);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_long.address = msg_long_dst_sram_addr;
	pkt_info.msg_long.value = value;
	hltests_add_msg_long_pkt(fd, scalar_buf, 0, &pkt_info);

	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_FALSE, scalar_buf_device_va,
				scalar_buf_sram_addr, 16,
				DMA_DIR_HOST_TO_SRAM);

	/* Load and execute in a single packet */
	load_scalars_and_exe_4_rfs(fd, scalar_buf_sram_addr, cb_sram_addr,
					msg_long_dst_sram_addr,
					host_data_device_va, false);
	assert_int_equal(*host_data, value);

	/* Load and execute in separate packets */
	load_scalars_and_exe_4_rfs(fd, scalar_buf_sram_addr, cb_sram_addr,
					msg_long_dst_sram_addr,
					host_data_device_va, true);
	assert_int_equal(*host_data, value);

	/* Cleanup */
	hltests_free_host_mem(fd, host_data);
	hltests_free_host_mem(fd, scalar_buf);

	END_TEST;
}

VOID load_scalars_and_exe_2_rfs(int fd, uint64_t scalar_buf_sram_addr,
					uint64_t cb_sram_addr, uint16_t sob0,
					uint16_t mon0, bool is_upper_rfs,
					bool is_separate_exe)
{
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t ddma_cb_size, dma_down_cb_size;
	struct hltests_cs_chunk execute_arr[2];
	struct hltests_pkt_info pkt_info;
	enum hl_tests_exe_type exe_type;
	uint64_t ddma_cb_device_va, seq;
	void *ddma_cb, *dma_down_cb;
	int rc;

	exe_type = is_upper_rfs ? ETYPE_UPPER_RF : ETYPE_ALL_OR_LOWER_RF;

	/* Clear SOB0 */
	hltests_clear_sobs(fd, 1);

	/* DDMA CB: {1,2} x LOAD_AND_EXE + signal SOB0 */
	ddma_cb = hltests_create_cb(fd, SZ_4K, INTERNAL, cb_sram_addr);
	assert_non_null(ddma_cb);
	ddma_cb_device_va = hltests_get_device_va_for_host_ptr(fd, ddma_cb);
	ddma_cb_size = 0;

	/* Load scalars data and execute the instruction */

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.load_and_exe.src_addr = scalar_buf_sram_addr;
	pkt_info.load_and_exe.load = 1;
	pkt_info.load_and_exe.exe = is_separate_exe ? 0 : 1;
	pkt_info.load_and_exe.load_dst = DST_SCALARS;
	pkt_info.load_and_exe.pred_map = 0;
	pkt_info.load_and_exe.exe_type = exe_type;
	ddma_cb_size = hltests_add_load_and_exe_pkt(fd, ddma_cb, ddma_cb_size,
							&pkt_info);

	if (is_separate_exe) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.load_and_exe.src_addr = 0;
		pkt_info.load_and_exe.load = 0;
		pkt_info.load_and_exe.exe = 1;
		pkt_info.load_and_exe.load_dst = 0;
		pkt_info.load_and_exe.pred_map = 0;
		pkt_info.load_and_exe.exe_type = exe_type;
		ddma_cb_size = hltests_add_load_and_exe_pkt(fd, ddma_cb,
								ddma_cb_size,
								&pkt_info);
	}

	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_FALSE, ddma_cb_device_va,
				cb_sram_addr, ddma_cb_size,
				DMA_DIR_HOST_TO_SRAM);

	/* DMA DOWN CB: Fence on SOB0 */
	dma_down_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(dma_down_cb);
	dma_down_cb_size = 0;

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_down_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	dma_down_cb_size = hltests_add_monitor_and_fence(fd, dma_down_cb,
							dma_down_cb_size,
							&mon_and_fence_info);

	execute_arr[0].cb_ptr = ddma_cb;
	execute_arr[0].cb_size = ddma_cb_size;
	execute_arr[0].queue_index = hltests_get_ddma_qid(fd, 0, STREAM0);

	execute_arr[1].cb_ptr = dma_down_cb;
	execute_arr[1].cb_size = dma_down_cb_size;
	execute_arr[1].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Cleanup */
	hltests_destroy_cb(fd, dma_down_cb);
	hltests_destroy_cb(fd, ddma_cb);

	END_TEST;
}

VOID test_cs_load_scalars_exe_2_rfs(void **state, bool is_upper_rfs)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	uint64_t scalar_buf_sram_addr, scalar_buf_device_va, cb_sram_addr;
	uint32_t scalar_buf_offset;
	uint16_t sob0, mon0;
	uint8_t *scalar_buf;
	int rc, fd = tests_state->fd;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is not relevant in ARC mode, skipping\n");
		skip();
	}

	/* Goya doesn't support LOAD_AND_EXE packets */
	if (hltests_is_goya(fd)) {
		printf("Test is not relevant for Goya, skipping\n");
		skip();
	}

	/* SRAM MAP (base + )
	 * 0x0    : 4 x 4 bytes for scalars data [R0-R3]
	 * 0x1000 : Internal CB
	 *
	 * Test description:
	 * 1. In a single LOAD_AND_EXE packet, load scalars data that includes a
	 *    MSG_SHORT packet (8B) that signals SOB0, and execute the
	 *    instruction with ETYPE value according to "is_upper_rfs".
	 * 2. Fence on SOB0.
	 * 3. Load scalars data that includes a MSG_SHORT packet (8B) that
	 *    signals SOB0.
	 * 4. In a different LOAD_AND_EXE packet, execute the instruction with
	 *    ETYPE value according to "is_upper_rfs".
	 * 5. Fence on SOB0.
	 */

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	scalar_buf_sram_addr = hw_ip.sram_base_address;
	cb_sram_addr = hw_ip.sram_base_address + 0x1000;

	/* Check alignment of scalars address to 128B */
	assert_int_equal((scalar_buf_sram_addr & 0x7f), 0);

	scalar_buf = hltests_allocate_host_mem(fd, 16, NOT_HUGE_MAP);
	assert_non_null(scalar_buf);
	scalar_buf_device_va =
			hltests_get_device_va_for_host_ptr(fd, scalar_buf);

	/* Prepare scalars buffer and DMA it from host to SRAM */
	scalar_buf_offset = is_upper_rfs ? 8 : 0;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = sob0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_SET;
	hltests_add_write_to_sob_pkt(fd, scalar_buf, scalar_buf_offset,
					&pkt_info);

	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_FALSE, scalar_buf_device_va,
				scalar_buf_sram_addr, 16,
				DMA_DIR_HOST_TO_SRAM);

	/* Load and execute in a single packet */
	load_scalars_and_exe_2_rfs(fd, scalar_buf_sram_addr, cb_sram_addr, sob0,
					mon0, is_upper_rfs, false);

	/* Load and execute in separate packets */
	load_scalars_and_exe_2_rfs(fd, scalar_buf_sram_addr, cb_sram_addr, sob0,
					mon0, is_upper_rfs, true);

	/* Cleanup */
	hltests_free_host_mem(fd, scalar_buf);

	END_TEST;
}

VOID test_cs_load_scalars_exe_lower_2_rfs(void **state)
{
	END_TEST_FUNC(test_cs_load_scalars_exe_2_rfs(state, false));
}

VOID test_cs_load_scalars_exe_upper_2_rfs(void **state)
{
	END_TEST_FUNC(test_cs_load_scalars_exe_2_rfs(state, true));
}

#define CB_LIST_LENGTH	10

VOID test_cs_cb_list(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t cb_sram_addr, int_cb_device_va[CB_LIST_LENGTH],
			index_sram_addr, table_sram_addr, table_device_va, seq;
	uint32_t ext_cb_size[2], int_cb_size[CB_LIST_LENGTH], table_size,
			entry_size, index_factor = 1;
	struct hltests_monitor_and_fence mon_and_fence_info;
	enum hl_tests_size_desc size_desc = ENTRY_SIZE_16B;
	void *ext_cb[2], *int_cb[CB_LIST_LENGTH], *table;
	struct hltests_cs_chunk execute_arr[2];
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info hw_ip;
	int rc, fd = tests_state->fd, i;
	uint16_t sob0, mon0;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is irrelevant when running in ARC mode, skipping\n");
		skip();
	}

	/* Goya/Gaudi don't support CB_LIST packets */
	if (hltests_is_goya(fd) || hltests_is_gaudi(fd)) {
		printf("Test is not relevant for Goya/Gaudi, skipping\n");
		skip();
	}

	/* SRAM MAP (base + )
	 * 0x0    : CB_LIST index
	 * 0x1000 : CB_LIST table
	 * 0x9000 : Internal CBs
	 *
	 * "N" = CB_LIST_LENGTH
	 *
	 * Test description:
	 * 1. DMA to SRAM the internal CBs:
	 *      0..(N-1) - Increment SOB_0 + increment index value + CB_LIST
	 *      N        - Increment SOB_0
	 * 2. DMA the CB_LIST table to SRAM.
	 *      Each table entry holds CP_DMA of the corresponding internal CB
	 *      to the upper CP.
	 * 3. QMAN #0: MSG_LONG to set index to 0 + CB_LIST
	 * 4. QMAN #1: Fence on SOB0 until it has a value of N.
	 */

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	index_sram_addr = hw_ip.sram_base_address;
	table_sram_addr = hw_ip.sram_base_address + 0x1000;
	cb_sram_addr = hw_ip.sram_base_address + 0x9000;

	if (size_desc == ENTRY_SIZE_16B)
		entry_size = 16;
	else
		fail_msg("CB_LIST entry size of 32 bytes is not supported");

	/* Verify that CB_LIST table is large enough to hold all entries */
	table_size = CB_LIST_LENGTH * entry_size * index_factor;
	assert_true((cb_sram_addr - table_sram_addr) > table_size);

	/* Prepare internal CBs */
	for (i = 0 ; i < CB_LIST_LENGTH ; i++) {
		uint64_t sram_addr = cb_sram_addr + i * SZ_4K;

		int_cb[i] = hltests_create_cb(fd, SZ_4K, INTERNAL, sram_addr);
		assert_non_null(int_cb[i]);
		int_cb_device_va[i] =
			hltests_get_device_va_for_host_ptr(fd, int_cb[i]);
		int_cb_size[i] = 0;

		/* Increment SOB0 */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.write_to_sob.sob_id = sob0;
		pkt_info.write_to_sob.value = 1;
		pkt_info.write_to_sob.mode = SOB_ADD;
		int_cb_size[i] = hltests_add_write_to_sob_pkt(fd, int_cb[i],
								int_cb_size[i],
								&pkt_info);

		/* No index update and CB_LIST in the Nth internal CB */
		if (i != (CB_LIST_LENGTH - 1)) {

			/* Update value in index memory */
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_TRUE;
			pkt_info.msg_long.address = index_sram_addr;
			pkt_info.msg_long.value = (i + 1) * index_factor;
			int_cb_size[i] = hltests_add_msg_long_pkt(fd, int_cb[i],
								int_cb_size[i],
								&pkt_info);

			/* CB_LIST command to run next table entry */
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_TRUE;
			pkt_info.cb_list.table_addr = table_sram_addr;
			pkt_info.cb_list.index_addr = index_sram_addr;
			pkt_info.cb_list.size_desc = size_desc;
			int_cb_size[i] = hltests_add_cb_list_pkt(fd, int_cb[i],
								int_cb_size[i],
								&pkt_info);
		}

		hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
					EB_FALSE, MB_FALSE, int_cb_device_va[i],
					sram_addr, int_cb_size[i],
					DMA_DIR_HOST_TO_SRAM);
	}

	/* Prepare CB_LIST table */
	table = hltests_allocate_host_mem(fd, table_size, NOT_HUGE_MAP);
	assert_non_null(table);
	table_device_va = hltests_get_device_va_for_host_ptr(fd, table);

	for (i = 0 ; i < CB_LIST_LENGTH ; i++) {
		uint64_t sram_addr = cb_sram_addr + i * SZ_4K;
		uint32_t entry_offset = i * entry_size * index_factor;

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.cp_dma.src_addr = sram_addr;
		pkt_info.cp_dma.size = int_cb_size[i];
		pkt_info.cp_dma.upper_cp = 1;
		hltests_add_cp_dma_pkt(fd, table, entry_offset, &pkt_info);
	}

	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_FALSE, table_device_va,
				table_sram_addr, table_size,
				DMA_DIR_HOST_TO_SRAM);

	/* Clear SOB0 */
	hltests_clear_sobs(fd, 1);

	/* External CB #0: Initialize index value + CB_LIST */
	ext_cb[0] = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(ext_cb[0]);
	ext_cb_size[0] = 0;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_long.address = index_sram_addr;
	pkt_info.msg_long.value = 0;
	ext_cb_size[0] = hltests_add_msg_long_pkt(fd, ext_cb[0], ext_cb_size[0],
							&pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.cb_list.table_addr = table_sram_addr;
	pkt_info.cb_list.index_addr = index_sram_addr;
	pkt_info.cb_list.size_desc = size_desc;
	ext_cb_size[0] = hltests_add_cb_list_pkt(fd, ext_cb[0], ext_cb_size[0],
							&pkt_info);

	/* External CB #1: Fence on SOB0 */
	ext_cb[1] = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(ext_cb[1]);
	ext_cb_size[1] = 0;

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = CB_LIST_LENGTH;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	ext_cb_size[1] = hltests_add_monitor_and_fence(fd, ext_cb[1],
							ext_cb_size[1],
							&mon_and_fence_info);

	execute_arr[0].cb_ptr = ext_cb[0];
	execute_arr[0].cb_size = ext_cb_size[0];
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	execute_arr[1].cb_ptr = ext_cb[1];
	execute_arr[1].cb_size = ext_cb_size[1];
	execute_arr[1].queue_index = hltests_get_dma_up_qid(fd, STREAM0);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Cleanup */
	hltests_destroy_cb(fd, ext_cb[1]);
	hltests_destroy_cb(fd, ext_cb[0]);
	hltests_free_host_mem(fd, table);
	for (i = 0 ; i < CB_LIST_LENGTH ; i++)
		hltests_destroy_cb(fd, int_cb[i]);

	END_TEST;
}

struct cb_list_thread_params {
	pthread_barrier_t *barrier;
	enum hl_tests_size_desc size_desc;
	uint64_t index_sram_addr;
	uint64_t table_sram_addr;
	uint16_t sob[2];
	uint16_t mon[2];
	int fd;
	int iterations;
};

static void *cb_list_thread_0_start(void *args)
{
	struct cb_list_thread_params *params =
			(struct cb_list_thread_params *) args;
	struct hltests_pkt_info pkt_info;
	int rc, fd = params->fd, i;
	uint32_t cb_size;
	void *cb;

	/* Initialize index value + CB_LIST */
	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	if (!cb) {
		printf("Thread #0: failed to create CB\n");
		return NULL;
	}
	cb_size = 0;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.msg_long.address = params->index_sram_addr;
	pkt_info.msg_long.value = 0;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.cb_list.table_addr = params->table_sram_addr;
	pkt_info.cb_list.index_addr = params->index_sram_addr;
	pkt_info.cb_list.size_desc = params->size_desc;
	cb_size = hltests_add_cb_list_pkt(fd, cb, cb_size, &pkt_info);

	/*
	 * PTHREAD_BARRIER_SERIAL_THREAD is returned to one unspecified thread
	 * and zero is returned to each of the remaining threads.
	 */
	rc = pthread_barrier_wait(params->barrier);
	if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD)
		return NULL;

	for (i = 0 ; i < params->iterations ; i++)
		hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);

	/* Cleanup */
	hltests_destroy_cb(fd, cb);

	return args;
}

static void *cb_list_thread_1_start(void *args)
{
	struct cb_list_thread_params *params =
			(struct cb_list_thread_params *) args;
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t cb_size, sob_target_val = 7;
	struct hltests_pkt_info pkt_info;
	int rc, fd = params->fd, i;
	void *cb;

	/* Zero SOB and corrupt index value to allegedly interfere thread 0.
	 * Increment SOB1 x "sob_target_val.
	 * Fence on SOB1 + Clear SOB1.
	 */
	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	if (!cb) {
		printf("Thread #1: failed to create CB\n");
		return NULL;
	}
	cb_size = 0;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = params->sob[0];
	pkt_info.write_to_sob.value = 0;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = params->index_sram_addr;
	pkt_info.msg_long.value = 0xffffffff;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	for (i = 0 ; i < sob_target_val ; i++) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.sob_id = params->sob[1];
		pkt_info.write_to_sob.value = 1;
		pkt_info.write_to_sob.mode = SOB_ADD;
		cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size,
							&pkt_info);
	}

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_down_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = params->sob[1];
	mon_and_fence_info.mon_id = params->mon[1];
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = sob_target_val;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_size = hltests_add_monitor_and_fence(fd, cb, cb_size,
						&mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = params->sob[1];
	pkt_info.write_to_sob.value = 0;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

	/*
	 * PTHREAD_BARRIER_SERIAL_THREAD is returned to one unspecified thread
	 * and zero is returned to each of the remaining threads.
	 */
	rc = pthread_barrier_wait(params->barrier);
	if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD)
		return NULL;

	for (i = 0 ; i < params->iterations ; i++)
		hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);

	/* Cleanup */
	hltests_destroy_cb(fd, cb);

	return args;
}

VOID test_cs_cb_list_with_parallel_pqe(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t index_sram_addr, table_sram_addr, table_device_va,
			cb_sram_addr, int_cb_device_va[CB_LIST_LENGTH];
	uint32_t int_cb_size[CB_LIST_LENGTH], table_size, entry_size,
			index_factor = 1;
	struct hltests_monitor_and_fence mon_and_fence_info;
	enum hl_tests_size_desc size_desc = ENTRY_SIZE_16B;
	struct cb_list_thread_params thread_params[2];
	void *int_cb[CB_LIST_LENGTH], *table, *retval;
	uint32_t cb_list_threads_itr[2] = {100, 150};
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info hw_ip;
	int rc, fd = tests_state->fd, i;
	pthread_barrier_t barrier;
	uint16_t sob[2], mon[2];
	pthread_t thread_id[2];

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is irrelevant when running in ARC mode, skipping\n");
		skip();
	}

	/* Goya/Gaudi don't support CB_LIST packets */
	if (hltests_is_goya(fd) || hltests_is_gaudi(fd)) {
		printf("Test is not relevant for Goya/Gaudi, skipping\n");
		skip();
	}

	if (hltests_is_pldm(fd)) {
		cb_list_threads_itr[0] = 10;
		cb_list_threads_itr[1] = 15;
	}

	/* SRAM MAP (base + )
	 * 0x0    : CB_LIST index
	 * 0x1000 : CB_LIST table
	 * 0x9000 : Internal CBs
	 *
	 * "N" = CB_LIST_LENGTH
	 *
	 * SOB0 is used by thread #0.
	 * SOB1 is used by thread #1.
	 *
	 * Test description:
	 * 1. DMA to SRAM the internal CBs:
	 *      0..(N-1) - (1) Zero SOB1 -> interfere thread #1
	 *                 (2) Increment SOB0
	 *                 (3) Increment index value
	 *                 (4) CB_LIST
	 *      N - (1) Zero SOB1 -> interfere thread #1
	 *          (2) Increment SOB0
	 *          (3) Fence on SOB0 until it has a value of N
	 *          (4) Clear SOB0
	 * 2. DMA the CB_LIST table to SRAM.
	 *      Each table entry holds CP_DMA of the corresponding internal CB
	 *      to the upper CP.
	 * 3. Thread #1 - MSG_LONG to set index to 0 + CB_LIST
	 *    Thread #2 - (1) Zero SOB0 -> interfere thread #0
	 *                (2) Corrupt index value -> interfere thread #0
	 *                (3) M x Increment SOB1
	 *                (4) Fence on SOB1 until it has a value of M
	 *                (5) Clear SOB1
	 *
	 * Due to QMAN "PQ-CQ blocking" mode:
	 * 1. There should be no CQ-CP deadlock.
	 * 2. The interfering commands should not be harmful.
	 * 3. The QMAN auto completion should be in order.
	 */

	sob[0] = hltests_get_first_avail_sob(fd);
	sob[1] = hltests_get_first_avail_sob(fd) + 1;
	mon[0] = hltests_get_first_avail_mon(fd);
	mon[1] = hltests_get_first_avail_mon(fd) + 1;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	index_sram_addr = hw_ip.sram_base_address;
	table_sram_addr = hw_ip.sram_base_address + 0x1000;
	cb_sram_addr = hw_ip.sram_base_address + 0x9000;

	if (size_desc == ENTRY_SIZE_16B)
		entry_size = 16;
	else
		fail_msg("CB_LIST entry size of 32 bytes is not supported");

	/* Verify that CB_LIST table is large enough to hold all entries */
	table_size = CB_LIST_LENGTH * entry_size * index_factor;
	assert_true((cb_sram_addr - table_sram_addr) > table_size);

	/* Prepare internal CBs */
	for (i = 0 ; i < CB_LIST_LENGTH ; i++) {
		uint64_t sram_addr = cb_sram_addr + i * SZ_4K;

		int_cb[i] = hltests_create_cb(fd, SZ_4K, INTERNAL, sram_addr);
		assert_non_null(int_cb[i]);
		int_cb_device_va[i] =
			hltests_get_device_va_for_host_ptr(fd, int_cb[i]);
		int_cb_size[i] = 0;

		/* Zero SOB1 to allegedly interfere thread #1 */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.write_to_sob.sob_id = sob[1];
		pkt_info.write_to_sob.value = 0;
		pkt_info.write_to_sob.mode = SOB_SET;
		int_cb_size[i] = hltests_add_write_to_sob_pkt(fd, int_cb[i],
								int_cb_size[i],
								&pkt_info);

		/* Increment SOB0 */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.sob_id = sob[0];
		pkt_info.write_to_sob.value = 1;
		pkt_info.write_to_sob.mode = SOB_ADD;
		int_cb_size[i] = hltests_add_write_to_sob_pkt(fd, int_cb[i],
								int_cb_size[i],
								&pkt_info);

		/* Internal CB #0..(N-1) - Increment index value + CB_LIST
		 * Internal CB #N        - Fence on SOB0 + Clear SOB0
		 */
		if (i != (CB_LIST_LENGTH - 1)) {

			/* Update value in index memory */
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_TRUE;
			pkt_info.msg_long.address = index_sram_addr;
			pkt_info.msg_long.value = (i + 1) * index_factor;
			int_cb_size[i] = hltests_add_msg_long_pkt(fd, int_cb[i],
								int_cb_size[i],
								&pkt_info);

			/* CB_LIST command to run next table entry */
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_TRUE;
			pkt_info.cb_list.table_addr = table_sram_addr;
			pkt_info.cb_list.index_addr = index_sram_addr;
			pkt_info.cb_list.size_desc = size_desc;
			int_cb_size[i] = hltests_add_cb_list_pkt(fd, int_cb[i],
								int_cb_size[i],
								&pkt_info);
		} else {
			memset(&mon_and_fence_info, 0,
					sizeof(mon_and_fence_info));
			mon_and_fence_info.queue_id =
					hltests_get_dma_down_qid(fd, STREAM0);
			mon_and_fence_info.cmdq_fence = false;
			mon_and_fence_info.sob_id = sob[0];
			mon_and_fence_info.mon_id = mon[0];
			mon_and_fence_info.mon_address = 0;
			mon_and_fence_info.sob_val = CB_LIST_LENGTH;
			mon_and_fence_info.dec_fence = true;
			mon_and_fence_info.mon_payload = 1;
			int_cb_size[i] = hltests_add_monitor_and_fence(fd,
							int_cb[i],
							int_cb_size[i],
							&mon_and_fence_info);

			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_TRUE;
			pkt_info.write_to_sob.sob_id = sob[0];
			pkt_info.write_to_sob.value = 0;
			pkt_info.write_to_sob.mode = SOB_SET;
			int_cb_size[i] = hltests_add_write_to_sob_pkt(fd,
							int_cb[i],
							int_cb_size[i],
							&pkt_info);
		}

		hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
					EB_FALSE, MB_FALSE, int_cb_device_va[i],
					sram_addr, int_cb_size[i],
					DMA_DIR_HOST_TO_SRAM);
	}

	/* Prepare CB_LIST table */
	table = hltests_allocate_host_mem(fd, table_size, NOT_HUGE_MAP);
	assert_non_null(table);
	table_device_va = hltests_get_device_va_for_host_ptr(fd, table);

	for (i = 0 ; i < CB_LIST_LENGTH ; i++) {
		uint64_t sram_addr = cb_sram_addr + i * SZ_4K;
		uint32_t entry_offset = i * entry_size * index_factor;

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.cp_dma.src_addr = sram_addr;
		pkt_info.cp_dma.size = int_cb_size[i];
		pkt_info.cp_dma.upper_cp = 1;
		hltests_add_cp_dma_pkt(fd, table, entry_offset, &pkt_info);
	}

	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_FALSE, table_device_va,
				table_sram_addr, table_size,
				DMA_DIR_HOST_TO_SRAM);

	/* Clear SOB0 & SOB1 */
	hltests_clear_sobs(fd, 2);

	rc = pthread_barrier_init(&barrier, NULL, 2);
	assert_int_equal(rc, 0);

	for (i = 0 ; i < 2 ; i++) {
		thread_params[i].barrier = &barrier;
		thread_params[i].size_desc = size_desc;
		thread_params[i].index_sram_addr = index_sram_addr;
		thread_params[i].table_sram_addr = table_sram_addr;
		thread_params[i].sob[0] = sob[0];
		thread_params[i].sob[1] = sob[1];
		thread_params[i].mon[0] = mon[0];
		thread_params[i].mon[1] = mon[1];
		thread_params[i].fd = fd;
		thread_params[i].iterations = cb_list_threads_itr[i];
	}

	/* Create and execute threads */
	rc = pthread_create(&thread_id[0], NULL, cb_list_thread_0_start,
				&thread_params[0]);
	assert_int_equal(rc, 0);
	rc = pthread_create(&thread_id[1], NULL, cb_list_thread_1_start,
				&thread_params[1]);
	assert_int_equal(rc, 0);

	/* Wait for the termination of the threads */
	for (i = 0 ; i < 2 ; i++) {
		rc = pthread_join(thread_id[i], &retval);
		assert_int_equal(rc, 0);
		assert_non_null(retval);
	}

	/* Cleanup */
	pthread_barrier_destroy(&barrier);
	hltests_free_host_mem(fd, table);
	for (i = 0 ; i < CB_LIST_LENGTH ; i++)
		hltests_destroy_cb(fd, int_cb[i]);

	END_TEST;
}

#define CS_DROP_NUM_CS		256
#define CS_DROP_NUM_CB_PER_CS	256

VOID test_cs_drop(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[CS_DROP_NUM_CB_PER_CS];
	struct hl_info_cs_counters info_start, info_end;
	struct hlthunk_wait_for_signal_data wait_for_signal;
	struct hlthunk_signal_in sig_in;
	struct hlthunk_signal_out sig_out;
	struct hlthunk_wait_in wait_in;
	struct hlthunk_wait_out wait_out;
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info hw_ip;
	void *src_data, *cb[CS_DROP_NUM_CB_PER_CS];
	uint64_t drop_cnt, src_data_device_va, device_data_address, seq;
	uint32_t queue_down, queue_up, cb_size = 0;
	int rc, i, j, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	if (hltests_is_simulator(fd)) {
		printf("Test is not relevant for Simulator, skipping\n");
		skip();
	}

	if (hltests_is_pldm(fd)) {
		printf("Test is not relevant for PLDM, skipping\n");
		skip();
	}

	if (hltests_is_goya(fd)) {
		printf("Test is  not supported on Goya, skipping.\n");
		skip();
	}

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is not supported for ARCs, skipping.\n");
		skip();
	}

	rc = hlthunk_get_cs_counters_info(fd, &info_start);
	assert_int_equal(rc, 0);

	queue_down = hltests_get_dma_down_qid(fd, STREAM0);
	queue_up = hltests_get_dma_up_qid(fd, STREAM0);
	src_data = hltests_allocate_host_mem(fd, 0x100000, NOT_HUGE_MAP);
	device_data_address = hw_ip.sram_base_address + 0x1000;
	src_data_device_va = hltests_get_device_va_for_host_ptr(fd, src_data);

	memset(&sig_in, 0, sizeof(sig_in));
	memset(&sig_out, 0, sizeof(sig_out));
	memset(&wait_in, 0, sizeof(wait_in));
	memset(&wait_out, 0, sizeof(wait_out));
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = src_data_device_va;
	pkt_info.dma.dst_addr = device_data_address;
	pkt_info.dma.size = 0x100000;
	pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;

	for (j = 0 ; j < CS_DROP_NUM_CB_PER_CS ; j++) {
		cb[j] = hltests_create_cb(fd, 512, EXTERNAL, 0);
		assert_non_null(cb[j]);

		cb_size = hltests_add_dma_pkt(fd, cb[j], 0, &pkt_info);
		execute_arr[j].cb_ptr = cb[j];
		execute_arr[j].cb_size = cb_size;
		execute_arr[j].queue_index =
				hltests_get_dma_down_qid(fd, STREAM0);
	}

	/*
	 * Submit multiple command submissions containing DMA transfers.
	 * In between those command submissions, submit a couple of sync stream
	 * command submissions: 'signal_submission' and 'wait_for_signal'
	 * Statistically 1% of the sync stream command submissions
	 * will be dropped
	 */
	for (i = 0 ; i < CS_DROP_NUM_CS ; i++) {
		rc = hltests_submit_cs(fd, NULL, 0, execute_arr,
				CS_DROP_NUM_CB_PER_CS, 0, &seq);
		assert_int_equal(rc, 0);

		sig_in.queue_index = queue_down;
		rc = hlthunk_signal_submission(fd, &sig_in, &sig_out);
		assert_int_equal(rc, 0);

		wait_for_signal.queue_index = queue_up;
		wait_for_signal.signal_seq_arr = &sig_out.seq;
		wait_for_signal.signal_seq_nr = 1;
		wait_in.hlthunk_wait_for_signal = (uint64_t *)&wait_for_signal;
		wait_in.num_wait_for_signal = 1;
		rc = hlthunk_wait_for_signal(fd, &wait_in, &wait_out);
		assert_int_equal(rc, 0);
	}

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hlthunk_get_cs_counters_info(fd, &info_end);
	assert_int_equal(rc, 0);

	drop_cnt = info_end.ctx_queue_full_drop_cnt
			- info_start.ctx_queue_full_drop_cnt;
	assert_int_equal(!drop_cnt, 0);

	for (j = 0 ; j < CS_DROP_NUM_CB_PER_CS ; j++) {
		rc = hltests_destroy_cb(fd, cb[j]);
		assert_int_equal(rc, 0);
	}

	rc = hltests_free_host_mem(fd, src_data);
	assert_int_equal(rc, 0);

	END_TEST;
}

#define NANO_ONE_SEC 1000000000ull
#define NANO_TWO_SEC 2000000000ull

VOID test_wait_for_cs_with_timestamp(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[2];
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size = 0;
	uint32_t status = 0;
	uint64_t seq = 0;
	uint64_t timestamp[2];
	void *cb[2];
	int rc, i, fd = tests_state->fd;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is irrelevant when running in ARC mode, skipping\n");
		skip();
	}

	for (i = 0; i < 2; i++) {
		cb[i] = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
		assert_non_null(cb[i]);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		cb_size = hltests_add_nop_pkt(fd, cb[i], 0, &pkt_info);

		execute_arr[i].cb_ptr = cb[i];
		execute_arr[i].cb_size = cb_size;
		execute_arr[i].queue_index =
				hltests_get_dma_down_qid(fd, STREAM0);
	}

	for (i = 0; i < 2; i++) {
		rc = hltests_submit_cs(fd, NULL, 0, &(execute_arr[i]), 1,
					HL_CS_FLAGS_TIMESTAMP, &seq);
		assert_int_equal(rc, 0);

		do {
			rc = hlthunk_wait_for_cs_with_timestamp(fd, seq,
					WAIT_FOR_CS_DEFAULT_TIMEOUT, &status,
					&(timestamp[i]));
			assert_int_equal(rc, 0);
		} while (status == HL_WAIT_CS_STATUS_BUSY);

		if (i == 0)
			sleep(1);
	}

	assert_in_range((timestamp[1] - timestamp[0]), NANO_ONE_SEC,
			NANO_TWO_SEC);

	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_destroy_cb(fd, cb[i]);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_wait_for_cs_with_timestamp_status_gone(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[SZ_32K];
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size = 0;
	uint32_t status = 0;
	uint64_t seq[SZ_32K];
	uint64_t timestamp[2];
	void *cb[SZ_32K];
	int rc, i, fd = tests_state->fd;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is irrelevant when running in ARC mode, skipping\n");
		skip();
	}

	/* Create lots of commands */
	for (i = 0; i < SZ_32K; i++) {
		cb[i] = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
		assert_non_null(cb[i]);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		cb_size = hltests_add_nop_pkt(fd, cb[i], 0, &pkt_info);

		execute_arr[i].cb_ptr = cb[i];
		execute_arr[i].cb_size = cb_size;
		execute_arr[i].queue_index =
				hltests_get_dma_down_qid(fd, STREAM0);
	}

	/* Submit lots of commands */
	for (i = 0; i < SZ_32K; i++) {
		rc = hltests_submit_cs(fd, NULL, 0, &(execute_arr[i]), 1,
					i < 2 ? HL_CS_FLAGS_TIMESTAMP : 0, &seq[i]);
		if (!i)
			sleep(1);
		assert_int_equal(rc, 0);
	}

	/* Wait for the last command */
	do {
		rc = hlthunk_wait_for_cs(fd, seq[SZ_32K-1],
				WAIT_FOR_CS_DEFAULT_TIMEOUT, &status);
		assert_int_equal(rc, 0);
	} while (status == HL_WAIT_CS_STATUS_BUSY);
	assert_int_equal(status, HL_WAIT_CS_STATUS_COMPLETED);

	/* Wait for the first command only, make sure it is not lost */
	do {
		rc = hlthunk_wait_for_cs_with_timestamp(fd, seq[0],
				WAIT_FOR_CS_DEFAULT_TIMEOUT, &status,
				&timestamp[0]);
		assert_int_equal(rc, 0);
	} while (status == HL_WAIT_CS_STATUS_BUSY);
	assert_int_equal(status, HL_WAIT_CS_STATUS_COMPLETED);

	/* Same for the second command */
	do {
		rc = hlthunk_wait_for_cs_with_timestamp(fd, seq[1],
				WAIT_FOR_CS_DEFAULT_TIMEOUT, &status,
				&timestamp[1]);
		assert_int_equal(rc, 0);
	} while (status == HL_WAIT_CS_STATUS_BUSY);
	assert_int_equal(status, HL_WAIT_CS_STATUS_COMPLETED);

	/* Verify the timestamp values actually make sense */
	assert_in_range((timestamp[1] - timestamp[0]), 1, NANO_TWO_SEC);

	for (i = 0 ; i < SZ_32K ; i++) {
		rc = hltests_destroy_cb(fd, cb[i]);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

struct staged_cs_thread_params {
	uint64_t sram_addr;
	uint32_t sob_id;
	uint32_t mon_id;
	uint32_t dma_size;
	uint32_t dma_channel;
	int fd;
};

static void *test_staged_submission(void *args)
{
	struct staged_cs_thread_params *params =
			(struct staged_cs_thread_params *) args;
	struct hltests_monitor_and_fence mon_and_fence_info;
	struct hltests_cs_chunk execute_chunk, restore_chunk;
	struct hltests_pkt_info pkt_info;
	uint32_t flags, size = params->dma_size, cb_size[2],
		common_cb_buf_size = 0, cp_dma_cb_size = 0, restore_cb_size = 0;
	uint64_t seq, staged_seq, host_src_va, host_dst_va, common_cb_address,
		cp_dma_cb_address, common_cb_device_va, cp_dma_cb_device_va,
		sram_addr[2];
	uint16_t sob0, sob1, mon0, mon1;
	void *host_src, *host_dst, *cb[2], *common_cb_buf,
		*cp_dma_cb, *restore_cb;
	int rc, i, fd = params->fd;

	for (i = 0 ; i < 2 ; i++) {
		cb[i] = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
		assert_non_null_ret_ptr(cb[i]);
		cb_size[i] = 0;
	}

	sram_addr[0] = params->sram_addr;
	sram_addr[1] = params->sram_addr + size;

	sob0 = params->sob_id;
	sob1 = params->sob_id + 1;
	mon0 = params->mon_id;
	mon1 = params->mon_id + 1;

	host_src = hltests_allocate_host_mem(fd, size, false);
	assert_non_null_ret_ptr(host_src);
	hltests_fill_rand_values(host_src, size);
	host_src_va = hltests_get_device_va_for_host_ptr(fd, host_src);

	host_dst = hltests_allocate_host_mem(fd, size, false);
	assert_non_null_ret_ptr(host_dst);
	memset(host_dst, 0, size);
	host_dst_va = hltests_get_device_va_for_host_ptr(fd, host_dst);

	common_cb_address = params->sram_addr + (size * 2);
	cp_dma_cb_address = params->sram_addr + (size * 3);

	/* Allocate a common cb buffer to hold dma packets for cp_dma */
	common_cb_buf = hltests_allocate_host_mem(fd, 0x1000, NOT_HUGE_MAP);
	assert_non_null_ret_ptr(common_cb_buf);
	memset(common_cb_buf, 0, 0x1000);
	common_cb_buf_size = 0;
	common_cb_device_va =
		hltests_get_device_va_for_host_ptr(fd, common_cb_buf);

	restore_cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null_ret_ptr(restore_cb);

	/* Internal CB for CP_DMA */
	cp_dma_cb = hltests_create_cb(fd, 0x1000, INTERNAL, cp_dma_cb_address);
	assert_non_null_ret_ptr(cp_dma_cb);
	cp_dma_cb_device_va = hltests_get_device_va_for_host_ptr(fd, cp_dma_cb);

	/* First CS - DMA to SRAM, signal SOB0 */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = host_src_va;
	pkt_info.dma.dst_addr = sram_addr[0];
	pkt_info.dma.size = size;
	pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;
	cb_size[0] = hltests_add_dma_pkt(fd, cb[0], cb_size[0], &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_size[0] = hltests_add_write_to_sob_pkt(fd, cb[0],
					cb_size[0], &pkt_info);

	execute_chunk.cb_ptr = cb[0];
	execute_chunk.cb_size = cb_size[0];
	execute_chunk.queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	flags = HL_CS_FLAGS_STAGED_SUBMISSION |
			HL_CS_FLAGS_STAGED_SUBMISSION_FIRST;
	rc = hltests_submit_staged_cs(fd, NULL, 0, &execute_chunk, 1, flags, 0,
									&seq);
	assert_int_equal_ret_ptr(rc, 0);

	staged_seq = seq;

	/* Second CS: Fence on SOB0, SRAM to SRAM, signal SOB1 */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = sram_addr[0];
	pkt_info.dma.dst_addr = sram_addr[1];
	pkt_info.dma.size = size;
	common_cb_buf_size = hltests_add_dma_pkt(fd,
		common_cb_buf, common_cb_buf_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob1;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	common_cb_buf_size = hltests_add_write_to_sob_pkt(fd, common_cb_buf,
			common_cb_buf_size, &pkt_info);

	/* cp_dma will execute packets located in common cb */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id =
			hltests_get_ddma_qid(fd, params->dma_channel, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cp_dma_cb_size = hltests_add_monitor_and_fence(fd, cp_dma_cb,
			cp_dma_cb_size, &mon_and_fence_info);

	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.cp_dma.src_addr = common_cb_address;
	pkt_info.cp_dma.size = common_cb_buf_size;
	cp_dma_cb_size = hltests_add_cp_dma_pkt(fd, cp_dma_cb,
			cp_dma_cb_size, &pkt_info);

	/* Restore cb copies common cb and cp_dma cb to sram */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = common_cb_device_va;
	pkt_info.dma.dst_addr = common_cb_address;
	pkt_info.dma.size = common_cb_buf_size;
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb,
			restore_cb_size, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = cp_dma_cb_device_va;
	pkt_info.dma.dst_addr = cp_dma_cb_address;
	pkt_info.dma.size = cp_dma_cb_size;
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb,
			restore_cb_size, &pkt_info);

	restore_chunk.cb_ptr = restore_cb;
	restore_chunk.cb_size = restore_cb_size;
	restore_chunk.queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	execute_chunk.cb_ptr = cp_dma_cb;
	execute_chunk.cb_size = cp_dma_cb_size;
	execute_chunk.queue_index =
			hltests_get_ddma_qid(fd, params->dma_channel, STREAM0);

	flags = HL_CS_FLAGS_STAGED_SUBMISSION | HL_CS_FLAGS_FORCE_RESTORE;
	rc = hltests_submit_staged_cs(fd, &restore_chunk, 1, &execute_chunk,
					1, flags, staged_seq, &seq);
	assert_int_equal_ret_ptr(rc, 0);

	/* Third CS - Fence on SOB1, DMA SRAM to HOST */
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob1;
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
	pkt_info.dma.src_addr = sram_addr[1];
	pkt_info.dma.dst_addr = host_dst_va;
	pkt_info.dma.size = size;
	pkt_info.dma.dma_dir = DMA_DIR_SRAM_TO_HOST;
	cb_size[1] = hltests_add_dma_pkt(fd, cb[1], cb_size[1], &pkt_info);

	execute_chunk.cb_ptr = cb[1];
	execute_chunk.cb_size = cb_size[1];
	execute_chunk.queue_index = hltests_get_dma_up_qid(fd, STREAM0);

	flags = HL_CS_FLAGS_STAGED_SUBMISSION |
			HL_CS_FLAGS_STAGED_SUBMISSION_LAST;
	rc = hltests_submit_staged_cs(fd, NULL, 0, &execute_chunk, 1, flags,
							staged_seq, &seq);
	assert_int_equal_ret_ptr(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, staged_seq);
	assert_int_equal_ret_ptr(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Compare host memories */
	rc = hltests_mem_compare(host_src, host_dst, size);
	assert_int_equal_ret_ptr(rc, 0);

	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_destroy_cb(fd, cb[i]);
		assert_int_equal_ret_ptr(rc, 0);
	}

	hltests_free_host_mem(fd, host_src);
	hltests_free_host_mem(fd, host_dst);
	hltests_free_host_mem(fd, common_cb_buf);

	rc = hltests_destroy_cb(fd, cp_dma_cb);
	assert_int_equal_ret_ptr(rc, 0);

	rc = hltests_destroy_cb(fd, restore_cb);
	assert_int_equal_ret_ptr(rc, 0);

	return args;
}

#define NUM_THREADS	256

VOID test_staged_submission_256_threads(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct staged_cs_thread_params *thread_params;
	struct hlthunk_hw_ip_info hw_ip;
	int rc, i, fd = tests_state->fd;
	uint32_t dma_queues_count, sob, mon, dma_size = 0x2000;
	uint64_t sram_base;
	pthread_t *thread_id;
	void *retval;

	if (!hltests_is_gaudi(fd)) {
		printf("Test is only relevant for Gaudi, skipping\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	assert_not_in_range(hw_ip.sram_size, 0, dma_size * 4 * NUM_THREADS);

	thread_params = hlthunk_malloc(NUM_THREADS * sizeof(*thread_params));
	assert_non_null(thread_params);

	/* Allocate arrays for threads management */
	thread_id = hlthunk_malloc(NUM_THREADS * sizeof(*thread_id));
	assert_non_null(thread_id);

	sob = hltests_get_first_avail_sob(fd);
	mon = hltests_get_first_avail_mon(fd);
	dma_queues_count = hltests_get_ddma_cnt(fd);

	/* Clear SOBs */
	hltests_clear_sobs(fd, NUM_THREADS * 2);
	sram_base = hw_ip.sram_base_address;

	/* Create and execute threads */
	for (i = 0 ; i < NUM_THREADS ; i++) {
		thread_params[i].fd = fd;
		thread_params[i].dma_size = dma_size;
		thread_params[i].sob_id = sob + (i * 2);
		thread_params[i].mon_id = mon + (i * 2);
		thread_params[i].sram_addr = sram_base + (dma_size * 4 * i);
		thread_params[i].dma_channel = i % dma_queues_count;
		rc = pthread_create(&thread_id[i], NULL, test_staged_submission,
					&thread_params[i]);
		assert_int_equal(rc, 0);
	}

	/* Wait for the termination of the threads */
	for (i = 0 ; i < NUM_THREADS ; i++) {
		rc = pthread_join(thread_id[i], &retval);
		assert_int_equal(rc, 0);
		assert_non_null(retval);
	}

	hlthunk_free(thread_params);
	hlthunk_free(thread_id);

	END_TEST;
}

static void prepare_cq_config(int fd, void *cb, uint16_t sob, uint16_t mon, uint16_t cq_id,
			uint16_t interrupt_id, uint16_t sob_val, uint32_t payload,
			uint64_t cq_device_va, struct hltests_cs_chunk *exec, bool direct_cq_en)
{
	struct hltests_direct_cq_write direct_cq;
	struct hltests_monitor mon_info;
	struct hltests_cq_config cq_config;
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size = 0, dma_qid;

	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	/* Configure CQ */
	cq_config.qid = dma_qid;
	cq_config.cq_address = cq_device_va;
	cq_config.cq_size_log2 = 2;
	cq_config.cq_id = cq_id;
	cq_config.interrupt_id = interrupt_id;
	cq_config.inc_mode = 0;
	cb_size = hltests_add_cq_config_pkt(fd, cb, cb_size, &cq_config);

	if (direct_cq_en) {
		memset(&direct_cq, 0, sizeof(direct_cq));
		direct_cq.qid = dma_qid;
		direct_cq.cq_id = cq_id;
		direct_cq.value = payload;
		cb_size = hltests_add_direct_write_cq_pkt(fd, cb, cb_size, &direct_cq);
	} else {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = dma_qid;
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.sob_id = sob;
		pkt_info.write_to_sob.value = 1;
		pkt_info.write_to_sob.mode = SOB_ADD;
		cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

		memset(&mon_info, 0, sizeof(mon_info));
		mon_info.qid = dma_qid;
		mon_info.sob_id = sob;
		mon_info.mon_id = mon;
		mon_info.sob_val = sob_val;

		/* Set payload to be more than compared value */
		mon_info.mon_payload = payload;
		mon_info.cq_enable = 1;
		mon_info.cq_id = cq_id;
		cb_size = hltests_add_monitor(fd, cb, cb_size, &mon_info);
	}

	exec->cb_ptr = cb;
	exec->cb_size = cb_size;
	exec->queue_index = dma_qid;
}

VOID test_wait_for_interrupt_common(void **state, bool direct_cq_en)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[1];
	uint16_t sob0, mon0, cq_id;
	struct hltests_cb *cq_cb;
	uint64_t seq, cq_device_va;
	uint16_t interrupt_id;
	void *cb;
	int rc, fd = tests_state->fd;

	if (hltests_is_gaudi(fd) || hltests_is_goya(fd)) {
		printf("Test relevant for Gaudi2 and above, skipping\n");
		skip();
	}

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);
	cq_id = hltests_get_first_avail_cq(fd);
	hltests_clear_sobs(fd, 1);

	cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb);

	cq_cb = hlthunk_malloc(sizeof(struct hltests_cb));
	assert_non_null(cq_cb);

	cq_cb->cb_size = sizeof(uint64_t);

	rc = hlthunk_request_mapped_command_buffer(fd, cq_cb->cb_size, &cq_cb->cb_handle);
	assert_int_equal(rc, 0);

	cq_cb->ptr = hltests_mmap(fd, cq_cb->cb_size, cq_cb->cb_handle);
	assert_ptr_not_equal(cq_cb->ptr, MAP_FAILED);

	rc = hlthunk_get_mapped_cb_device_va_by_handle(fd, cq_cb->cb_handle, &cq_device_va);
	assert_int_equal(rc, 0);

	*(uint64_t *) cq_cb->ptr = 0;

	interrupt_id = hltests_get_first_avail_interrupt(fd);

	prepare_cq_config(fd, cb, sob0, mon0, cq_id, interrupt_id, 1, 101,
				cq_device_va, execute_arr, direct_cq_en);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq);
	assert_int_equal(rc, 0);

	/* We wait for a value greater or equal to 100 */
	rc = hltests_wait_for_interrupt_by_handle(fd, cq_cb->cb_handle, 0, 100,
			interrupt_id, WAIT_FOR_CS_DEFAULT_TIMEOUT);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
			assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	rc = hltests_munmap(cq_cb->ptr, cq_cb->cb_size);
	assert_int_equal(rc, 0);

	rc = hlthunk_destroy_command_buffer(fd, cq_cb->cb_handle);
	assert_int_equal(rc, 0);

	hlthunk_free(cq_cb);

	END_TEST;
}

VOID test_wait_for_interrupt(void **state)
{
	END_TEST_FUNC(test_wait_for_interrupt_common(state, false));
}

static inline void timestamp_poll(void *ptr, uint64_t *timestamp)
{
	uint32_t iter = 0;

	do {
		sleep(1);
		iter++;
	} while ((*(uint64_t *) ptr == 0) && iter < 5);

	*timestamp = *(uint64_t *) ptr;
}

/*
 * This will test timestamp registration driver.
 * It will add several timestamp registration records(nodes) and other user interrupt
 * wait nodes on the same interrupt id, in order to test the driver is
 * functioning as expected on both cases, since in registration case driver
 * add a node to the user interrupt list and exit, and later on when we reach target value
 * it'll write the timestamp to some ts cb offset. In wait node case
 * it should block the caller till we reach target value
 * and both cases are handled in the same functions in driver.
 */
VOID test_multiple_timestamp_registrations(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[1];
	uint16_t sob0, mon0, cq_id;
	struct hltests_cb *cq_cb;
	uint64_t seq, cq_device_va, ts_handle, timestamp, interrupt_id;
	void *cb, *ts_user_ptr;
	int rc, fd = tests_state->fd;

	if (!hltests_is_gaudi2(fd)) {
		printf("Test relevant for Gaudi2 and above, skipping\n");
		skip();
	}

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);
	cq_id = hltests_get_first_avail_cq(fd);
	interrupt_id = hltests_get_first_avail_interrupt(fd);
	hltests_clear_sobs(fd, 1);

	cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb);

	cq_cb = hlthunk_malloc(sizeof(struct hltests_cb));
	assert_non_null(cq_cb);

	cq_cb->cb_size = sizeof(uint64_t);

	rc = hlthunk_request_mapped_command_buffer(fd, cq_cb->cb_size, &cq_cb->cb_handle);
	assert_int_equal(rc, 0);

	cq_cb->ptr = hltests_mmap(fd, cq_cb->cb_size, cq_cb->cb_handle);
	assert_ptr_not_equal(cq_cb->ptr, MAP_FAILED);

	rc = hlthunk_get_mapped_cb_device_va_by_handle(fd, cq_cb->cb_handle, &cq_device_va);
	assert_int_equal(rc, 0);

	*(uint64_t *) cq_cb->ptr = 0;

	/* Allocate timestamp pool */
	rc = hlthunk_allocate_timestamp_elements(fd, 10, &ts_handle);
	assert_int_equal(rc, 0);

	ts_user_ptr = hltests_mmap(fd, 10 * sizeof(uint64_t), ts_handle);
	assert_ptr_not_equal(ts_user_ptr, MAP_FAILED);

	memset(ts_user_ptr, 0, 10 * sizeof(uint64_t));

	/* Register timestamp record target val 100 */
	rc = hlthunk_register_timestamp_interrupt(fd, interrupt_id,
				cq_cb->cb_handle, 0, 100, ts_handle, 0);

	/* Register timestamp record target val 200 */
	rc = hlthunk_register_timestamp_interrupt(fd, interrupt_id,
				cq_cb->cb_handle, 1, 200, ts_handle, 1);

	/* Register timestamp record target val 400 */
	rc = hlthunk_register_timestamp_interrupt(fd, interrupt_id,
				cq_cb->cb_handle, 3, 400, ts_handle, 2);

	prepare_cq_config(fd, cb, sob0, mon0, cq_id, interrupt_id, 1, 101,
				cq_device_va, execute_arr, false);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq);
	assert_int_equal(rc, 0);

	/* Validate that driver set the timestamp in offset 0 of the pool */
	timestamp_poll(ts_user_ptr, &timestamp);
	assert_int_not_equal(timestamp, 0);

	prepare_cq_config(fd, cb, sob0, mon0, cq_id + 1, interrupt_id, 2, 201,
				cq_device_va + sizeof(uint64_t), execute_arr, false);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq);
	assert_int_equal(rc, 0);

	/* Validate that driver set the timestamp in offset 1 of the pool */
	timestamp_poll((uint64_t *)ts_user_ptr + 1, &timestamp);
	assert_int_not_equal(timestamp, 0);

	/* Lets add a wait node in between other registration nodes */
	prepare_cq_config(fd, cb, sob0, mon0, cq_id + 2, interrupt_id, 3, 301,
				cq_device_va + (sizeof(uint64_t) * 2), execute_arr, false);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_interrupt_by_handle(fd, cq_cb->cb_handle, 2, 300,
			interrupt_id, WAIT_FOR_CS_DEFAULT_TIMEOUT);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Make sure timestamp in offset 2 is still zero */
	assert_int_equal(*((uint64_t *)ts_user_ptr + 2), 0);

	prepare_cq_config(fd, cb, sob0, mon0, cq_id + 3, interrupt_id, 4, 401,
				cq_device_va + (sizeof(uint64_t) * 3), execute_arr, false);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq);
	assert_int_equal(rc, 0);

	/* Validate that driver set the timestamp in offset 2 of the pool */
	timestamp_poll((uint64_t *)ts_user_ptr + 2, &timestamp);
	assert_int_not_equal(timestamp, 0);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	rc = hltests_munmap(cq_cb->ptr, cq_cb->cb_size);
	assert_int_equal(rc, 0);

	rc = hlthunk_destroy_command_buffer(fd, cq_cb->cb_handle);
	assert_int_equal(rc, 0);

	rc = hltests_munmap(ts_user_ptr, 10 * sizeof(uint64_t));
	assert_int_equal(rc, 0);

	hlthunk_free(cq_cb);

	END_TEST;
}

/*
 * Test timestamp registration driver.
 * This test will register one timestamp record with some target value.
 * it'll submit cs which set monitor cq to write value above the target value
 * to the cq buffer, which then will trigger interrupt and cause timestamp
 * to be written to first ts buffer offset.
 * The test will wait sometime polling on that ts offset value, to see if the
 * timestamp was successfully written.
 */
VOID test_timestamp_registration(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[1];
	uint16_t sob0, mon0, cq_id, interrupt_id;
	struct hltests_cb *cq_cb;
	uint64_t seq, cq_device_va, ts_handle, timestamp;
	void *cb, *ts_user_ptr;
	int rc, fd = tests_state->fd;

	if (!hltests_is_gaudi2(fd)) {
		printf("Test relevant for Gaudi2, skipping\n");
		skip();
	}

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);
	cq_id = hltests_get_first_avail_cq(fd);
	interrupt_id = hltests_get_first_avail_interrupt(fd);
	hltests_clear_sobs(fd, 1);

	cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb);

	cq_cb = hlthunk_malloc(sizeof(struct hltests_cb));
	assert_non_null(cq_cb);

	cq_cb->cb_size = sizeof(uint64_t);

	rc = hlthunk_request_mapped_command_buffer(fd, cq_cb->cb_size, &cq_cb->cb_handle);
	assert_int_equal(rc, 0);

	cq_cb->ptr = hltests_mmap(fd, cq_cb->cb_size, cq_cb->cb_handle);
	assert_ptr_not_equal(cq_cb->ptr, MAP_FAILED);

	rc = hlthunk_get_mapped_cb_device_va_by_handle(fd, cq_cb->cb_handle, &cq_device_va);
	assert_int_equal(rc, 0);

	*(uint64_t *) cq_cb->ptr = 0;

	/* Allocate timestamp pool */
	rc = hlthunk_allocate_timestamp_elements(fd, 10, &ts_handle);
	assert_int_equal(rc, 0);

	ts_user_ptr = hltests_mmap(fd, 10 * sizeof(uint64_t), ts_handle);
	assert_ptr_not_equal(ts_user_ptr, MAP_FAILED);

	*(uint64_t *) ts_user_ptr = 0;

	prepare_cq_config(fd, cb, sob0, mon0, cq_id, interrupt_id, 1, 101,
				cq_device_va, execute_arr, false);

	/* Register timestamp record */
	rc = hlthunk_register_timestamp_interrupt(fd, interrupt_id,
			cq_cb->cb_handle, 0, 100, ts_handle, 0);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq);
	assert_int_equal(rc, 0);

	timestamp_poll((uint64_t *)ts_user_ptr, &timestamp);
	assert_int_not_equal(timestamp, 0);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	rc = hltests_munmap(cq_cb->ptr, cq_cb->cb_size);
	assert_int_equal(rc, 0);

	rc = hlthunk_destroy_command_buffer(fd, cq_cb->cb_handle);
	assert_int_equal(rc, 0);

	rc = hltests_munmap(ts_user_ptr, 10 * sizeof(uint64_t));
	assert_int_equal(rc, 0);

	hlthunk_free(cq_cb);

	END_TEST;
}

#define MAX_NUM_SUBMIT_THREADS 8
#define NUM_OF_WAIT_THREADS 2
#define NUM_OF_CS_PER_QID 1000000
#define NUM_OF_CS_PER_QID_SINGLE_MODE 100000

/**
 * struct submitted_seq_buf_params - parameters of CS buffer maintained for each QID
 * @seq: buffer of seqs.
 * @buf_len: seqs buffer length.
 * @num_of_active_seqs: number of active seqs. Active seq is seq of CS that was submitted
 *                      and yet to be completed.
 * @active_seq: array that indicates which seq is active.
 * @lock: lock for getting/setting struct parameters.
 * @remain_of_submit_cs: total remaining number of CSs to submit for related QID.
 * @remain_of_receive_cs: total remaining number of CSs to receive for related QID.
 */
struct submitted_seq_buf_params {
	uint64_t *seq;
	uint8_t buf_len;
	uint8_t num_of_active_seqs;
	bool *active_seq;
	pthread_mutex_t lock;
	uint32_t remain_of_submit_cs;
	uint32_t remain_of_receive_cs;
};

/**
 * struct merged_seq_info - parameters of CSs from several QIDs merged into multi CS array.
 * @seq: CS seq number.
 * @qid: QID of the seq.
 * @inner_stream_idx: inner index of the seq inside the QID seq buffer.
 */
struct merged_seq_info {
	uint64_t seq;
	uint8_t qid;
	uint8_t inner_stream_idx;
};

/**
 * struct multi_cs_common_params - common parameters of all threads in the test.
 * @seq_info: CS seq buffer for each QID.
 * @stream_master_tbl: table of QIDs.
 * @num_of_submit_threads: number of threads that submitting CSs.
 * @num_of_wait_threads: number of threads that waiting for CSs completion.
 * @test_pass: test result, if it passed or not.
 * @single_mode: test is running in single mode.
 * @fd: device file descriptor.
 */
struct multi_cs_common_params {
	struct submitted_seq_buf_params *seq_info;
	uint32_t *stream_master_tbl;
	uint8_t num_of_submit_threads;
	uint8_t num_of_wait_threads;
	bool test_pass;
	bool single_mode;
	int fd;
};

/**
 * struct multi_cs_submit_thread_params - parameters of threads that submit CSs.
 * @common: common parameters for all threads.
 * @id: thread id.
 */
struct multi_cs_submit_thread_params {
	struct multi_cs_common_params *common;
	uint8_t id;
};

/**
 * struct multi_cs_submit_thread_params - parameters of threads that wait for CSs completion.
 * @common: common parameters for all threads.
 * @id: thread id.
 * @start_qid: first QID which the thread waits on its CSs.
 * @end_qid: last QID which the thread waits on its CSs.
 */
struct multi_cs_wait_thread_params {
	struct multi_cs_common_params *common;
	uint8_t id;
	uint8_t start_qid;
	uint8_t end_qid;
};

static void *multi_cs_submit_thread(void *data)
{
	struct multi_cs_submit_thread_params *p =
		(struct multi_cs_submit_thread_params *) data;
	struct multi_cs_common_params *cp = p->common;
	struct hltests_cs_chunk execute_arr[HL_WAIT_MULTI_CS_LIST_MAX_LEN];
	uint8_t non_active_seq_idx;
	struct submitted_seq_buf_params *si = &cp->seq_info[p->id];
	uint32_t nop_cb_size[HL_WAIT_MULTI_CS_LIST_MAX_LEN] = {0};
	void *nop_cb[HL_WAIT_MULTI_CS_LIST_MAX_LEN];
	struct hltests_pkt_info pkt_info;
	int i, rc, fd = cp->fd;
	uint64_t temp_seq;

	/*
	 * N - size of CS buffer
	 * M - remain number of CSs the thread need to send
	 * active CS - already submitted CS that did not completed yet
	 * non active CS - completed or yet to be submitted CS
	 *
	 * Submit thread description :
	 *- Create N nop CBs
	 *- Loop while (M > 0)
	 *	- Loop while (number of active CS < N)
	 *		- Find first available non active CS and submit it
	 *		- Update active CS data structure
	 *		- Decrement M
	 */

	for (i = 0; i < si->buf_len; i++) {
		nop_cb[i] = hltests_create_cb(fd, 8, EXTERNAL, 0);
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		nop_cb_size[i] = hltests_add_nop_pkt(fd, nop_cb[i], 0, &pkt_info);
	}

	while (true && cp->test_pass) {
		pthread_mutex_lock(&si->lock);

		non_active_seq_idx = 0;
		while (si->num_of_active_seqs < si->buf_len) {
			/* Find the next free seq index to insert a new one*/
			while (si->active_seq[non_active_seq_idx]) {
				non_active_seq_idx++;
				if (non_active_seq_idx == si->buf_len) {
					printf("Error : num of non active seqs exceeded maximum\n");
					cp->test_pass = false;
					pthread_mutex_unlock(&si->lock);
					return NULL;
				}
			}

			execute_arr[0].cb_ptr = nop_cb[non_active_seq_idx];
			execute_arr[0].cb_size = nop_cb_size[non_active_seq_idx];
			execute_arr[0].queue_index = cp->stream_master_tbl[p->id];

			rc = hltests_submit_cs_timeout(fd, NULL, 0, execute_arr, 1, 0,
					30, &temp_seq);
			if (rc != 0) {
				printf("Error : submit CS returned %d\n", rc);
				cp->test_pass = false;
				pthread_mutex_unlock(&si->lock);
				return NULL;
			}

			si->seq[non_active_seq_idx] = temp_seq;
			si->num_of_active_seqs++;
			si->active_seq[non_active_seq_idx] = true;
			si->remain_of_submit_cs--;

			if (si->remain_of_submit_cs == 0) {
				pthread_mutex_unlock(&si->lock);
				for (i = 0; i < si->buf_len; i++) {
					rc = hltests_destroy_cb(fd, nop_cb[i]);
					if (rc != 0) {
						printf("Error destroying CB\n");
						cp->test_pass = false;
						return NULL;
					}
				}
				return 0;
			}
		}
		pthread_mutex_unlock(&si->lock);

	}

	return NULL;
}

static void *multi_cs_wait_thread(void *data)
{
	struct multi_cs_wait_thread_params *p =
		(struct multi_cs_wait_thread_params *) data;
	struct multi_cs_common_params *cp = p->common;
	uint64_t seq[HL_WAIT_MULTI_CS_LIST_MAX_LEN];
	struct hlthunk_wait_multi_cs_in mcs_in;
	struct hlthunk_wait_multi_cs_out mcs_out;
	struct merged_seq_info info[HL_WAIT_MULTI_CS_LIST_MAX_LEN];
	struct submitted_seq_buf_params *si;
	int i, j, seq_idx, rc, fd = cp->fd;
	int64_t remain_cs;

	/*
	 * remain_cs - remain number of CSs to wait for
	 *
	 * Wait thread description :
	 *
	 *- remain_cs = remain sum of all CSs from related QIDs
	 *- Loop while (remain_cs > 0)
	 *	- Loop on relevant QIDs
	 *		- Loop on QID CS buffer
	 *			- if CS is active, add it to multi CS wait arr
	 *	- Wait for multi CS
	 *	- Loop on all completed CSs
	 *		- Update Cs's related buffer
	 *		- Decrement  remain_cs
	 */
	mcs_in.seq = seq;
	mcs_in.timeout_us = WAIT_FOR_CS_DEFAULT_TIMEOUT;
	remain_cs = 0;

	for (i = p->start_qid; i <= p->end_qid; i++)
		remain_cs += cp->seq_info[i].remain_of_receive_cs;

	/* Each wait thread waits only on a portion of all submitted CSs */
	remain_cs /= NUM_OF_WAIT_THREADS;

	while (remain_cs && cp->test_pass) {
		/* Merge seq vectors from relevant streams to one seq vector*/
		seq_idx = 0;
		for (i = p->start_qid; i <= p->end_qid; i++) {
			pthread_mutex_lock(&cp->seq_info[i].lock);
			for (j = 0; j < cp->seq_info[i].buf_len; j++) {
				if (cp->seq_info[i].active_seq[j]) {
					if (seq_idx == HL_WAIT_MULTI_CS_LIST_MAX_LEN)
						break;
					if (cp->seq_info[i].seq[j] % NUM_OF_WAIT_THREADS == p->id) {
						seq[seq_idx] = cp->seq_info[i].seq[j];
						info[seq_idx].seq = seq[seq_idx];
						info[seq_idx].qid = i;
						info[seq_idx].inner_stream_idx = j;
						seq_idx++;
					}
				}

				/*
				 * in single mode we let the wait thread wait on single CS at
				 * the time
				 */
				if (p->common->single_mode && (seq_idx > 0))
					break;
			}
			pthread_mutex_unlock(&cp->seq_info[i].lock);

			/* same here: wait on single CS */
			if (p->common->single_mode && (seq_idx > 0))
				break;
		}
		/* In case no available active CS*/
		if (seq_idx == 0)
			continue;

		mcs_in.seq_len = seq_idx;
		rc = hlthunk_wait_for_multi_cs(fd, &mcs_in, &mcs_out);
		if (rc != 0) {
			printf("Error: wait for multi CS returned %d\n", rc);
			cp->test_pass = false;
			return NULL;
		}

		if (!mcs_out.seq_set) {
			printf("Error: timeout while waiting for multi CS\n");
			cp->test_pass = false;
			return NULL;
		}

		i = 0;
		while (mcs_out.seq_set) {
			if (mcs_out.seq_set & 0x1) {
				si = &cp->seq_info[info[i].qid];
				pthread_mutex_lock(&si->lock);
				if (si->num_of_active_seqs == 0) {
					printf("Error: completed CS from empty QID %u\n",
							info[i].qid);
					cp->test_pass = false;
					pthread_mutex_unlock(&si->lock);
					return NULL;
				}

				remain_cs--;
				si->num_of_active_seqs--;
				si->active_seq[info[i].inner_stream_idx] = false;
				si->remain_of_receive_cs--;
				pthread_mutex_unlock(&si->lock);
			}
			mcs_out.seq_set >>= 1;
			i++;
		}
		/* Check that remain_cs is not negative*/
		if (remain_cs < 0) {
			printf("Error: remain_cs in thread %u is less than 0\n", p->id);
			cp->test_pass = false;
			return NULL;
		}
	}

	return NULL;
}

static int multi_cs_multi_thread_init(int fd, struct multi_cs_common_params *cp, bool single_mode)
{
	int i, j, rc;
	uint32_t cs_per_qid, divider;

	divider = hltests_is_simulator(fd) ? 3 : 1;
	cs_per_qid = single_mode ? NUM_OF_CS_PER_QID_SINGLE_MODE : NUM_OF_CS_PER_QID;

	cp->fd = fd;
	cp->single_mode = single_mode;
	cp->num_of_submit_threads = hltests_get_stream_master_qid_arr(fd, &cp->stream_master_tbl);
	cp->num_of_wait_threads = NUM_OF_WAIT_THREADS;
	cp->seq_info = hlthunk_malloc(sizeof(struct submitted_seq_buf_params) *
			cp->num_of_submit_threads);
	assert_non_null(cp->seq_info);

	for (i = 0; i < cp->num_of_submit_threads; i++) {
		/*
		 * Buffer length is the portion on each submit thread in a multi CS vector.
		 * It also depends how many ,multi CS contexts we have hence we need to multiply
		 * with it
		 */
		cp->seq_info[i].buf_len =
				(HL_WAIT_MULTI_CS_LIST_MAX_LEN / cp->num_of_submit_threads) *
				NUM_OF_WAIT_THREADS;
		/* Test running time is longer in simulator, hence reducing iterations*/
		cp->seq_info[i].remain_of_receive_cs = cs_per_qid / divider;
		cp->seq_info[i].remain_of_submit_cs = cs_per_qid / divider;

		cp->seq_info[i].seq =
				hlthunk_malloc(sizeof(uint64_t) * cp->seq_info[i].buf_len);
		assert_non_null(cp->seq_info[i].seq);
		cp->seq_info[i].active_seq =
				hlthunk_malloc(sizeof(uint64_t) * cp->seq_info[i].buf_len);
		assert_non_null(cp->seq_info[i].active_seq);

		/* Init buffer info to no active seqs */
		for (j = 0; j < cp->seq_info[i].buf_len; j++)
			cp->seq_info[i].active_seq[j] = false;
		cp->seq_info[i].num_of_active_seqs = 0;
		rc = pthread_mutex_init(&cp->seq_info[i].lock, NULL);
		assert_int_equal(rc, 0);
	}

	cp->test_pass = true;

	return 0;
}

static void multi_cs_multi_thread_finish(struct multi_cs_common_params *cp)
{
	int i;

	for (i = 0; i < cp->num_of_submit_threads; i++) {
		hlthunk_free(cp->seq_info[i].seq);
		hlthunk_free(cp->seq_info[i].active_seq);
	}
	hlthunk_free(cp->seq_info);
}

VOID test_wait_for_multi_cs_multi_thread_common(void **state, bool single_mode)
{
	pthread_t submit_thread_id[MAX_NUM_SUBMIT_THREADS], wait_thread_id[NUM_OF_WAIT_THREADS];
	struct multi_cs_submit_thread_params s_params[MAX_NUM_SUBMIT_THREADS];
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct multi_cs_wait_thread_params w_params[NUM_OF_WAIT_THREADS];
	struct multi_cs_common_params cp;
	int rc, i, fd = tests_state->fd;
	void *retval;

	if (hltests_is_simulator(fd)) {
		printf("Temporarily test is not supported for simulator\n");
		skip();
	}

	if (!hltests_is_gaudi(fd)) {
		printf("Test is supported only for Gaudi, support for Greco will be added later\n");
		skip();
	}

	/*
	 * Test Description:
	 *
	 * Wait threads retrieve CS's from related submit threads CS buffers
	 * and perform multi CS wait.
	 *
	 * Submit threads taking care of submitting CS and filling buffers
	 * as soon buffers not full.
	 */

	memset(&cp, 0, sizeof(struct multi_cs_common_params));
	memset(&s_params, 0, sizeof(struct multi_cs_submit_thread_params) * MAX_NUM_SUBMIT_THREADS);
	memset(&w_params, 0, sizeof(struct multi_cs_wait_thread_params) * NUM_OF_WAIT_THREADS);

	multi_cs_multi_thread_init(fd, &cp, single_mode);

	for (i = 0; i < cp.num_of_wait_threads; i++) {
		w_params[i].start_qid = 0;
		w_params[i].end_qid = cp.num_of_submit_threads - 1;
		w_params[i].common = &cp;
		w_params[i].id = i;
		rc = pthread_create(&wait_thread_id[i], NULL,
				multi_cs_wait_thread, &w_params[i]);

		assert_int_equal(rc, 0);
	}

	for (i = 0; i < cp.num_of_submit_threads; i++) {
		s_params[i].common = &cp;
		s_params[i].id = i;
		rc = pthread_create(&submit_thread_id[i], NULL,
				multi_cs_submit_thread, &s_params[i]);

		assert_int_equal(rc, 0);
	}

	for (i = 0; i < cp.num_of_submit_threads; i++) {
		rc = pthread_join(submit_thread_id[i], &retval);
		assert_int_equal(rc, 0);
	}

	for (i = 0; i < cp.num_of_wait_threads; i++) {
		rc = pthread_join(wait_thread_id[i], &retval);
		assert_int_equal(rc, 0);
	}
	assert_true(cp.test_pass);

	multi_cs_multi_thread_finish(&cp);

	END_TEST;
}

VOID test_wait_for_multi_cs_multi_thread(void **state)
{
	/* Temporarily skip test as it causes driver deadlocks */
	skip();

	END_TEST_FUNC(test_wait_for_multi_cs_multi_thread_common(state, false));
}

/*
 * multi CS with threads in single mode means that each wait thread
 * waits each time on a single CS instead of, potentially, a full multi CS array.
 * This is done to detect driver races that are generally floating in a "single mode"
 * scenarios.
 */
VOID test_wait_for_multi_cs_multi_thread_single_mode(void **state)
{
	printf("Temporarily skip randomly failing test\n");
	skip();
	END_TEST_FUNC(test_wait_for_multi_cs_multi_thread_common(state, true));
}

#define MAX_NUM_OF_TEST_THREADS 64
#define TARGET_VAL 100
#define NUM_OF_WAIT_FOR_INTERRUPT_THREADS (TARGET_VAL + 1)

/**
 * struct interrupt_params - interrupt related parameters
 * @cq_config: cq configuration.
 * @cq_cb: cq cb configuration.
 * @trig_barrier: barrier to sync all trigger threads.
 * @lock: syncwaiting value incrementatiotn between threads.
 * @last_wait_confirm: indicates that waiting for last value (one above trigger maximum value)
 *                     got busy status (as expected).
 * @cq_device_va: cq virtual address for the device.
 * @seq: cs sequence number that the relates to the cq.
 * @cq_target_val_counter: cq target value counter.
 * @num_of_wait_threads: number of wait threads
 * @target_val: target value
 * @sob: sob id of the cs that relates to the cq.
 * @mon: mon id of the cs that relates to the cq.
 * @cq_id: cq id.
 * @cb: command buffer.
 * @fd: file descriptor.
 * @trigger_res: trigger thread result.
 * @wait_res: wait thread result.
 * @idx: main thread index.
 */
struct interrupt_params {
	struct hltests_cq_config cq_config;
	struct hltests_cb *cq_cb;
	pthread_barrier_t trig_barrier;
	pthread_mutex_t lock;
	bool last_wait_confirm;
	uint64_t cq_device_va;
	uint64_t seq;
	uint32_t cq_target_val_counter;
	uint32_t num_of_wait_threads;
	uint32_t target_val;
	uint16_t sob;
	uint16_t mon;
	uint16_t cq_id;
	void *cb;
	int fd;
	int trigger_res;
	int wait_res;
	int test_res;
	int idx;
};

static int mon_config(struct interrupt_params *ip)
{
	struct hltests_cs_chunk execute_arr[1];
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor mon_info;
	uint32_t cb_size = 0, qid;
	int rc;

	qid = hltests_get_dma_down_qid(ip->fd, STREAM0);
	ip->sob = hltests_get_first_avail_sob(ip->fd) + ip->idx;
	ip->mon = hltests_get_first_avail_mon(ip->fd) + ip->idx;
	ip->cq_id = hltests_get_first_avail_cq(ip->fd) + ip->idx;
	ip->cb = hltests_create_cb(ip->fd, 0x1000, EXTERNAL, 0);
	if (!ip->cb) {
		printf("cb allocation failed\n");
		return -1;
	}

	ip->cq_config.qid = qid;
	ip->cq_config.cq_address = ip->cq_device_va + (ip->idx * sizeof(uint64_t));
	ip->cq_config.cq_size_log2 = 3;
	ip->cq_config.cq_id = ip->cq_id;
	ip->cq_config.interrupt_id = hltests_get_first_avail_interrupt(ip->fd) + ip->idx;
	ip->cq_config.inc_mode = 1;
	cb_size = hltests_add_cq_config_pkt(ip->fd, ip->cb, cb_size, &ip->cq_config);
	ip->cq_target_val_counter = 1;
	ip->trigger_res = 0;
	ip->wait_res = 0;

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid;
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = ip->sob;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_size = hltests_add_write_to_sob_pkt(ip->fd, ip->cb, cb_size, &pkt_info);

	memset(&mon_info, 0, sizeof(mon_info));
	mon_info.qid = qid;
	mon_info.sob_id = ip->sob;
	mon_info.mon_id = ip->mon;
	mon_info.sob_val = 1;
	mon_info.mon_payload = 0;
	mon_info.cq_enable = 1;
	mon_info.cq_id = ip->cq_id;
	cb_size = hltests_add_monitor(ip->fd, ip->cb, cb_size, &mon_info);

	execute_arr[0].cb_ptr = ip->cb;
	execute_arr[0].cb_size = cb_size;
	execute_arr[0].queue_index = qid;

	rc = hltests_submit_cs(ip->fd, NULL, 0, execute_arr, 1, 0, &ip->seq);
	if (rc) {
		printf("Submit CS failed %d\n", rc);
		return -1;
	}

	rc = hltests_wait_for_cs_until_not_busy(ip->fd, ip->seq);
	if (rc != HL_WAIT_CS_STATUS_COMPLETED) {
		printf("Error hltests_wait_for_cs_until_not_busy seq %lu\n", ip->seq);
		return -1;
	}

	return 0;
}

static void *wait_for_interrupt_thread(void *data)
{
	struct interrupt_params *ip = (struct interrupt_params *) data;
	uint32_t target_val;
	uint64_t *val;
	int rc;

	pthread_mutex_lock(&ip->lock);
	target_val = ip->cq_target_val_counter;
	ip->cq_target_val_counter++;
	pthread_mutex_unlock(&ip->lock);

	rc = hltests_wait_for_interrupt_by_handle(ip->fd, ip->cq_cb->cb_handle, ip->idx,
			target_val, ip->cq_config.interrupt_id, 10000000);

	if (rc != HL_WAIT_CS_STATUS_COMPLETED) {
		/* As part of testing scenario, we expect the last wait thread to fail on busy*/
		if ((target_val == ip->num_of_wait_threads) &&
				(rc == HL_WAIT_CS_STATUS_BUSY)) {
			ip->last_wait_confirm = true;
			return data;
		}
		val = (uint64_t *)ip->cq_cb->ptr + ip->idx;
		printf("wait failed: interrupt %u, idx %d, rc %d, target %u, val %lu\n",
				ip->cq_config.interrupt_id, ip->idx, rc, target_val, *val);
		ip->wait_res = rc;
	}

	return data;
}

static void *trigger_interrupt_thread(void *data)
{
	struct interrupt_params *ip = (struct interrupt_params *) data;
	struct hltests_cs_chunk execute_arr[1];
	struct hltests_monitor mon_info;
	uint32_t cb_size = 0, dma_qid;
	uint64_t seq;
	void *cb;
	int rc;

	cb = hltests_create_cb(ip->fd, 0x1000, EXTERNAL, 0);
	if (!cb) {
		printf("trigger cb allocation failed\n");
		ip->trigger_res = -1;
		return NULL;
	}

	dma_qid = hltests_get_dma_down_qid(ip->fd, STREAM0);

	memset(&mon_info, 0, sizeof(mon_info));
	mon_info.qid = dma_qid;
	mon_info.sob_id = ip->sob;
	mon_info.mon_id = ip->mon;
	mon_info.sob_val = 1;
	mon_info.cq_enable = 1;
	mon_info.cq_id = ip->cq_id;
	mon_info.mon_payload = 1;

	cb_size = hltests_add_monitor(ip->fd, cb, 0, &mon_info);

	execute_arr[0].cb_ptr = cb;
	execute_arr[0].cb_size = cb_size;
	execute_arr[0].queue_index = dma_qid;

	rc = pthread_barrier_wait(&ip->trig_barrier);
	if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD)
		return NULL;

	rc = hltests_submit_cs_timeout(ip->fd, NULL, 0, execute_arr, 1, 0, 30, &seq);

	if (rc) {
		printf("Submit CS with trigger failed returned %d\n", rc);
		ip->trigger_res = -1;
		return NULL;
	}

	rc = hltests_wait_for_cs_until_not_busy(ip->fd, seq);
	if (rc) {
		printf("Submit CS with trigger failed returned %d\n", rc);
		ip->trigger_res = -1;
		return NULL;
	}

	rc = hltests_destroy_cb(ip->fd, cb);
	if (rc) {
		printf("Submit CS with trigger failed returned %d\n", rc);
		ip->trigger_res = -1;
		return NULL;
	}
	return data;
}

static int main_interrupt_test(struct interrupt_params *ip)
{
	int i, rc;
	pthread_t wait_thread_id[NUM_OF_WAIT_FOR_INTERRUPT_THREADS];
	pthread_t trigger_thread_id[TARGET_VAL];
	void *retval;

	/*
	 * Test main thread description:
	 * 1. Submit CS with cq related to its monitor.
	 * 2. Submit TARGET_VAL wait threads that waits on interrupt. Each wait thread will wait
	 *    on value between 1 to TARGET_VAL.
	 * 3. Submit TARGET_VAL trigger threads, each trigger thread will increment the cq value
	 *    until it reaches the target value. In order to stress the waiting mechanism, the
	 *    trigger threads using thread barrier so all the cq value increments will happen with
	 *    minimal delay.
	 * 4. Wait for triggering threads to end and check for errors.
	 * 5. Wait for waiting threads to end and check for errors.
	 * 6. Release resources.
	 */

	pthread_mutex_init(&ip->lock, NULL);

	/* Submit */
	rc = mon_config(ip);
	if (rc)
		return rc;

	for (i = 0; i < ip->num_of_wait_threads; i++) {
		rc = pthread_create(&wait_thread_id[i], NULL, wait_for_interrupt_thread, ip);
		if (rc) {
			printf("Error creating wait_for_interrupt_thread %d\n", rc);
			return -1;
		}
	}

	pthread_barrier_init(&ip->trig_barrier, NULL, ip->target_val);

	/* Trigger */
	for (i = 0; i < ip->target_val; i++) {
		rc = pthread_create(&trigger_thread_id[i], NULL, trigger_interrupt_thread, ip);
		if (rc) {
			printf("Error creating trigger_interrupt_thread\n");
			return -1;
		}
	}

	for (i = 0; i < ip->target_val; i++) {
		rc = pthread_join(trigger_thread_id[i], &retval);
		if (rc) {
			printf("Error joining trigger_interrupt_thread\n");
			return -1;
		}
		if (ip->trigger_res) {
			printf("Error trigger result = %d\n", ip->trigger_res);
			return -1;
		}
	}


	for (i = 0; i < ip->num_of_wait_threads; i++) {
		rc = pthread_join(wait_thread_id[i], &retval);
		if (rc) {
			printf("Error joining wait_for_interrupt_thread\n");
			return -1;
		}
	}

	if (ip->wait_res != HL_WAIT_CS_STATUS_COMPLETED) {
		printf("Error wait result = %d\n", ip->wait_res);
		return -1;
	}

	if (!ip->last_wait_confirm) {
		printf("Last wait did not happen\n");
		return -1;
	}

	rc = hltests_destroy_cb(ip->fd, ip->cb);
	if (rc) {
		printf("Error hltests_destroy_cb\n");
		return -1;
	}

	return 0;
}

static void *main_interrupt_thread(void *data)
{
	struct interrupt_params *ip = (struct interrupt_params *) data;

	ip->test_res = main_interrupt_test(ip);
	return data;
}

VOID test_wait_for_interrupt_multi_thread(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t num_of_wait_threads, num_of_test_threads, target_val;
	struct interrupt_params info[MAX_NUM_OF_TEST_THREADS];
	pthread_t test_thread_id[MAX_NUM_OF_TEST_THREADS];
	int i, rc, fd = tests_state->fd;
	struct hltests_cb *cq_cb;
	uint64_t cq_device_va;
	void *retval;

	/* Skip test until SW-85257 is resolved */
	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Temporarely skipping test in ARC mode\n");
		skip();
	}

	if (!hltests_is_gaudi2(fd)) {
		printf("Test relevant for Gaudi2 and above, skipping\n");
		skip();
	}

	if (hltests_is_pldm(fd)) {
		printf("Test is not supported for PLDM, skipping\n");
		skip();
	}

	/*
	 * Since coral runs slower than asic, we are reducing the number of threads
	 * in order to reduce the time of the test.
	 */
	if (hltests_is_simulator(fd)) {
		num_of_test_threads = 10;
		num_of_wait_threads = 11;
		target_val = 10;
	} else {
		num_of_wait_threads = NUM_OF_WAIT_FOR_INTERRUPT_THREADS;
		target_val = TARGET_VAL;
		if (hltests_is_legacy_mode_enabled(fd))
			/* Number of test threads is number of available CQs (not used by driver)*/
			num_of_test_threads =
					MAX_NUM_OF_TEST_THREADS - hltests_get_first_avail_cq(fd);
		else
			/* We have a limitation of up to 512 concurrect CSs in arc mode */
			num_of_test_threads = 4;
	}

	hltests_clear_sobs(fd, num_of_test_threads);

	cq_cb = hlthunk_malloc(sizeof(struct hltests_cb));
	assert_non_null(cq_cb);

	cq_cb->cb_size = sizeof(uint64_t) * num_of_test_threads;

	rc = hlthunk_request_mapped_command_buffer(fd, cq_cb->cb_size, &cq_cb->cb_handle);
	assert_int_equal(rc, 0);

	cq_cb->ptr = hltests_mmap(fd, cq_cb->cb_size, cq_cb->cb_handle);
	assert_non_null(cq_cb->ptr);

	rc = hlthunk_get_mapped_cb_device_va_by_handle(fd, cq_cb->cb_handle, &cq_device_va);
	assert_int_equal(rc, 0);

	memset(cq_cb->ptr, 0, cq_cb->cb_size);

	for (i = 0; i < num_of_test_threads; i++) {
		info[i].cq_cb = cq_cb;
		info[i].cq_device_va = cq_device_va;
		info[i].fd = tests_state->fd;
		info[i].idx = i;
		info[i].num_of_wait_threads = num_of_wait_threads;
		info[i].target_val = target_val;
		info[i].last_wait_confirm = false;
		rc = pthread_create(&test_thread_id[i], NULL, main_interrupt_thread, &info[i]);
		assert_int_equal(rc, 0);
	}

	for (i = 0; i < num_of_test_threads; i++) {
		rc = pthread_join(test_thread_id[i], &retval);
		assert_int_equal(rc, 0);
		assert_int_equal(info[i].test_res, 0);
		assert_non_null(retval);
	}

	rc = hltests_munmap(cq_cb->ptr, cq_cb->cb_size);
	assert_int_equal(rc, 0);

	rc = hlthunk_destroy_command_buffer(fd, cq_cb->cb_handle);
	assert_int_equal(rc, 0);

	hlthunk_free(cq_cb);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest cs_tests[] = {
	cmocka_unit_test_setup(test_cs_nop, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_nop_16PQE,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_nop_32PQE,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_nop_48PQE,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_nop_64PQE,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_and_measure_wait_after_submit_cs_nop,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_and_measure_wait_after_64_submit_cs_nop,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_and_measure_wait_after_256_submit_cs_nop,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_msg_long,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_msg_long_2000,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_two_streams_with_fence,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_two_streams_with_arb,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_two_streams_with_priority_arb,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_two_streams_with_wrr_arb,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_cq_wrap_around,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_load_pred_non_consecutive_map,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_load_pred_consecutive_map,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_load_scalars_exe_4_rfs,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_load_scalars_exe_lower_2_rfs,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_load_scalars_exe_upper_2_rfs,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_cb_list,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_cb_list_with_parallel_pqe,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_drop,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_wait_for_cs_with_timestamp,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_wait_for_cs_with_timestamp_status_gone,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_staged_submission_256_threads,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_wait_for_interrupt,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_wait_for_multi_cs_complete,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_wait_for_multi_cs_poll,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_wait_for_multi_cs_multi_thread,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_wait_for_multi_cs_multi_thread_single_mode,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_wait_for_interrupt_multi_thread,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_timestamp_registration,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_multiple_timestamp_registrations,
					hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"command_submission [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(cs_tests) / sizeof((cs_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE, cs_tests, num_tests);
	return hltests_run_group_tests("command_submission", cs_tests, num_tests,
						hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
