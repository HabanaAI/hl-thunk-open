// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
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

void test_cs_nop(void **state)
{
	struct hltests_state *tests_state =
			(struct hltests_state *) *state;
	uint32_t cb_size = 0;
	void *cb;
	int fd = tests_state->fd;

	cb = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(cb);

	cb_size = hltests_add_nop_pkt(fd, cb, cb_size, EB_FALSE, MB_FALSE);

	hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

void test_cs_msg_long(void **state)
{
	struct hltests_state *tests_state =
			(struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size = 0;
	void *cb;
	int rc, fd = tests_state->fd;

	cb = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(cb);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = hw_ip.sram_base_address + 0x1000;
	pkt_info.msg_long.value = 0xbaba0ded;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

#define NUM_OF_MSGS	2000

void test_cs_msg_long_2000(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size = 0;
	void *cb;
	int rc, fd = tests_state->fd, i;

	/* Largest packet is 24 bytes, so 32 is a good number */
	cb = hltests_create_cb(fd, NUM_OF_MSGS * 32, EXTERNAL, 0);
	assert_non_null(cb);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	for (i = 0 ; i < NUM_OF_MSGS ; i++) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.msg_long.address = hw_ip.sram_base_address +
							0x1000 + i * 4;
		pkt_info.msg_long.value = 0x0ded0000 + i;
		cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);
	}

	hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

void test_cs_two_streams_with_fence(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	struct hltests_cs_chunk execute_arr[1];
	uint32_t dma_size = 4, cb_stream0_size = 0, cb_stream3_size = 0;
	uint64_t src_data_device_va, device_data_address, seq;
	void *src_data, *cb_stream0, *cb_stream3;
	int rc, fd = tests_state->fd;

	/* This test can't run on Goya because it doesn't have streams */
	if (hlthunk_get_device_name_from_fd(fd) == HLTHUNK_DEVICE_GOYA) {
		printf("Test is skipped. Goya doesn't have streams\n");
		skip();
	}

	/* SRAM MAP (base + )
	 * 0x1000 : data
	 */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	device_data_address = hw_ip.sram_base_address + 0x1000;

	/* Allocate buffer on host for data transfer */
	src_data = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
	assert_non_null(src_data);
	hltests_fill_rand_values(src_data, dma_size);
	src_data_device_va = hltests_get_device_va_for_host_ptr(fd, src_data);

	/* Clear SOB 0 */
	hltests_clear_sobs(fd, 1);

	/* Stream 0: Fence on SOB0 + LIN_DMA from host to SRAM */
	cb_stream0 = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(cb_stream0);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_down_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = 0;
	mon_and_fence_info.mon_id = 0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.dec_val = 1;
	mon_and_fence_info.target_val = 1;
	cb_stream0_size = hltests_add_monitor_and_fence(fd, cb_stream0,
					cb_stream0_size, &mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = src_data_device_va;
	pkt_info.dma.dst_addr = device_data_address;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_SRAM;
	cb_stream0_size = hltests_add_dma_pkt(fd, cb_stream0, cb_stream0_size,
						&pkt_info);

	/* Stream 3: Signal SOB0 */
	cb_stream3 = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(cb_stream3);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = 0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_stream3_size = hltests_add_write_to_sob_pkt(fd, cb_stream3,
						cb_stream3_size, &pkt_info);

	/* First CS: Submit CB of stream 0 */
	execute_arr[0].cb_ptr = cb_stream0;
	execute_arr[0].cb_size = cb_stream0_size;
	execute_arr[0].queue_index =
				hltests_get_dma_down_qid(fd, STREAM0);
	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, FORCE_RESTORE_FALSE,
				&seq);
	assert_int_equal(rc, 0);

	/* Second CS: Submit CB of stream 3 and wait for completion */
	hltests_submit_and_wait_cs(fd, cb_stream3, cb_stream3_size,
				hltests_get_dma_down_qid(fd, STREAM3),
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
}

#define CQ_WRAP_AROUND_TEST_NUM_OF_CS	1000

void test_cs_cq_wrap_around(void **state)
{
	int i;

	for (i = 0 ; i < CQ_WRAP_AROUND_TEST_NUM_OF_CS ; i++)
		test_cs_nop(state);
}

const struct CMUnitTest cs_tests[] = {
	cmocka_unit_test_setup(test_cs_nop, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_msg_long,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_msg_long_2000,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_two_streams_with_fence,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_cq_wrap_around,
					hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"command_submission [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(cs_tests) / sizeof((cs_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE, cs_tests,
			num_tests);

	return hltests_run_group_tests("command_submission", cs_tests,
				num_tests, hltests_setup, hltests_teardown);
}
