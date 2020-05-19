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

static void submit_cs_nop(void **state, int num_of_pqe)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[64];
	uint32_t cb_size = 0;
	uint64_t seq = 0;
	void *cb[64];
	int rc, j, i, fd = tests_state->fd;

	assert_in_range(num_of_pqe, 1, 64);

	for (i = 0 ; i < num_of_pqe ; i++) {
		cb[i] = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
		assert_non_null(cb[i]);

		cb_size = hltests_add_nop_pkt(fd, cb[i], 0, EB_FALSE, MB_FALSE);

		execute_arr[i].cb_ptr = cb[i];
		execute_arr[i].cb_size = cb_size;
		execute_arr[i].queue_index =
				hltests_get_dma_down_qid(fd, STREAM0);
	}

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, num_of_pqe, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	for (i = 0 ; i < num_of_pqe ; i++) {
		rc = hltests_destroy_cb(fd, cb[i]);
		assert_int_equal(rc, 0);
	}
}

void test_cs_nop(void **state)
{
	submit_cs_nop(state, 1);
}

void test_cs_nop_16PQE(void **state)
{
	submit_cs_nop(state, 16);
}

void test_cs_nop_32PQE(void **state)
{
	submit_cs_nop(state, 32);
}

void test_cs_nop_48PQE(void **state)
{
	submit_cs_nop(state, 48);
}

void test_cs_nop_64PQE(void **state)
{
	submit_cs_nop(state, 64);
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
	uint16_t sob0, mon0;
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

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);

	/* Clear SOB0 */
	hltests_clear_sobs(fd, 1);

	/* Stream 0: Fence on SOB0 + LIN_DMA from host to SRAM */
	cb_stream0 = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(cb_stream0);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_down_qid(fd, STREAM0);
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
	pkt_info.write_to_sob.sob_id = sob0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_stream3_size = hltests_add_write_to_sob_pkt(fd, cb_stream3,
						cb_stream3_size, &pkt_info);

	/* First CS: Submit CB of stream 0 */
	execute_arr[0].cb_ptr = cb_stream0;
	execute_arr[0].cb_size = cb_stream0_size;
	execute_arr[0].queue_index =
				hltests_get_dma_down_qid(fd, STREAM0);
	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq);
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

static void hltests_cs_two_streams_arb_point(int fd,
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
	uint64_t seq, src_addr, dst_addr, num_dma_pkts, dma_pkt_bytes;

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

	qid[2] = ds_direction ? hltests_get_dma_down_qid(fd, STREAM2) :
			hltests_get_dma_up_qid(fd, STREAM2);

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
}

void test_cs_two_streams_with_arb(void **state)
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
	device_data_address[0] = hw_ip.sram_base_address;
	device_data_address[1] = hw_ip.sram_base_address + 0x1000;

	/* Allocate buffers on host for data transfer */
	for (i = 0 ; i < 4 ; i++) {
		data[i] = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
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
}

void test_cs_two_streams_with_priority_arb(void **state)
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

	/* This test can't run on Goya because it doesn't have streams */
	if (hlthunk_get_device_name_from_fd(fd) == HLTHUNK_DEVICE_GOYA) {
		printf("Test is not relevant for Goya, skipping\n");
		skip();
	}

	/* This test can't run on Simulator */
	if (hltests_is_simulator(fd)) {
		printf("Test is not relevant for Simulator, skipping\n");
		skip();
	}

	/* SRAM MAP (base + )
	 * 0x0    : data1
	 * 0x1000 : data2
	 */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	device_data_address[0] = hw_ip.sram_base_address;
	device_data_address[1] = hw_ip.sram_base_address;

	/* Allocate buffers on host for data transfer */
	for (i = 0 ; i < 3 ; i++) {
		data[i] = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
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

	for (i = 0 ; i < 3 ; i++) {
		rc = hltests_free_host_mem(fd, data[i]);
		assert_int_equal(rc, 0);
	}
}

void test_cs_two_streams_with_wrr_arb(void **state)
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
	device_data_address[0] = hw_ip.sram_base_address;
	device_data_address[1] = hw_ip.sram_base_address + 0x1000;

	/* Allocate buffers on host for data transfer */
	for (i = 0 ; i < 4 ; i++) {
		data[i] = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
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
	cmocka_unit_test_setup(test_cs_nop_16PQE,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_nop_32PQE,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_nop_48PQE,
					hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_nop_64PQE,
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
