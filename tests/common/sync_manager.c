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
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#define SIG_WAIT_TH	2
#define SIG_WAIT_CS	(64 / SIG_WAIT_TH)

struct signal_wait_thread_params {
	int fd;
	int queue_id;
	bool collective_wait;
	int engine_id;
};

static uint64_t sig_seqs[SIG_WAIT_CS];

static uint64_t atomic_read(uint64_t *ptr)
{
	return __sync_fetch_and_add(ptr, 0);
}

static void test_sm(void **state, bool is_tpc, bool is_wait, uint8_t engine_id)
{
	struct hltests_state *tests_state =
			(struct hltests_state *) *state;
	void *src_data, *dst_data, *engine_cb, *ext_cb;
	uint64_t src_data_device_va, dst_data_device_va, device_data_address,
		cb_engine_address, engine_cb_device_va;
	struct hltests_cs_chunk execute_arr[2];
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t offset = 0, dma_size = 4, engine_cb_size;
	int rc, engine_qid, fd = tests_state->fd;
	uint64_t seq;
	uint16_t sob0, mon0;

	/* Get device information, especially tpc enabled mask */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_tpc)
		engine_qid = hltests_get_tpc_qid(fd, engine_id, STREAM0);
	else
		engine_qid = hltests_get_mme_qid(fd, engine_id, STREAM0);

	/* SRAM MAP (base + )
	 * 0x1000 : data
	 * 0x2000 : engine's internal CB (we only use upper CP in this test)
	 */

	device_data_address = hw_ip.sram_base_address + 0x1000;
	cb_engine_address = hw_ip.sram_base_address + 0x2000;

	/* Allocate two buffers on the host for data transfers */
	src_data = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
	assert_non_null(src_data);
	hltests_fill_rand_values(src_data, dma_size);
	src_data_device_va = hltests_get_device_va_for_host_ptr(fd, src_data);

	dst_data = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
	assert_non_null(dst_data);
	memset(dst_data, 0, dma_size);
	dst_data_device_va = hltests_get_device_va_for_host_ptr(fd, dst_data);

	/* DMA of data host->sram */
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE, src_data_device_va,
				device_data_address, dma_size,
				GOYA_DMA_HOST_TO_SRAM);

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);

	/* Create internal CB for the engine */
	engine_cb = hltests_create_cb(fd, 64, INTERNAL, cb_engine_address);
	assert_non_null(engine_cb);
	engine_cb_device_va = hltests_get_device_va_for_host_ptr(fd, engine_cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	engine_cb_size = hltests_add_write_to_sob_pkt(fd, engine_cb,
								0, &pkt_info);

	/* DMA of cb engine host->sram */
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE, engine_cb_device_va,
				cb_engine_address,
				engine_cb_size, GOYA_DMA_HOST_TO_SRAM);

	/* Clear SOB0 */
	hltests_clear_sobs(fd, 1);

	/* Create CB for DMA that waits on internal engine and then performs
	 * a DMA down to the data address on the sram
	 */
	ext_cb = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(ext_cb);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	offset = hltests_add_monitor_and_fence(fd, ext_cb, 0,
						&mon_and_fence_info);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = device_data_address;
	pkt_info.dma.dst_addr = dst_data_device_va;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = GOYA_DMA_SRAM_TO_HOST;
	offset = hltests_add_dma_pkt(fd, ext_cb, offset, &pkt_info);

	execute_arr[0].cb_ptr = ext_cb;
	execute_arr[0].cb_size = offset;
	execute_arr[0].queue_index = hltests_get_dma_up_qid(fd, STREAM0);

	execute_arr[1].cb_ptr = engine_cb;
	execute_arr[1].cb_size = engine_cb_size;
	execute_arr[1].queue_index = engine_qid;

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, engine_cb);
	assert_int_equal(rc, 0);

	if (is_wait) {
		uint32_t i, err_cnt = 0;

		rc = hltests_wait_for_cs_until_not_busy(fd, seq);
		assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

		rc = hltests_destroy_cb(fd, ext_cb);
		assert_int_equal(rc, 0);

		for (i = 0 ; (i < dma_size) && (err_cnt < 100) ; i += 4) {
			if (((uint32_t *) src_data)[i] !=
						((uint32_t *) dst_data)[i]) {
				err_cnt++;
			}
		}

		assert_int_equal(err_cnt, 0);

		hltests_free_host_mem(fd, src_data);
		hltests_free_host_mem(fd, dst_data);
	}
}

static void test_sm_pingpong_upper_cp(void **state, bool is_tpc,
				bool upper_cb_in_host, uint8_t engine_id)
{
	struct hltests_state *tests_state =
			(struct hltests_state *) *state;
	void *src_data, *dst_data, *engine_cb, *restore_cb, *dmadown_cb,
		*dmaup_cb;
	uint64_t src_data_device_va, dst_data_device_va, device_data_address,
		engine_cb_sram_addr, engine_cb_device_va;
	struct hltests_cs_chunk restore_arr[1], execute_arr[3];
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t dma_size = 4, engine_cb_size, restore_cb_size = 0,
			dmadown_cb_size, dmaup_cb_size, i, err_cnt = 0;
	int rc, engine_qid, fd = tests_state->fd;
	uint64_t seq;
	uint16_t sob[2], mon[2];

	/* Check conditions if CB is in the host */
	if (upper_cb_in_host) {

		/* This test can't run on Goya */
		if (hlthunk_get_device_name_from_fd(fd) ==
						HLTHUNK_DEVICE_GOYA) {
			printf(
				"Test is skipped. Goya's common CP can't be in host\n");
			skip();
		}

		/* This test can't run if mmu disabled */
		if (!tests_state->mmu) {
			printf(
				"Test is skipped. MMU must be enabled\n");
			skip();
		}
	}

	/* Get device information, especially tpc enabled mask */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_tpc)
		engine_qid = hltests_get_tpc_qid(fd, engine_id, STREAM0);
	else
		engine_qid = hltests_get_mme_qid(fd, engine_id, STREAM0);

	/* SRAM MAP (base + )
	 * 0x1000 : data
	 * 0x2000 : engine's internal CB (we only use upper CP in this test)
	 *
	 * NOTE:
	 * The engine's upper CB can be located on the host, depending on
	 * the upper_cb_in_host flag
	 *
	 * Test description:
	 * DMA1 QMAN will transfer data to device and then signal the Engine's
	 * QMAN. It will signal DMA2 QMAN that will transfer the data from the
	 * device to the host.
	 * Setup CB will be used to clear SOB and to download the Engine's CB
	 * to the SRAM
	 */

	device_data_address = hw_ip.sram_base_address + 0x1000;

	if (upper_cb_in_host)
		engine_cb_sram_addr = 0;
	else
		engine_cb_sram_addr = hw_ip.sram_base_address + 0x2000;

	hltests_clear_sobs(fd, 2);

	/* Allocate two buffers on the host for data transfers */
	src_data = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
	assert_non_null(src_data);
	hltests_fill_rand_values(src_data, dma_size);
	src_data_device_va = hltests_get_device_va_for_host_ptr(fd, src_data);

	dst_data = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
	assert_non_null(dst_data);
	memset(dst_data, 0, dma_size);
	dst_data_device_va = hltests_get_device_va_for_host_ptr(fd, dst_data);

	sob[0] = hltests_get_first_avail_sob(fd);
	sob[1] = hltests_get_first_avail_sob(fd) + 1;
	mon[0] = hltests_get_first_avail_mon(fd);
	mon[1] = hltests_get_first_avail_mon(fd) + 1;

	/* Create internal CB for the engine. It will fence on SOB0 and signal
	 * SOB1
	 */
	engine_cb = hltests_create_cb(fd, 512, INTERNAL, engine_cb_sram_addr);
	assert_non_null(engine_cb);
	engine_cb_device_va = hltests_get_device_va_for_host_ptr(fd, engine_cb);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = engine_qid;
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob[0];
	mon_and_fence_info.mon_id = mon[0];
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	engine_cb_size = hltests_add_monitor_and_fence(fd, engine_cb, 0,
							&mon_and_fence_info);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob[1];
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	engine_cb_size = hltests_add_write_to_sob_pkt(fd, engine_cb,
						engine_cb_size, &pkt_info);

	/* Restore CB will download the engine's CB to the SRAM */
	if (engine_cb_sram_addr) {
		restore_cb = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
		assert_non_null(restore_cb);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.dma.src_addr = engine_cb_device_va;
		pkt_info.dma.dst_addr = engine_cb_sram_addr;
		pkt_info.dma.size = engine_cb_size;
		pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_SRAM;
		restore_cb_size = hltests_add_dma_pkt(fd, restore_cb,
						restore_cb_size, &pkt_info);
	}

	/* Create CB for DMA down that downloads data to device and signal the
	 * engine
	 */
	dmadown_cb = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(dmadown_cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = src_data_device_va;
	pkt_info.dma.dst_addr = device_data_address;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_SRAM;
	dmadown_cb_size = hltests_add_dma_pkt(fd, dmadown_cb, 0, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob[0];
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	dmadown_cb_size = hltests_add_write_to_sob_pkt(fd, dmadown_cb,
					dmadown_cb_size, &pkt_info);

	/* Create CB for DMA up that waits on internal engine and then
	 * performs a DMA up of the data address on the sram
	 */
	dmaup_cb = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(dmaup_cb);
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob[1];
	mon_and_fence_info.mon_id = mon[1];
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	dmaup_cb_size = hltests_add_monitor_and_fence(fd, dmaup_cb, 0,
							&mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = device_data_address;
	pkt_info.dma.dst_addr = dst_data_device_va;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = GOYA_DMA_SRAM_TO_HOST;
	dmaup_cb_size = hltests_add_dma_pkt(fd, dmaup_cb,
					dmaup_cb_size, &pkt_info);

	if (engine_cb_sram_addr) {
		restore_arr[0].cb_ptr = restore_cb;
		restore_arr[0].cb_size = restore_cb_size;
		restore_arr[0].queue_index =
				hltests_get_dma_down_qid(fd, STREAM0);
	}

	execute_arr[0].cb_ptr = dmaup_cb;
	execute_arr[0].cb_size = dmaup_cb_size;
	execute_arr[0].queue_index =
				hltests_get_dma_up_qid(fd, STREAM0);

	execute_arr[1].cb_ptr = engine_cb;
	execute_arr[1].cb_size = engine_cb_size;
	execute_arr[1].queue_index = engine_qid;

	execute_arr[2].cb_ptr = dmadown_cb;
	execute_arr[2].cb_size = dmadown_cb_size;
	execute_arr[2].queue_index =
			hltests_get_dma_down_qid(fd, STREAM0);

	if (engine_cb_sram_addr)
		rc = hltests_submit_cs(fd, restore_arr, 1, execute_arr, 3,
						CS_FLAGS_FORCE_RESTORE, &seq);
	else
		rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 3, 0, &seq);

	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_destroy_cb(fd, engine_cb);
	assert_int_equal(rc, 0);

	if (engine_cb_sram_addr) {
		rc = hltests_destroy_cb(fd, restore_cb);
		assert_int_equal(rc, 0);
	}

	rc = hltests_destroy_cb(fd, dmadown_cb);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, dmaup_cb);
	assert_int_equal(rc, 0);

	for (i = 0 ; (i < dma_size) && (err_cnt < 100) ; i += 4) {
		if (((uint32_t *) src_data)[i] !=
					((uint32_t *) dst_data)[i]) {
			err_cnt++;
		}
	}

	assert_int_equal(err_cnt, 0);

	hltests_free_host_mem(fd, src_data);
	hltests_free_host_mem(fd, dst_data);
}

void test_sm_tpc(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t tpc_id, tpc_cnt;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.tpc_enabled_mask) {
		printf("TPCs are disabled so skipping test\n");
		skip();
	}

	tpc_cnt = hltests_get_tpc_cnt(fd);
	for (tpc_id = 0 ; tpc_id < tpc_cnt ; tpc_id++)
		if (hw_ip.tpc_enabled_mask & (0x1 << tpc_id))
			test_sm(state, true, true, tpc_id);
}

void test_sm_mme(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t mme_id, mme_cnt;
	int rc, fd = tests_state->fd;

	if (!tests_state->mme) {
		printf("MME is disabled so skipping test\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	mme_cnt = hltests_get_mme_cnt(fd);
	for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++)
		test_sm(state, false, true, mme_id);
}

void test_sm_pingpong_tpc_upper_cp_from_sram(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t tpc_id, tpc_cnt;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.tpc_enabled_mask) {
		printf("TPCs are disabled so skipping test\n");
		skip();
	}

	tpc_cnt = hltests_get_tpc_cnt(fd);
	for (tpc_id = 0 ; tpc_id < tpc_cnt ; tpc_id++)
		if (hw_ip.tpc_enabled_mask & (0x1 << tpc_id))
			test_sm_pingpong_upper_cp(state, true, false, tpc_id);
}

void test_sm_pingpong_mme_upper_cp_from_sram(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t mme_id, mme_cnt;
	int rc, fd = tests_state->fd;

	if (!tests_state->mme) {
		printf("MME is disabled so skipping test\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	mme_cnt = hltests_get_mme_cnt(fd);
	for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++)
		test_sm_pingpong_upper_cp(state, false, false, mme_id);
}

void test_sm_pingpong_tpc_upper_cp_from_host(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t tpc_id, tpc_cnt;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.tpc_enabled_mask) {
		printf("TPCs are disabled so skipping test\n");
		skip();
	}

	tpc_cnt = hltests_get_tpc_cnt(fd);
	for (tpc_id = 0 ; tpc_id < tpc_cnt ; tpc_id++)
		if (hw_ip.tpc_enabled_mask & (0x1 << tpc_id))
			test_sm_pingpong_upper_cp(state, true, true, tpc_id);
}

void test_sm_pingpong_mme_upper_cp_from_host(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t mme_id, mme_cnt;
	int rc, fd = tests_state->fd;

	if (!tests_state->mme) {
		printf("MME is disabled so skipping test\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	mme_cnt = hltests_get_mme_cnt(fd);
	for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++)
		test_sm_pingpong_upper_cp(state, false, true, mme_id);
}

void test_sm_pingpong_tpc_common_cp_from_sram(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t tpc_id, tpc_cnt;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.tpc_enabled_mask) {
		printf("TPCs are disabled so skipping test\n");
		skip();
	}

	tpc_cnt = hltests_get_tpc_cnt(fd);
	for (tpc_id = 0 ; tpc_id < tpc_cnt ; tpc_id++)
		if (hw_ip.tpc_enabled_mask & (0x1 << tpc_id))
			test_sm_pingpong_common_cp(state, true, false, tpc_id);
}

void test_sm_pingpong_mme_common_cp_from_sram(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t mme_id, mme_cnt;
	int rc, fd = tests_state->fd;

	if (!tests_state->mme) {
		printf("MME is disabled so skipping test\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	mme_cnt = hltests_get_mme_cnt(fd);
	for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++)
		test_sm_pingpong_common_cp(state, false, false, mme_id);
}

void test_sm_pingpong_tpc_common_cp_from_host(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t tpc_id, tpc_cnt;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.tpc_enabled_mask) {
		printf("TPCs are disabled so skipping test\n");
		skip();
	}

	tpc_cnt = hltests_get_tpc_cnt(fd);
	for (tpc_id = 0 ; tpc_id < tpc_cnt ; tpc_id++)
		if (hw_ip.tpc_enabled_mask & (0x1 << tpc_id))
			test_sm_pingpong_common_cp(state, true, true, tpc_id);
}

void test_sm_pingpong_mme_common_cp_from_host(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t mme_id, mme_cnt;
	int rc, fd = tests_state->fd;

	if (!tests_state->mme) {
		printf("MME is disabled so skipping test\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	mme_cnt = hltests_get_mme_cnt(fd);
	for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++)
		test_sm_pingpong_common_cp(state, false, true, mme_id);
}

void test_sm_sob_cleanup_on_ctx_switch(void **state)
{
	struct hltests_state *tests_state =
				(struct hltests_state *) *state;
	char pci_bus_id[13];
	void *cb;
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t cb_size;
	uint16_t sob0, mon0;
	int rc, fd = tests_state->fd;

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);

	/* Create CB that sets SOB0 to a non-zero value */
	cb = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = sob0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, 0, &pkt_info);

	hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);

	/* Close and reopen the FD to cause a context switch */
	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	assert_int_equal(rc, 0);
	rc = hltests_close(fd);
	assert_int_equal(rc, 0);
	fd = tests_state->fd = hltests_open(pci_bus_id);
	assert_in_range(fd, 0, INT_MAX);

	/*
	 * Create CB that waits on SOB0 till it is zero.
	 * SOB0 is expected to be zeroed due to the context switch.
	 */
	cb = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(cb);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_down_qid(fd, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 0;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_size = hltests_add_monitor_and_fence(fd, cb, 0, &mon_and_fence_info);

	hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

static void *test_signal_wait_th(void *args)
{
	struct signal_wait_thread_params *params =
				(struct signal_wait_thread_params *) args;
	struct hlthunk_signal_in sig_in;
	struct hlthunk_signal_out sig_out;
	struct hlthunk_wait_in wait_in;
	struct hlthunk_wait_out wait_out;
	struct hlthunk_wait_for_signal wait_for_signal;
	int i, rc, fd = params->fd, queue_id = params->queue_id, iters;

	/* the max value of an SOB is 1 << 15 so we want to test a wraparound */
	iters = 3 * ((1 << 15) + (1 << 14));

	for (i = 0 ; i < iters ; i++) {
		memset(&sig_in, 0, sizeof(sig_in));
		memset(&sig_out, 0, sizeof(sig_out));
		memset(&wait_in, 0, sizeof(wait_in));
		memset(&wait_out, 0, sizeof(wait_out));
		memset(&wait_for_signal, 0, sizeof(wait_for_signal));

		sig_in.queue_index = queue_id;

		rc = hlthunk_signal_submission(fd, &sig_in, &sig_out);
		assert_int_equal(rc, 0);

		if (i & 1) {
			rc = hltests_wait_for_cs_until_not_busy(fd,
								sig_out.seq);
			assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);
		}

		wait_for_signal.queue_index = 7 - queue_id;
		wait_for_signal.signal_seq_arr = &sig_out.seq;
		wait_for_signal.signal_seq_nr = 1;
		wait_in.hlthunk_wait_for_signal = (uint64_t *) &wait_for_signal;
		wait_in.num_wait_for_signal = 1;

		rc = hlthunk_wait_for_signal(fd, &wait_in, &wait_out);
		assert_int_equal(rc, 0);

		/* check if the signal CS already finished */
		if (wait_out.seq == ULLONG_MAX)
			continue;

		rc = hltests_wait_for_cs_until_not_busy(fd, wait_out.seq);
		assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);
	}

	return args;
}

static void *test_signal_wait_parallel_th(void *args)
{
	struct signal_wait_thread_params *params =
				(struct signal_wait_thread_params *) args;
	struct hlthunk_signal_in sig_in;
	struct hlthunk_signal_out sig_out;
	struct hlthunk_wait_in wait_in;
	struct hlthunk_wait_out wait_out;
	struct hlthunk_wait_for_signal wait_for_signal;
	int i, j, rc, fd = params->fd, queue_id = params->queue_id;
	int iters = 1000;

	for (j = 0 ; j < iters ; j++) {
		if (queue_id & 1) {
			for (i = 0 ; i < SIG_WAIT_CS ; i++) {
				memset(&sig_in, 0, sizeof(sig_in));
				memset(&sig_out, 0, sizeof(sig_out));

				sig_in.queue_index = queue_id;

				rc = hlthunk_signal_submission(fd, &sig_in,
								&sig_out);
				assert_int_equal(rc, 0);

				sig_seqs[i] = sig_out.seq;

				/*
				 * On every odd iteration, wait for the waiter
				 * to finish so on the next iteration the signal
				 * won't finish before the wait begins.
				 */
				if (i & 1)
					while (atomic_read(&sig_seqs[i]))
						;
			}

			/*
			 * Wait for the last waiter to finish before starting a
			 * new iteration
			 */
			while (atomic_read(&sig_seqs[SIG_WAIT_CS - 1]))
				;
		} else {
			uint64_t sig_seq;
			uint32_t collective_engine = params->engine_id;

			for (i = 0 ; i < SIG_WAIT_CS ; i++) {
				memset(&wait_in, 0, sizeof(wait_in));
				memset(&wait_out, 0, sizeof(wait_out));
				memset(&wait_for_signal, 0,
					sizeof(wait_for_signal));

				/* Wait for a valid signal sequence number */
				while (atomic_read(&sig_seqs[i]) == 0)
					;

				sig_seq = sig_seqs[i];

				wait_for_signal.queue_index =
							7 - queue_id;
				wait_for_signal.signal_seq_arr = &sig_seq;
				wait_for_signal.signal_seq_nr = 1;
				wait_for_signal.collective_engine_id =
						collective_engine;
				wait_in.hlthunk_wait_for_signal =
						(uint64_t *) &wait_for_signal;
				wait_in.num_wait_for_signal = 1;

				if (params->collective_wait) {
					rc =
					hlthunk_wait_for_collective_signal(fd,
							&wait_in, &wait_out);
					assert_int_equal(rc, 0);
				} else {
					rc = hlthunk_wait_for_signal(fd,
							&wait_in, &wait_out);
					assert_int_equal(rc, 0);
				}

				sig_seqs[i] = 0;

				/* check if the signal CS already finished */
				if (wait_out.seq == ULLONG_MAX)
					continue;

				rc = hltests_wait_for_cs_until_not_busy(fd,
								wait_out.seq);
				assert_int_equal(rc,
						HL_WAIT_CS_STATUS_COMPLETED);
			}
		}
	}

	return args;
}

/*
 * test_signal_wait_dma_th() - this thread function does DMA from host to device
 * (down) on queue 0 and DMA from device to host (up) on queue 4.
 * It basically checks that the DMA up waits for the DMA down to finish before
 * starting execution.
 * This is done with the new sync stream but also the classic signaling
 * mechanism is supported for debug.
 * In addition, the DMA size should be big enough so the DMA down won't
 * naturally finish before DMA up started regardless of the signaling.
 */
static void *test_signal_wait_dma_th(void *args)
{
	struct signal_wait_thread_params *params =
				(struct signal_wait_thread_params *) args;
	struct hltests_cs_chunk execute_arr[1];
	struct hltests_pkt_info pkt_info;
	struct hlthunk_signal_in sig_in;
	struct hlthunk_signal_out sig_out;
	struct hlthunk_wait_in wait_in;
	struct hlthunk_wait_out wait_out;
	struct hlthunk_wait_for_signal wait_for_signal;
	void *buf[2], *cb[2], *dram_ptr;
	uint64_t dram_addr, device_va[2], seq[3];
	uint32_t dma_size, cb_size[2], queue_down, queue_up,
			collective_engine = params->engine_id;
	int i, j, rc, fd = params->fd;

	queue_down = hltests_get_dma_down_qid(fd, STREAM0);
	queue_up = hltests_get_dma_up_qid(fd, STREAM0);

	if (hltests_is_simulator(fd)) {
		dma_size = 1 << 24;
		j = 10;
	} else {
		dma_size = 1 << 27;
		j = 100;
	}

	dram_ptr = hltests_allocate_device_mem(fd, dma_size, CONTIGUOUS);
	assert_non_null(dram_ptr);
	dram_addr = (uint64_t) (uintptr_t) dram_ptr;

	for (i = 0 ; i < 2 ; i++) {
		cb[i] = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
		assert_non_null(cb[i]);
	}

	for (i = 0 ; i < 2 ; i++) {
		buf[i] = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
		assert_non_null(buf[i]);
		device_va[i] = hltests_get_device_va_for_host_ptr(fd, buf[i]);
	}

	hltests_fill_rand_values(buf[0], dma_size);

	while (j--) {
		memset(buf[1], 0, dma_size);
		memset(cb_size, 0, sizeof(cb_size));

		/* DMA down */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.dma.src_addr = device_va[0];
		pkt_info.dma.dst_addr = (uint64_t) (uintptr_t) dram_addr;
		pkt_info.dma.size = dma_size;
		pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_DRAM;
		cb_size[0] = hltests_add_dma_pkt(fd, cb[0], cb_size[0],
						&pkt_info);

		execute_arr[0].cb_ptr = cb[0];
		execute_arr[0].cb_size = cb_size[0];
		execute_arr[0].queue_index = queue_down;

		rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq[0]);
		assert_int_equal(rc, 0);

		memset(&sig_in, 0, sizeof(sig_in));
		memset(&sig_out, 0, sizeof(sig_out));
		memset(&wait_in, 0, sizeof(wait_in));
		memset(&wait_out, 0, sizeof(wait_out));

		sig_in.queue_index = queue_down;
		rc = hlthunk_signal_submission(fd, &sig_in, &sig_out);
		assert_int_equal(rc, 0);

		wait_for_signal.queue_index = queue_up;
		wait_for_signal.signal_seq_arr = &sig_out.seq;
		wait_for_signal.signal_seq_nr = 1;
		wait_for_signal.collective_engine_id =
					collective_engine;
		wait_in.hlthunk_wait_for_signal =
					(uint64_t *) &wait_for_signal;
		wait_in.num_wait_for_signal = 1;

		if (params->collective_wait) {
			rc = hlthunk_wait_for_collective_signal(fd, &wait_in,
								&wait_out);
			assert_int_equal(rc, 0);
		} else {
			rc = hlthunk_wait_for_signal(fd, &wait_in, &wait_out);
			assert_int_equal(rc, 0);
		}

		/* DMA up */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.dma.src_addr = (uint64_t) (uintptr_t) dram_addr;
		pkt_info.dma.dst_addr = device_va[1];
		pkt_info.dma.size = dma_size;
		pkt_info.dma.dma_dir = GOYA_DMA_DRAM_TO_HOST;
		cb_size[1] = hltests_add_dma_pkt(fd, cb[1], cb_size[1],
						&pkt_info);

		execute_arr[0].cb_ptr = cb[1];
		execute_arr[0].cb_size = cb_size[1];
		execute_arr[0].queue_index = queue_up;

		rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq[1]);
		assert_int_equal(rc, 0);

		/* Wait for DMA up to finish */
		rc = hltests_wait_for_cs_until_not_busy(fd, seq[1]);
		assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

		/* compare host memories */
		rc = hltests_mem_compare(buf[0], buf[1], dma_size);
		assert_int_equal(rc, 0);
	}

	/* cleanup */
	rc = hltests_free_device_mem(fd, dram_ptr);
	assert_int_equal(rc, 0);

	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_free_host_mem(fd, buf[i]);
		assert_int_equal(rc, 0);
	}

	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_destroy_cb(fd, cb[i]);
		assert_int_equal(rc, 0);
	}

	return args;
}

static void _test_signal_wait(void **state, bool collective_wait,
		void *(*__start_routine)(void *))
{
	struct hltests_state *tests_state =
			(struct hltests_state *) *state;
	struct signal_wait_thread_params *thread_params;
	struct hlthunk_hw_ip_info hw_ip;
	int i, rc, fd = tests_state->fd;
	pthread_t *thread_id;
	void *retval;

	if (hltests_is_goya(fd) || hltests_is_pldm(fd)) {
		printf("Test not supported on Goya/PLDM, skipping.\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	/* Allocate arrays for threads management */
	thread_id = (pthread_t *) hlthunk_malloc(SIG_WAIT_TH *
							sizeof(*thread_id));
	assert_non_null(thread_id);

	thread_params = (struct signal_wait_thread_params *)
			hlthunk_malloc(SIG_WAIT_TH * sizeof(*thread_params));
	assert_non_null(thread_params);

	/* Create and execute threads */
	for (i = 0 ; i < SIG_WAIT_TH ; i++) {
		thread_params[i].fd = fd;
		thread_params[i].queue_id = i;
		thread_params[i].collective_wait = collective_wait;
		thread_params[i].engine_id = GAUDI_ENGINE_ID_DMA_5;

		rc = pthread_create(&thread_id[i], NULL, __start_routine,
					&thread_params[i]);
		assert_int_equal(rc, 0);
	}

	/* Wait for the termination of the threads */
	for (i = 0 ; i < SIG_WAIT_TH ; i++) {
		rc = pthread_join(thread_id[i], &retval);
		assert_int_equal(rc, 0);
		assert_non_null(retval);
	}

	hlthunk_free(thread_id);
	hlthunk_free(thread_params);
}

static void test_signal_wait(void **state)
{
	int fd = ((struct hltests_state *)*state)->fd;

	if (hltests_is_simulator(fd) &&
	    !hltests_get_parser_run_disabled_tests()) {
		printf("Test is skipped by default in simulator\n");
		skip();
	}

	_test_signal_wait(state, false, test_signal_wait_th);
}

static void test_signal_wait_parallel(void **state)
{
	_test_signal_wait(state, false, test_signal_wait_parallel_th);
}

static void test_signal_collective_wait_parallel(void **state)
{
	int fd = ((struct hltests_state *)*state)->fd;

	if (!hltests_is_gaudi(fd)) {
		printf("Test is relevant only for Gaudi, skipping\n");
		skip();
	}

	_test_signal_wait(state, true, test_signal_wait_parallel_th);
}

static void test_signal_wait_dma(void **state)
{
	_test_signal_wait(state, false, test_signal_wait_dma_th);
}

static void test_signal_collective_wait_dma(void **state)
{
	int fd = ((struct hltests_state *)*state)->fd;

	if (!hltests_is_gaudi(fd)) {
		printf("Test is relevant only for Gaudi, skipping\n");
		skip();
	}

	_test_signal_wait(state, true, test_signal_wait_dma_th);
}

const struct CMUnitTest sm_tests[] = {
	cmocka_unit_test_setup(test_sm_tpc, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_mme, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_pingpong_tpc_upper_cp_from_sram,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_pingpong_mme_upper_cp_from_sram,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_pingpong_tpc_upper_cp_from_host,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_pingpong_mme_upper_cp_from_host,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_pingpong_tpc_common_cp_from_sram,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_pingpong_mme_common_cp_from_sram,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_pingpong_tpc_common_cp_from_host,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_pingpong_mme_common_cp_from_host,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_sob_cleanup_on_ctx_switch,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_signal_wait,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_signal_wait_parallel,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_signal_wait_dma,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_signal_collective_wait_dma,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_signal_collective_wait_parallel,
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"sync_manager [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(sm_tests) / sizeof((sm_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE, sm_tests,
			num_tests);

	return hltests_run_group_tests("sync_manager", sm_tests, num_tests,
					hltests_setup, hltests_teardown);
}
