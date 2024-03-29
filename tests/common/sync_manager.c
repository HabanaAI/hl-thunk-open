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

#define SIG_WAIT_TH	2
#define SIG_WAIT_CS	(64 / SIG_WAIT_TH)

struct signal_wait_thread_params {
	int fd;
	int queue_id;
	bool collective_wait;
	int engine_id;
	bool result;
};

struct encaps_sig_wait_thread_params {
	int fd;
	int count;
	bool collective_wait;
	int engine_id;
	pthread_barrier_t *barrier;
	int thread_id;
	uint32_t q_idx;
};

static uint64_t sig_seqs[SIG_WAIT_CS];

static uint64_t atomic_read(uint64_t *ptr)
{
	return __sync_fetch_and_add(ptr, 0);
}

VOID test_sm(void **state, bool is_tpc, bool is_wait, uint8_t engine_id)
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
	int rc, engine_qid, dma_qid, fd = tests_state->fd;
	uint64_t seq;
	uint16_t sob0, mon0;

	/* Get device information, especially tpc enabled mask */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	if (is_tpc)
		engine_qid = hltests_get_tpc_qid(fd, engine_id, STREAM0);
	else
		engine_qid = hltests_get_mme_qid(fd, engine_id, STREAM0);

	/* SRAM MAP (base + )
	 * 0x1000 : data
	 * 0x2000 : engine's internal CB (we only use upper CP in this test)
	 */

	device_data_address = hw_ip.sram_base_address + 0x1000;
	/*
	 * If we using arcs (non legacy mode) we can't patch CB located on SRAM, hence use
	 * zero in address, so the CB will be allocated on host memory.
	 */
	cb_engine_address = hltests_is_legacy_mode_enabled(fd) ?
					(hw_ip.sram_base_address + 0x2000) : 0;

	/* Allocate two buffers on the host for data transfers */
	src_data = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
	assert_non_null(src_data);
	hltests_fill_rand_values(src_data, dma_size);
	src_data_device_va = hltests_get_device_va_for_host_ptr(fd, src_data);

	dst_data = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
	assert_non_null(dst_data);
	memset(dst_data, 0, dma_size);
	dst_data_device_va = hltests_get_device_va_for_host_ptr(fd, dst_data);

	/* DMA of data host->sram */
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE, src_data_device_va,
				device_data_address, dma_size,
				DMA_DIR_HOST_TO_SRAM);

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);

	/* Create internal CB for the engine */
	engine_cb = hltests_create_cb(fd, SZ_4K, INTERNAL, cb_engine_address);
	assert_non_null(engine_cb);
	engine_cb_device_va = hltests_get_device_va_for_host_ptr(fd, engine_cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = engine_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	engine_cb_size = hltests_add_write_to_sob_pkt(fd, engine_cb,
								0, &pkt_info);
	if (hltests_is_legacy_mode_enabled(fd))
	/* DMA of cb engine host->sram */
		hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE, engine_cb_device_va,
				cb_engine_address,
				engine_cb_size, DMA_DIR_HOST_TO_SRAM);

	/* Clear SOB0 */
	hltests_clear_sobs(fd, 1);

	/* Create CB for DMA that waits on internal engine and then performs
	 * a DMA down to the data address on the sram
	 */
	ext_cb = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(ext_cb);

	dma_qid = hltests_get_dma_up_qid(fd, STREAM0);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = dma_qid;
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
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = device_data_address;
	pkt_info.dma.dst_addr = dst_data_device_va;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = DMA_DIR_SRAM_TO_HOST;
	offset = hltests_add_dma_pkt(fd, ext_cb, offset, &pkt_info);

	execute_arr[0].cb_ptr = ext_cb;
	execute_arr[0].cb_size = offset;
	execute_arr[0].queue_index = dma_qid;

	execute_arr[1].cb_ptr = engine_cb;
	execute_arr[1].cb_size = engine_cb_size;
	execute_arr[1].queue_index = engine_qid;

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2, 0, &seq);
	assert_int_equal(rc, 0);

	if (is_wait) {
		uint32_t i, err_cnt = 0;

		rc = hltests_wait_for_cs(fd, seq, WAIT_FOR_CS_DEFAULT_TIMEOUT);
		assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

		for (i = 0 ; (i < dma_size) && (err_cnt < 100) ; i += 4) {
			if (((uint32_t *) src_data)[i] !=
						((uint32_t *) dst_data)[i]) {
				err_cnt++;
			}
		}

		assert_int_equal(err_cnt, 0);
	}

	rc = hltests_destroy_cb(fd, engine_cb);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, ext_cb);
	assert_int_equal(rc, 0);

	hltests_free_host_mem(fd, src_data);
	hltests_free_host_mem(fd, dst_data);

	END_TEST;
}

VOID test_sm_pingpong_upper_cp(void **state, bool is_tpc,
				bool upper_cb_in_host, uint8_t engine_id)
{
	struct hltests_state *tests_state =
			(struct hltests_state *) *state;
	void *src_data, *dst_data, *engine_cb, *restore_cb = NULL, *dmadown_cb,
		*dmaup_cb;
	uint64_t src_data_device_va, dst_data_device_va, device_data_address,
		engine_cb_sram_addr, engine_cb_device_va;
	struct hltests_cs_chunk restore_arr[1], execute_arr[3];
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t dma_size = 4, engine_cb_size, restore_cb_size = 0,
			dmadown_cb_size, dmaup_cb_size, i, err_cnt = 0;
	uint16_t sob[2], mon[2], dma_down_qid, dma_up_qid;
	int rc, engine_qid, fd = tests_state->fd;
	uint64_t seq;

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
			printf("Test is skipped when MMU is disabled\n");
			skip();
		}
	}

	/* Get device information, especially tpc enabled mask */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	if (is_tpc)
		engine_qid = hltests_get_tpc_qid(fd, engine_id, STREAM0);
	else
		engine_qid = hltests_get_mme_qid(fd, engine_id, STREAM0);

	dma_down_qid = hltests_get_dma_down_qid(fd, STREAM0);
	dma_up_qid = hltests_get_dma_up_qid(fd, STREAM0);

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
	src_data = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
	assert_non_null(src_data);
	hltests_fill_rand_values(src_data, dma_size);
	src_data_device_va = hltests_get_device_va_for_host_ptr(fd, src_data);

	dst_data = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
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
	pkt_info.qid = engine_qid;
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
		pkt_info.qid = dma_down_qid;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.dma.src_addr = engine_cb_device_va;
		pkt_info.dma.dst_addr = engine_cb_sram_addr;
		pkt_info.dma.size = engine_cb_size;
		pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;
		restore_cb_size = hltests_add_dma_pkt(fd, restore_cb,
						restore_cb_size, &pkt_info);
	}

	/* Create CB for DMA down that downloads data to device and signal the
	 * engine
	 */
	dmadown_cb = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(dmadown_cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_down_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = src_data_device_va;
	pkt_info.dma.dst_addr = device_data_address;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;
	dmadown_cb_size = hltests_add_dma_pkt(fd, dmadown_cb, 0, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_down_qid;
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.qid = hltests_get_dma_down_qid(fd, STREAM0);
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
	mon_and_fence_info.queue_id = dma_up_qid;
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
	pkt_info.qid = dma_up_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = device_data_address;
	pkt_info.dma.dst_addr = dst_data_device_va;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = DMA_DIR_SRAM_TO_HOST;
	dmaup_cb_size = hltests_add_dma_pkt(fd, dmaup_cb,
					dmaup_cb_size, &pkt_info);

	if (engine_cb_sram_addr) {
		restore_arr[0].cb_ptr = restore_cb;
		restore_arr[0].cb_size = restore_cb_size;
		restore_arr[0].queue_index = dma_down_qid;
	}

	execute_arr[0].cb_ptr = dmaup_cb;
	execute_arr[0].cb_size = dmaup_cb_size;
	execute_arr[0].queue_index = dma_up_qid;

	execute_arr[1].cb_ptr = engine_cb;
	execute_arr[1].cb_size = engine_cb_size;
	execute_arr[1].queue_index = engine_qid;

	execute_arr[2].cb_ptr = dmadown_cb;
	execute_arr[2].cb_size = dmadown_cb_size;
	execute_arr[2].queue_index = dma_down_qid;

	if (engine_cb_sram_addr)
		rc = hltests_submit_cs(fd, restore_arr, 1, execute_arr, 3,
					HL_CS_FLAGS_FORCE_RESTORE, &seq);
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

	END_TEST;
}

VOID test_sm_tpc(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t tpc_id, tpc_cnt;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.tpc_enabled_mask_ext) {
		printf("TPCs are disabled so skipping test\n");
		skip();
	}

	tpc_cnt = hltests_get_tpc_cnt(fd);
	for (tpc_id = 0 ; tpc_id < tpc_cnt ; tpc_id++)
		if (hw_ip.tpc_enabled_mask_ext & (0x1 << tpc_id))
			test_sm(state, true, true, tpc_id);

	END_TEST;
}

VOID test_sm_mme(void **state)
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

	/* In gaudi2 mme1 and mme3 arcs are working as schedulers */
	if (!hltests_is_legacy_mode_enabled(fd) && hltests_is_gaudi2(fd)) {
		test_sm(state, false, true, 0);
		test_sm(state, false, true, 2);
	} else {
		mme_cnt = hltests_get_mme_cnt(fd, hw_ip.mme_master_slave_mode);
		for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++)
			test_sm(state, false, true, mme_id);
	}

	END_TEST;
}

VOID test_sm_pingpong_tpc_upper_cp_from_sram(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t tpc_id, tpc_cnt;
	int rc, fd = tests_state->fd;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is not relevant in ARC mode, skipping\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.tpc_enabled_mask_ext) {
		printf("TPCs are disabled so skipping test\n");
		skip();
	}

	tpc_cnt = hltests_get_tpc_cnt(fd);
	for (tpc_id = 0 ; tpc_id < tpc_cnt ; tpc_id++)
		if (hw_ip.tpc_enabled_mask_ext & (0x1 << tpc_id))
			test_sm_pingpong_upper_cp(state, true, false, tpc_id);

	END_TEST;
}

VOID test_sm_pingpong_mme_upper_cp_from_sram(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t mme_id, mme_cnt;
	int rc, fd = tests_state->fd;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is not relevant in ARC mode, skipping\n");
		skip();
	}

	if (!tests_state->mme) {
		printf("MME is disabled so skipping test\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	mme_cnt = hltests_get_mme_cnt(fd, hw_ip.mme_master_slave_mode);
	for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++)
		test_sm_pingpong_upper_cp(state, false, false, mme_id);

	END_TEST;
}

VOID test_sm_pingpong_tpc_upper_cp_from_host(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t tpc_id, tpc_cnt;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.tpc_enabled_mask_ext) {
		printf("TPCs are disabled so skipping test\n");
		skip();
	}

	tpc_cnt = hltests_get_tpc_cnt(fd);
	for (tpc_id = 0 ; tpc_id < tpc_cnt ; tpc_id++)
		if (hw_ip.tpc_enabled_mask_ext & (0x1 << tpc_id))
			test_sm_pingpong_upper_cp(state, true, true, tpc_id);

	END_TEST;
}

VOID test_sm_pingpong_mme_upper_cp_from_host(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t mme_id, mme_cnt;
	int rc, fd = tests_state->fd;

	/* TODO - enable test only after bug SW-65228/SW-83299 is resolved */
	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is temporarily disabled in ARC mode, skipping\n");
		skip();
	}

	if (!tests_state->mme) {
		printf("MME is disabled so skipping test\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	mme_cnt = hltests_get_mme_cnt(fd, hw_ip.mme_master_slave_mode);
	for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++)
		test_sm_pingpong_upper_cp(state, false, true, mme_id);

	END_TEST;
}

VOID test_sm_pingpong_tpc_common_cp_from_sram(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t tpc_id, tpc_cnt;
	int rc, fd = tests_state->fd;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is not relevant in ARC mode, skipping\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.tpc_enabled_mask_ext) {
		printf("TPCs are disabled so skipping test\n");
		skip();
	}

	tpc_cnt = hltests_get_tpc_cnt(fd);
	for (tpc_id = 0 ; tpc_id < tpc_cnt ; tpc_id++)
		if (hw_ip.tpc_enabled_mask_ext & (0x1 << tpc_id))
			test_sm_pingpong_common_cp(state, true, false, tpc_id);

	END_TEST;
}

VOID test_sm_pingpong_mme_common_cp_from_sram(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t mme_id, mme_cnt;
	int rc, fd = tests_state->fd;

	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is not relevant in ARC mode, skipping\n");
		skip();
	}

	if (!tests_state->mme) {
		printf("MME is disabled so skipping test\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	mme_cnt = hltests_get_mme_cnt(fd, hw_ip.mme_master_slave_mode);
	for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++)
		test_sm_pingpong_common_cp(state, false, false, mme_id);

	END_TEST;
}

VOID test_sm_pingpong_tpc_common_cp_from_host(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t tpc_id, tpc_cnt;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.tpc_enabled_mask_ext) {
		printf("TPCs are disabled so skipping test\n");
		skip();
	}

	tpc_cnt = hltests_get_tpc_cnt(fd);
	for (tpc_id = 0 ; tpc_id < tpc_cnt ; tpc_id++)
		if (hw_ip.tpc_enabled_mask_ext & (0x1 << tpc_id))
			test_sm_pingpong_common_cp(state, true, true, tpc_id);

	END_TEST;
}

VOID test_sm_pingpong_mme_common_cp_from_host(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint8_t mme_id, mme_cnt;
	int rc, fd = tests_state->fd;

	/* TODO - enable test only after bug SW-65228/SW-83299 is resolved */
	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("Test is temporarily disabled in ARC mode, skipping\n");
		skip();
	}

	if (!tests_state->mme) {
		printf("MME is disabled so skipping test\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	mme_cnt = hltests_get_mme_cnt(fd, hw_ip.mme_master_slave_mode);
	for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++)
		test_sm_pingpong_common_cp(state, false, true, mme_id);

	END_TEST;
}

VOID test_sm_sob_cleanup_on_ctx_switch(void **state)
{
	struct hltests_state *tests_state =
				(struct hltests_state *) *state;
	char pci_bus_id[13];
	void *cb;
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t cb_size, dma_qid;
	uint16_t sob0, mon0;
	int rc, fd = tests_state->fd;

	sob0 = hltests_get_first_avail_sob(fd);
	mon0 = hltests_get_first_avail_mon(fd);
	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	/* Create CB that sets SOB0 to a non-zero value */
	cb = hltests_create_cb(fd, 4096, EXTERNAL, 0);
	assert_non_null(cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = sob0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, 0, &pkt_info);

	hltests_submit_and_wait_cs(fd, cb, cb_size, dma_qid,
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);

	/* Close and reopen the FD to cause a context switch */
	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	assert_int_equal(rc, 0);
	rc = hltests_teardown_user_engines(tests_state);
	assert_int_equal(rc, 0);
	rc = hltests_close(fd);
	assert_int_equal(rc, 0);
	fd = tests_state->fd = hltests_open(pci_bus_id);
	assert_in_range(fd, 0, INT_MAX);
	rc = hltests_setup_user_engines(tests_state);
	assert_int_equal(rc, 0);

	/*
	 * Create CB that waits on SOB0 till it is zero.
	 * SOB0 is expected to be zeroed due to the context switch.
	 */
	cb = hltests_create_cb(fd, 4096, EXTERNAL, 0);
	assert_non_null(cb);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = dma_qid;
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 0;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	cb_size = hltests_add_monitor_and_fence(fd, cb, 0, &mon_and_fence_info);

	END_TEST_FUNC(hltests_submit_and_wait_cs(fd, cb, cb_size, dma_qid,
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED));
}

VOID test_sm_monitor_set_sram(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor mon_info;
	void *host_mem, *cb;
	uint64_t host_mem_device_va, sram_addr;
	uint32_t dma_size = 32, cb_max_size = 4096, cb_size = 0;
	uint16_t sob, mon, dma_down_qid, dma_up_qid;
	int rc, fd = tests_state->fd;

	if (hltests_is_gaudi(fd) || hltests_is_goya(fd)) {
		printf("Test relevant for Greco and above, skipping\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	sob = hltests_get_first_avail_sob(fd);
	mon = hltests_get_first_avail_mon(fd);
	dma_down_qid = hltests_get_dma_down_qid(fd, STREAM0);
	dma_up_qid = hltests_get_dma_up_qid(fd, STREAM0);

	/* Allocate memory on host and set the SRAM address */
	host_mem = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
	assert_non_null(host_mem);
	memset(host_mem, 0, dma_size);
	/* Make sure known value is there */
	*((uint32_t *)host_mem) = 0xDEADDAED;
	host_mem_device_va = hltests_get_device_va_for_host_ptr(fd, host_mem);

	sram_addr = hw_ip.sram_base_address + 0x1000;

	/* Setup CB: clear SOB  */
	hltests_clear_sobs(fd, 1);

	/* CB:
	 * Transfer data from host to SRAM + signal SOB0 + transfer data back
	 * from SRAM to host.
	 */

	/* Down the buffer */
	hltests_dma_transfer(fd, dma_down_qid, EB_FALSE, MB_TRUE,
			host_mem_device_va, (uint64_t) (uintptr_t) sram_addr,
			dma_size, DMA_DIR_HOST_TO_SRAM);

	/* Add monitor and set packets */
	cb = hltests_create_cb(fd, cb_max_size, EXTERNAL, 0);
	assert_non_null(cb);
	memset(cb, 0, cb_max_size);
	cb_size = 0;

	memset(&mon_info, 0, sizeof(mon_info));
	mon_info.qid = dma_down_qid;
	mon_info.sob_id = sob;
	mon_info.sob_val = 1;
	mon_info.mon_id = mon;
	mon_info.mon_address = sram_addr;
	mon_info.mon_payload = 0xFEEDDEAF;
	cb_size = hltests_add_monitor(fd, cb, cb_size, &mon_info);

	/* Add writing the desired value to the SOB */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_down_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = sob;
	pkt_info.write_to_sob.value = mon_info.sob_val;
	pkt_info.write_to_sob.mode = SOB_SET;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

	hltests_submit_and_wait_cs(fd, cb, cb_size, dma_down_qid,
			DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);

	/* Up the buffer */
	hltests_dma_transfer(fd, dma_up_qid, EB_FALSE, MB_TRUE,
			(uint64_t)(uintptr_t)sram_addr, host_mem_device_va,
			dma_size, DMA_DIR_HOST_TO_SRAM);

	/* Verify result */
	assert_true(*(uint32_t *)host_mem == mon_info.mon_payload);

	/* Cleanup */
	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, host_mem);
	assert_int_equal(rc, 0);

	END_TEST;
}

static void *test_signal_wait_th(void *args)
{
	struct signal_wait_thread_params *params =
				(struct signal_wait_thread_params *) args;
	struct hlthunk_signal_in sig_in;
	struct hlthunk_signal_out sig_out;
	struct hlthunk_wait_in wait_in;
	struct hlthunk_wait_out wait_out;
	struct hlthunk_wait_for_signal_data wait_for_signal;
	int i, rc, fd = params->fd, queue_id = params->queue_id, iters,
							max_up_queue_id;

	max_up_queue_id = 7; /* DMA1_3 */

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
		if (rc) {
			printf("signal submission failed with rc %d\n", rc);
			goto error;
		}

		if (i & 1) {
			rc = hltests_wait_for_cs_until_not_busy(fd,
								sig_out.seq);
			if (rc != HL_WAIT_CS_STATUS_COMPLETED) {
				printf("wait for cs failed with rc %d\n", rc);
				goto error;
			}
		}

		wait_for_signal.queue_index = max_up_queue_id - queue_id;
		wait_for_signal.signal_seq_arr = &sig_out.seq;
		wait_for_signal.signal_seq_nr = 1;
		wait_in.hlthunk_wait_for_signal = (uint64_t *) &wait_for_signal;
		wait_in.num_wait_for_signal = 1;

		rc = hlthunk_wait_for_signal(fd, &wait_in, &wait_out);
		if (rc) {
			printf("wait for signal failed with rc %d\n", rc);
			goto error;
		}

		/* check if the signal CS already finished */
		if (wait_out.seq == ULLONG_MAX)
			continue;

		rc = hltests_wait_for_cs_until_not_busy(fd, wait_out.seq);
		if (rc != HL_WAIT_CS_STATUS_COMPLETED) {
			printf("wait for cs failed with rc %d\n", rc);
			goto error;
		}
	}

	params->result = true;

error:
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
	struct hlthunk_wait_for_signal_data wait_for_signal;
	int i, j, rc, fd = params->fd, queue_id = params->queue_id;
	int max_up_queue_id, iters = 1100;

	max_up_queue_id = 7; /* DMA1_3 */

	for (j = 0 ; j < iters ; j++) {
		if (queue_id & 1) {
			for (i = 0 ; i < SIG_WAIT_CS ; i++) {
				memset(&sig_in, 0, sizeof(sig_in));
				memset(&sig_out, 0, sizeof(sig_out));

				sig_in.queue_index = queue_id;

				rc = hlthunk_signal_submission(fd, &sig_in,
								&sig_out);
				if (rc) {
					printf("signal submission failed(%d)\n",
						rc);
					goto error;
				}

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
						max_up_queue_id - queue_id;

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
					if (rc) {
						printf("wait sig failed(%d)\n",
							rc);
						goto error;
					}
				} else {
					rc = hlthunk_wait_for_signal(fd,
							&wait_in, &wait_out);
					if (rc) {
						printf("wait sig failed(%d)\n",
							rc);
						goto error;
					}
				}

				sig_seqs[i] = 0;

				/* check if the signal CS already finished */
				if (wait_out.seq == ULLONG_MAX)
					continue;

				rc = hltests_wait_for_cs_until_not_busy(fd,
								wait_out.seq);
				if (rc != HL_WAIT_CS_STATUS_COMPLETED) {
					printf("wait cs failed with rc %d\n",
						rc);
					goto error;
				}
			}
		}
	}

	params->result = true;

error:
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
	struct hlthunk_wait_for_signal_data wait_for_signal;
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

	dram_ptr = hltests_allocate_device_mem(fd, dma_size, 0, CONTIGUOUS);
	if (!dram_ptr) {
		printf("allocate device mem failed\n");
		goto error;
	}
	dram_addr = (uint64_t) (uintptr_t) dram_ptr;

	for (i = 0 ; i < 2 ; i++) {
		cb[i] = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
		if (!cb[i]) {
			printf("allocate cb failed\n");
			goto error;
		}

	}

	for (i = 0 ; i < 2 ; i++) {
		buf[i] = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
		if (!buf[i]) {
			printf("allocate host mem failed\n");
			goto error;
		}
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
		pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_DRAM;
		cb_size[0] = hltests_add_dma_pkt(fd, cb[0], cb_size[0],
						&pkt_info);

		execute_arr[0].cb_ptr = cb[0];
		execute_arr[0].cb_size = cb_size[0];
		execute_arr[0].queue_index = queue_down;

		rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq[0]);
		if (rc) {
			printf("submit cs failed with rc %d\n", rc);
			goto error;
		}

		memset(&sig_in, 0, sizeof(sig_in));
		memset(&sig_out, 0, sizeof(sig_out));
		memset(&wait_in, 0, sizeof(wait_in));
		memset(&wait_out, 0, sizeof(wait_out));

		sig_in.queue_index = queue_down;
		rc = hlthunk_signal_submission(fd, &sig_in, &sig_out);
		if (rc) {
			printf("signal submission failed with rc %d\n", rc);
			goto error;
		}

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
			if (rc) {
				printf("wait for signal failed(%d)\n", rc);
				goto error;
			}
		} else {
			rc = hlthunk_wait_for_signal(fd, &wait_in, &wait_out);
			if (rc) {
				printf("wait for signal failed with rc %d\n",
					rc);
				goto error;
			}
		}

		/* DMA up */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.dma.src_addr = (uint64_t) (uintptr_t) dram_addr;
		pkt_info.dma.dst_addr = device_va[1];
		pkt_info.dma.size = dma_size;
		pkt_info.dma.dma_dir = DMA_DIR_DRAM_TO_HOST;
		cb_size[1] = hltests_add_dma_pkt(fd, cb[1], cb_size[1],
						&pkt_info);

		execute_arr[0].cb_ptr = cb[1];
		execute_arr[0].cb_size = cb_size[1];
		execute_arr[0].queue_index = queue_up;

		rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, 0, &seq[1]);
		if (rc) {
			printf("submit cs failed with rc %d\n", rc);
			goto error;
		}

		/* Wait for DMA up to finish */
		rc = hltests_wait_for_cs_until_not_busy(fd, seq[1]);
		if (rc != HL_WAIT_CS_STATUS_COMPLETED) {
			printf("wait for cs failed with rc %d\n", rc);
			goto error;
		}
		/* compare host memories */
		rc = hltests_mem_compare(buf[0], buf[1], dma_size);
		if (rc) {
			printf("mem compare failed with rc %d\n", rc);
			goto error;
		}
	}

	/* cleanup */
	rc = hltests_free_device_mem(fd, dram_ptr);
	if (rc) {
		printf("free device mem failed with rc %d\n", rc);
		goto error;
	}

	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_free_host_mem(fd, buf[i]);
		if (rc) {
			printf("free host mem failed with rc %d\n", rc);
			goto error;
		}
	}

	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_destroy_cb(fd, cb[i]);
		if (rc) {
			printf("destroy cb failed with rc %d\n", rc);
			goto error;
		}
	}

	params->result = true;

error:
	return args;
}

static VOID _test_signal_wait(void **state, bool collective_wait,
		void *(*__start_routine)(void *))
{
	struct hltests_state *tests_state =
			(struct hltests_state *) *state;
	struct signal_wait_thread_params *thread_params;
	struct hlthunk_hw_ip_info hw_ip;
	int i, rc, fd = tests_state->fd;
	pthread_t *thread_id;
	void *retval;

	if (!hltests_is_gaudi(fd)) {
		printf("Test is supported on Gaudi/Greco, skipping.\n");
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
		thread_params[i].result = false;

		rc = pthread_create(&thread_id[i], NULL, __start_routine,
					&thread_params[i]);
		assert_int_equal(rc, 0);
	}

	/* Wait for the termination of the threads */
	for (i = 0 ; i < SIG_WAIT_TH ; i++) {
		rc = pthread_join(thread_id[i], &retval);
		assert_int_equal(rc, 0);
	}

	for (i = 0 ; i < SIG_WAIT_TH ; i++)
		assert_int_equal(thread_params[i].result, true);

	hlthunk_free(thread_id);
	hlthunk_free(thread_params);

	END_TEST;
}

VOID test_signal_wait(void **state)
{
	int fd = ((struct hltests_state *)*state)->fd;

	if (hltests_is_simulator(fd) &&
	    !hltests_get_parser_run_disabled_tests()) {
		printf("Test is skipped by default in simulator\n");
		skip();
	}

	END_TEST_FUNC(_test_signal_wait(state, false, test_signal_wait_th));
}

VOID test_signal_wait_parallel(void **state)
{
	END_TEST_FUNC(_test_signal_wait(state, false,
			test_signal_wait_parallel_th));
}

VOID test_signal_wait_dma(void **state)
{
	END_TEST_FUNC(_test_signal_wait(state, false,
				test_signal_wait_dma_th));
}

VOID test_sm_long_mode(void **state)
{
	struct hltests_state *tests_state =
				(struct hltests_state *) *state;
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t cb_size, dma_down_qid;
	uint16_t sob0, mon0;
	void *cb;
	int fd = tests_state->fd;

	if (hltests_is_gaudi(fd) || hltests_is_goya(fd)) {
		printf("Test relevant for Gaudi2 and above, skipping\n");
		skip();
	}

	/* SOB index must be aligned to 8 */
	sob0 = (DIV_ROUND_UP(hltests_get_first_avail_sob(fd), 8) * 8);
	mon0 = (DIV_ROUND_UP(hltests_get_first_avail_mon(fd), 8) * 8);

	/* Create CB that sets SOB0 to a non-zero value */
	cb = hltests_create_cb(fd, 4096, EXTERNAL, 0);
	assert_non_null(cb);

	dma_down_qid = hltests_get_dma_down_qid(fd, STREAM0);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_down_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = sob0;
	pkt_info.write_to_sob.value = 0xFFFE0003FFF8000;
	pkt_info.write_to_sob.mode = SOB_SET;
	pkt_info.write_to_sob.long_mode = 1;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, 0, &pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_down_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = sob0;
	pkt_info.write_to_sob.value = 0x100;
	pkt_info.write_to_sob.mode = SOB_ADD;
	pkt_info.write_to_sob.long_mode = 1;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);

	hltests_submit_and_wait_cs(fd, cb, cb_size, dma_down_qid,
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);

	cb = hltests_create_cb(fd, 4096, EXTERNAL, 0);
	assert_non_null(cb);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = dma_down_qid;
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = sob0;
	mon_and_fence_info.mon_id = mon0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 0xFFFE0003FFF8100;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	mon_and_fence_info.long_mode = 1;
	cb_size = hltests_add_monitor_and_fence(fd, cb, 0, &mon_and_fence_info);

	END_TEST_FUNC(hltests_submit_and_wait_cs(fd, cb, cb_size, dma_down_qid,
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED));
}

static uint32_t waitq_map[] = {
			GAUDI_QUEUE_ID_DMA_1_0,
			GAUDI_QUEUE_ID_DMA_1_1,
			GAUDI_QUEUE_ID_DMA_1_2,
			GAUDI_QUEUE_ID_DMA_1_3
};

/*
 * test_encaps_sig_wait_wa_th() - this thread test encaps signaling
 * sob wraparound. each queue has pair of SOBs.
 * it does two big reservations 32k each, without sending any actual
 * signaling jobs to device, the driver should fails the 3rd reservation attempt
 * if both SOB of the queue are fully reserved and more request keeps coming.
 * after reservation fails send signaling jobs which releases all
 * reservations, then try reserve again, this time reservation should succeed.
 */
static void *test_encaps_sig_wait_wa_th(void *args)
{
	struct encaps_sig_wait_thread_params *params =
				(struct encaps_sig_wait_thread_params *) args;
	struct hlthunk_wait_for_signal_data wait_for_signal;
	struct reserve_sig_handle first_handle;
	struct hlthunk_sig_res_out res_sig_out;
	struct hltests_cs_chunk execute_chunk;
	struct hlthunk_sig_res_in res_sig_in;
	struct hlthunk_wait_out wait_out;
	struct hltests_pkt_info pkt_info;
	struct hlthunk_wait_in wait_in;
	uint64_t seq, staged_seq1, staged_seq2;
	uint32_t cb_size, nop_cb_size = 0, flags = 0, status;
	int fd = params->fd, rc, iter = 0;
	void *cb, *nop_cb;
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	memset(&res_sig_in, 0, sizeof(res_sig_in));
	memset(&res_sig_out, 0, sizeof(res_sig_out));
	memset(&execute_chunk, 0, sizeof(struct hltests_cs_chunk));
	memset(&wait_for_signal, 0, sizeof(struct hlthunk_wait_for_signal_data));
	memset(&wait_in, 0, sizeof(struct hlthunk_wait_in));
	memset(&pkt_info, 0, sizeof(pkt_info));
	memset(&first_handle, 0, sizeof(first_handle));

	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null_ret_ptr(cb);

	nop_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null_ret_ptr(nop_cb);

	cb_size = 0;
	res_sig_in.queue_index = params->q_idx;
	res_sig_in.count = params->count;

	/*
	 * PTHREAD_BARRIER_SERIAL_THREAD is returned to one unspecified thread
	 * and zero is returned to each of the remaining threads.
	 */
	rc = pthread_barrier_wait(params->barrier);
	if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD)
		return NULL;

	do {
		rc = hlthunk_reserve_encaps_signals(fd, &res_sig_in,
				&res_sig_out);
		if (iter == 0)
			memcpy(&first_handle, &res_sig_out.handle,
						sizeof(first_handle));
		/* since we're reserving 32k every time,
		 * so we cannot iter more than twice
		 */
		assert_true_ret_ptr(iter <= 2);
		iter++;
	} while (rc == 0);

	/* set encaps signals in CS on the first SOB */
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id =
			 asic->get_sob_id(first_handle.sob_base_addr_offset);
	pkt_info.write_to_sob.base = SYNC_MNG_BASE_WS;
	pkt_info.write_to_sob.value = params->count;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb,
					cb_size, &pkt_info);

	execute_chunk.cb_ptr = cb;
	execute_chunk.cb_size = cb_size;
	execute_chunk.queue_index = params->q_idx;

	flags = HL_CS_FLAGS_STAGED_SUBMISSION |
			HL_CS_FLAGS_STAGED_SUBMISSION_FIRST |
			HL_CS_FLAGS_ENCAP_SIGNALS;

	rc = hltests_submit_staged_cs(fd, NULL, 0,
			&execute_chunk, 1, flags,
			first_handle.id,
			&seq);
	assert_int_equal_ret_ptr(rc, 0);

	staged_seq1 = seq;

	wait_for_signal.queue_index = waitq_map[params->q_idx];
	wait_for_signal.encaps_signal_seq = staged_seq1;
	wait_for_signal.signal_seq_nr = 1;
	wait_for_signal.encaps_signal_offset = params->count;
	wait_in.hlthunk_wait_for_signal = (uint64_t *) &wait_for_signal;
	wait_in.num_wait_for_signal = 1;
	wait_in.flags = 0;

	rc = hlthunk_wait_for_reserved_encaps_signals(
			fd, &wait_in, &wait_out);
	assert_int_equal_ret_ptr(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, wait_out.seq);
	assert_int_equal_ret_ptr(rc, HL_WAIT_CS_STATUS_COMPLETED);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	nop_cb_size = hltests_add_nop_pkt(fd, nop_cb, nop_cb_size, &pkt_info);
	execute_chunk.cb_ptr = nop_cb;
	execute_chunk.cb_size = nop_cb_size;
	execute_chunk.queue_index = params->q_idx;

	flags = HL_CS_FLAGS_STAGED_SUBMISSION |
			HL_CS_FLAGS_STAGED_SUBMISSION_LAST;
	rc = hltests_submit_staged_cs(fd, NULL, 0, &execute_chunk, 1, flags,
			staged_seq1, &seq);
	assert_int_equal_ret_ptr(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, staged_seq1);
	assert_int_equal_ret_ptr(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* set encaps signals in CS on the second SOB */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id =
			asic->get_sob_id(res_sig_out.handle.sob_base_addr_offset);
	pkt_info.write_to_sob.base = SYNC_MNG_BASE_WS;
	pkt_info.write_to_sob.value = params->count;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb,
					cb_size, &pkt_info);

	execute_chunk.cb_ptr = cb;
	execute_chunk.cb_size = cb_size;
	execute_chunk.queue_index = params->q_idx;

	flags = HL_CS_FLAGS_STAGED_SUBMISSION |
			HL_CS_FLAGS_STAGED_SUBMISSION_FIRST |
			HL_CS_FLAGS_ENCAP_SIGNALS;

	rc = hltests_submit_staged_cs(fd, NULL, 0,
			&execute_chunk, 1, flags,
			res_sig_out.handle.id,
			&seq);
	assert_int_equal_ret_ptr(rc, 0);

	staged_seq2 = seq;

	wait_for_signal.queue_index = waitq_map[params->q_idx];
	wait_for_signal.encaps_signal_seq = staged_seq2;
	wait_for_signal.signal_seq_nr = 1;
	wait_for_signal.encaps_signal_offset = params->count;
	wait_in.hlthunk_wait_for_signal = (uint64_t *) &wait_for_signal;
	wait_in.num_wait_for_signal = 1;
	wait_in.flags = 0;

	rc = hlthunk_wait_for_reserved_encaps_signals(
			fd, &wait_in, &wait_out);
	assert_int_equal_ret_ptr(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, wait_out.seq);
	assert_int_equal_ret_ptr(rc, HL_WAIT_CS_STATUS_COMPLETED);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	nop_cb_size = hltests_add_nop_pkt(fd, nop_cb, nop_cb_size, &pkt_info);
	execute_chunk.cb_ptr = nop_cb;
	execute_chunk.cb_size = nop_cb_size;
	execute_chunk.queue_index = params->q_idx;

	flags = HL_CS_FLAGS_STAGED_SUBMISSION |
				HL_CS_FLAGS_STAGED_SUBMISSION_LAST;
	rc = hltests_submit_staged_cs(fd, NULL, 0, &execute_chunk, 1, flags,
						staged_seq2, &seq);
	assert_int_equal_ret_ptr(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, staged_seq2);
	assert_int_equal_ret_ptr(rc, HL_WAIT_CS_STATUS_COMPLETED);

	memset(&res_sig_in, 0, sizeof(res_sig_in));
	memset(&res_sig_out, 0, sizeof(res_sig_out));

	res_sig_in.queue_index = params->q_idx;
	res_sig_in.count = params->count;

	rc = hlthunk_reserve_encaps_signals(fd, &res_sig_in, &res_sig_out);
	assert_int_equal_ret_ptr(rc, 0);

	rc = hlthunk_unreserve_encaps_signals(fd, &res_sig_out.handle, &status);
	assert_int_equal_ret_ptr(rc, 0);

	rc = hltests_destroy_cb(fd, nop_cb);
	assert_int_equal_ret_ptr(rc, 0);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal_ret_ptr(rc, 0);

	return args;
}

/*
 * test_encaps_sig_wait_th() - this thread test encaps signaling functionality.
 * it first reserve signals then send some job to device which basically
 * increment the same SOB used for reservation,
 * to the same value as it was reserved, then call API which wait
 * on encaps signaling to finish.
 * when reserving signal the API return SOB offset from base address.
 * for simplicity and in order to match sob and reservation handle,
 * we use gaudi define of the sob base address, and use it to
 * get the sob_id(get_sob_id).
 * a real application will use the sob full address to build the signaling jobs.
 */
static void *test_encaps_sig_wait_th(void *args)
{
	struct encaps_sig_wait_thread_params *params =
				(struct encaps_sig_wait_thread_params *) args;
	struct hlthunk_wait_for_signal_data wait_for_signal;
	struct hltests_cs_chunk execute_chunk;
	struct hlthunk_wait_in wait_in;
	struct hlthunk_wait_out wait_out;
	struct hlthunk_sig_res_in res_sig_in;
	struct hlthunk_sig_res_out res_sig_out;
	struct hltests_pkt_info pkt_info;
	void *cb, *nop_cb;
	uint64_t seq, staged_seq;
	uint32_t cb_size, nop_cb_size = 0, flags = 0;
	int fd = params->fd, rc;
	const struct hltests_asic_funcs *asic =
			get_hdev_from_fd(fd)->asic_funcs;

	memset(&res_sig_in, 0, sizeof(res_sig_in));
	memset(&res_sig_out, 0, sizeof(res_sig_out));
	memset(&execute_chunk, 0, sizeof(struct hltests_cs_chunk));
	memset(&wait_for_signal, 0, sizeof(struct hlthunk_wait_for_signal_data));
	memset(&wait_in, 0, sizeof(struct hlthunk_wait_in));
	memset(&pkt_info, 0, sizeof(pkt_info));

	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null_ret_ptr(cb);

	nop_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null_ret_ptr(nop_cb);

	cb_size = 0;

	res_sig_in.queue_index = params->q_idx;
	res_sig_in.count = params->count;

	/*
	 * PTHREAD_BARRIER_SERIAL_THREAD is returned to one unspecified thread
	 * and zero is returned to each of the remaining threads.
	 */
	rc = pthread_barrier_wait(params->barrier);
	if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD)
		return NULL;

	rc = hlthunk_reserve_encaps_signals(fd, &res_sig_in,
			&res_sig_out);
	assert_int_equal_ret_ptr(rc, 0);

	/* set encaps signals in CS  */
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id =
			asic->get_sob_id(res_sig_out.handle.sob_base_addr_offset);
	pkt_info.write_to_sob.base = SYNC_MNG_BASE_WS;
	pkt_info.write_to_sob.value = params->count;
	pkt_info.write_to_sob.mode = SOB_ADD;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb,
					cb_size, &pkt_info);

	execute_chunk.cb_ptr = cb;
	execute_chunk.cb_size = cb_size;
	execute_chunk.queue_index = params->q_idx;

	flags = HL_CS_FLAGS_STAGED_SUBMISSION |
			HL_CS_FLAGS_STAGED_SUBMISSION_FIRST |
			HL_CS_FLAGS_ENCAP_SIGNALS;

	rc = hltests_submit_staged_cs(fd, NULL, 0,
			&execute_chunk, 1, flags,
			res_sig_out.handle.id,
			&seq);

	assert_int_equal_ret_ptr(rc, 0);

	staged_seq = seq;

	wait_for_signal.queue_index = waitq_map[params->q_idx];
	wait_for_signal.encaps_signal_seq = seq;
	wait_for_signal.signal_seq_nr = 1;
	wait_for_signal.encaps_signal_offset = params->count;
	wait_in.hlthunk_wait_for_signal = (uint64_t *) &wait_for_signal;
	wait_in.num_wait_for_signal = 1;
	wait_in.flags = 0;

	if (params->collective_wait) {
		wait_for_signal.collective_engine_id = GAUDI_ENGINE_ID_DMA_5;
		rc = hlthunk_wait_for_reserved_encaps_collective_signals(fd,
				&wait_in, &wait_out);
		assert_int_equal_ret_ptr(rc, 0);
	} else {
		rc = hlthunk_wait_for_reserved_encaps_signals(
				fd, &wait_in, &wait_out);
		assert_int_equal_ret_ptr(rc, 0);
	}

	rc = hltests_wait_for_cs_until_not_busy(fd, wait_out.seq);
	assert_int_equal_ret_ptr(rc, HL_WAIT_CS_STATUS_COMPLETED);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	nop_cb_size = hltests_add_nop_pkt(fd, nop_cb, nop_cb_size, &pkt_info);

	execute_chunk.cb_ptr = nop_cb;
	execute_chunk.cb_size = nop_cb_size;
	execute_chunk.queue_index = params->q_idx;

	flags = HL_CS_FLAGS_STAGED_SUBMISSION |
				HL_CS_FLAGS_STAGED_SUBMISSION_LAST;
	rc = hltests_submit_staged_cs(fd, NULL, 0, &execute_chunk, 1, flags,
							staged_seq, &seq);
	assert_int_equal_ret_ptr(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, staged_seq);
	assert_int_equal_ret_ptr(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_destroy_cb(fd, nop_cb);
	assert_int_equal_ret_ptr(rc, 0);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal_ret_ptr(rc, 0);

	return args;
}

static VOID _test_encaps_signal_wait(void **state, bool collective_wait,
		int threads_num, int count,
		void *(*__start_routine)(void *))
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct encaps_sig_wait_thread_params *thread_params;
	pthread_barrier_t barrier;
	pthread_t *thread_id;
	void *retval;
	int rc, i;

	thread_params = hlthunk_malloc(threads_num * sizeof(*thread_params));
	assert_non_null(thread_params);

	thread_id = hlthunk_malloc(threads_num * sizeof(*thread_id));
	assert_non_null(thread_id);

	rc = pthread_barrier_init(&barrier, NULL, threads_num);
	assert_int_equal(rc, 0);

	/* Create and execute threads */
	for (i = 0 ; i < threads_num ; i++) {
		thread_params[i].barrier = &barrier;
		thread_params[i].fd = tests_state->fd;
		thread_params[i].count = count;
		thread_params[i].thread_id = i;
		thread_params[i].q_idx = i % 4;
		thread_params[i].collective_wait = collective_wait;

		rc = pthread_create(&thread_id[i], NULL, __start_routine,
					&thread_params[i]);
		assert_int_equal(rc, 0);
	}

	/* Wait for the termination of the threads */
	for (i = 0 ; i < threads_num ; i++) {
		rc = pthread_join(thread_id[i], &retval);
		assert_int_equal(rc, 0);
		assert_non_null(retval);
	}

	/* Cleanup */
	pthread_barrier_destroy(&barrier);
	hlthunk_free(thread_id);
	hlthunk_free(thread_params);

	END_TEST;
}

VOID test_encaps_signal_wait(void **state)
{
	int fd = ((struct hltests_state *)*state)->fd;

	if (!hltests_is_gaudi(fd)) {
		printf("Test is relevant only for Gaudi, skipping\n");
		skip();
	}

	CALL_HELPER_FUNC(_test_encaps_signal_wait(state, false, 1, 200,
				test_encaps_sig_wait_th));

	END_TEST;
}

VOID test_encaps_signal_wait_parallel(void **state)
{
	int fd = ((struct hltests_state *)*state)->fd;

	if (!hltests_is_gaudi(fd)) {
		printf("Test is relevant only for Gaudi, skipping\n");
		skip();
	}

	CALL_HELPER_FUNC(_test_encaps_signal_wait(state, false, 200, 200,
				test_encaps_sig_wait_th));

	END_TEST;
}

VOID test_encaps_signal_wait_sob_wa(void **state)
{
	int fd = ((struct hltests_state *)*state)->fd;

	/*
	 * Test for debug purposes only, since it'll always cause
	 * error log message and will always fail CI.
	 */
	if (!hltests_get_parser_run_disabled_tests()) {
		printf("This test needs to be run with -d flag\n");
		skip();
	}

	if (!hltests_is_gaudi(fd)) {
		printf("Test is relevant only for Gaudi, skipping\n");
		skip();
	}

	CALL_HELPER_FUNC(_test_encaps_signal_wait(state, false, 1, 32000,
					test_encaps_sig_wait_wa_th));

	END_TEST;
}

VOID test_encaps_signal_collective_wait(void **state)
{
	int fd = ((struct hltests_state *)*state)->fd;

	if (!hltests_is_gaudi(fd)) {
		printf("Test is relevant only for Gaudi, skipping\n");
		skip();
	}

	CALL_HELPER_FUNC(_test_encaps_signal_wait(state, true, 1, 10,
				test_encaps_sig_wait_th));

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE
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
	cmocka_unit_test_setup(test_sm_monitor_set_sram,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_signal_wait,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_signal_wait_parallel,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_signal_wait_dma,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_long_mode,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_encaps_signal_wait,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_encaps_signal_wait_parallel,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_encaps_signal_wait_sob_wa,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_encaps_signal_collective_wait,
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"sync_manager [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(sm_tests) / sizeof((sm_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE, sm_tests,
			num_tests);

	return hltests_run_group_tests("sync_manager", sm_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
