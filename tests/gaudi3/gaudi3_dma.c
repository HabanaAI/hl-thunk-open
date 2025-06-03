// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "gaudi3/gaudi3.h"
#include "gaudi3/asic_reg/gaudi3_regs.h"
#include "gaudi3/gaudi3_pqm_packets.h"

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

VOID test_cs_pqm_msg_short_to_mon(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_pkt_info pkt_info;
	int fd = tests_state->fd, rc;
	uint32_t cb_size = 0;
	uint16_t mon;
	void *cb;

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	cb = hltests_create_cb(fd, SZ_4K, CB_TYPE_USER, 0);
	assert_non_null(cb);

	mon = hltests_get_first_avail_mon(fd);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = hltests_get_dma_down_qid(fd, STREAM0);
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;

	pkt_info.msg_short.base = 0; /* PDMA_GRP_PQM_CP_MSG_BASE_ADDR0 */
	pkt_info.msg_short.address = mon * sizeof(uint32_t);
	pkt_info.msg_short.value = 0x11111111;

	cb_size = hltests_add_msg_short_pkt(fd, cb, cb_size, &pkt_info);

	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, pkt_info.qid,
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_cs_pqm_msg_short_to_sob(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_pkt_info pkt_info;
	int fd = tests_state->fd, rc;
	uint32_t cb_size = 0;
	uint16_t sob;
	void *cb;

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	cb = hltests_create_cb(fd, SZ_4K, CB_TYPE_USER, 0);
	assert_non_null(cb);

	sob = hltests_get_first_avail_sob(fd);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = hltests_get_dma_down_qid(fd, STREAM0);
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;

	pkt_info.msg_short.base = 1; /* PDMA_GRP_PQM_CP_MSG_BASE_ADDR1 */
	pkt_info.msg_short.address = sob * sizeof(uint32_t);
	pkt_info.msg_short.value = 0x12AB;

	cb_size = hltests_add_msg_short_pkt(fd, cb, cb_size, &pkt_info);

	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, pkt_info.qid,
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_cs_pqm_msg_long_to_mon(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_pkt_info pkt_info;
	int rc, fd = tests_state->fd;
	uint32_t cb_size = 0;
	uint16_t mon;
	void *cb;

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	cb = hltests_create_cb(fd, 0x1000, CB_TYPE_USER, 0);
	assert_non_null(cb);

	mon = hltests_get_first_avail_mon(fd);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = hltests_get_dma_down_qid(fd, STREAM0);
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = mmHD0_SYNC_MNGR_OBJS_BASE +
			mmSOB_OBJS_MON_PAY_ADDRL_0_0 + mon * sizeof(uint32_t);
	pkt_info.msg_long.value = 0x22222222;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, pkt_info.qid,
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_cs_pqm_msg_long_to_sob(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_pkt_info pkt_info;
	int rc, fd = tests_state->fd;
	uint32_t cb_size = 0;
	uint16_t sob;
	void *cb;

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	cb = hltests_create_cb(fd, SZ_4K, CB_TYPE_USER, 0);
	assert_non_null(cb);

	sob = hltests_get_first_avail_sob(fd);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = hltests_get_dma_down_qid(fd, STREAM0);
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = hltests_get_sob_base_addr(fd) + sob * sizeof(uint32_t);
	pkt_info.msg_long.value = 0x12AB;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, pkt_info.qid,
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_cs_pqm_2000_msg_long_to_sob(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t cb_size = 0, sob, cb_alloc_size, num_of_msgs = 2000, qid;
	struct hltests_pkt_info pkt_info;
	int fd = tests_state->fd, i;
	void *cb;

	qid = hltests_get_dma_down_qid(fd, STREAM0);
	cb_alloc_size = num_of_msgs * hltests_get_max_pkt_size(fd, MB_TRUE, EB_FALSE, qid);
	cb_alloc_size += hltests_get_cq_patch_size(fd, qid);

	cb = hltests_create_cb(fd, cb_alloc_size, CB_TYPE_USER, 0);
	assert_non_null(cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;

	/* In Gaudi3, PQM msgs (msg_long/short, etc.,) can't do HBW writes */
	sob = hltests_get_first_avail_sob(fd);
	pkt_info.msg_long.address = hltests_get_sob_base_addr(fd) +
			sob * sizeof(uint32_t);
	pkt_info.msg_long.value = 0x12AB;

	for (i = 0 ; i < num_of_msgs ; i++)
		cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	END_TEST_FUNC(hltests_submit_and_wait_cs(fd, cb, cb_size, qid,
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED));
}

VOID test_cs_pqm_q_wrap_around(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_device *hdev = get_hdev_from_fd(tests_state->fd);
	uint32_t cb_size = 0, old_q_size, new_q_size = SZ_4K;
	uint16_t num_of_cs_for_wrap, qid, ch_id;
	struct hltests_pkt_info pkt_info;
	int rc, i, fd = tests_state->fd;
	struct pdma_ch_info *ch_info;
	void *cb;

	/* SW-172941:
	 * A HW bug has been discovered in PDMA, where apparently the HW
	 * does not handle right the wraparound of the msq_pi/ci registers
	 * (so the SW has to reset them manually before they overflow).
	 * Although this HW issue wasn't reproduced with this test, we're
	 * skipping it (unless running with disabled tests).
	 */
	if (!hltests_get_parser_run_disabled_tests())
		skip();

	qid = hltests_get_dma_down_qid(fd, STREAM0);
	ch_id = qid - GAUDI3_DIE0_ENGINE_ID_PDMA_0_CH_0;
	ch_info = &hdev->pdma_db.ch_info[ch_id];

	/* The size of PQM's submission q is temporarily lowered in order
	 * to tackle possible edge cases.
	 */
	old_q_size = ch_info->submission_q_size;
	ch_info->submission_q_size = new_q_size;
	rc = hltests_pdma_config_ch_blocks(fd);
	assert_int_equal(rc, 0);

	cb = hltests_create_cb(fd, 0x1000, CB_TYPE_USER, 0);
	assert_non_null(cb);

	/* We add 10 more packets to ensure we wrap around the submission queue */
	num_of_cs_for_wrap = new_q_size / sizeof(struct pqm_packet_nop) + 10;

	for (i = 0 ; i < num_of_cs_for_wrap ; i++) {
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = qid;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		cb_size = hltests_add_nop_pkt(fd, cb, 0, &pkt_info);

		rc = hltests_submit_and_wait_cs(fd, cb, cb_size, qid,
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
		assert_int_equal(rc, 0);
	}

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	/* The size of PQM's submission q is restored not to mess up other tests
	 * in this binary.
	 */
	ch_info->submission_q_size = old_q_size;
	rc = hltests_pdma_config_ch_blocks(fd);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_cs_pqm_lin_pdma_host_sob_host(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t src_data_dev_va, dst_data_dev_va, dev_addr;
	uint32_t cb_size = 0, dma_size = sizeof(uint32_t);
	struct hltests_pkt_info pkt_info;
	void *cb, *src_data, *dst_data;
	int rc, fd = tests_state->fd;
	uint16_t sob, qid;

	/* This test isn't trivial since LPDMA of HBW <--> LBW requires a LBW
	 * PDMA channel. User's owned PDMA channels are usually of type HBW, so
	 * we must first switch channel's BW property which isn't an accessible
	 * property (being located in the PDMA HW blocks allocated for the
	 * driver-only use).
	 * Solution: PDMA will write to its own HW address space to change BW
	 * property, followed by HBW(host)-->LBW(SOB)-->HBW(host) test.
	 */
	cb = hltests_create_cb(fd, SZ_4K, CB_TYPE_USER, 0);
	assert_non_null(cb);

	sob = hltests_get_first_avail_sob(fd);
	dev_addr = hltests_get_sob_base_addr(fd) + sob * sizeof(uint32_t);
	qid = hltests_get_dma_down_qid(fd, STREAM0);

	/* Set PDMA channel as LBW (deliberately sent under a unique CS) */
	cb_size = hltests_add_pdma_ch_bw_config_pkt(fd, cb, cb_size, qid, true);
	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, qid,
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
	assert_int_equal(rc, 0);

	/* Allocate buffer on host for data transfer */
	src_data = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
	assert_non_null(src_data);
	dst_data = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
	assert_non_null(dst_data);
	*(uint32_t *)src_data = 0x1234;
	src_data_dev_va = hltests_get_device_va_for_host_ptr(fd, src_data);
	dst_data_dev_va = hltests_get_device_va_for_host_ptr(fd, dst_data);

	/* HBW --> LBW */

	cb_size = 0;
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = src_data_dev_va;
	pkt_info.dma.dst_addr = dev_addr;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;
	cb_size = hltests_add_dma_pkt(fd, cb, cb_size, &pkt_info);

	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, qid,
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
	assert_int_equal(rc, 0);

	/* LBW --> HBW */

	cb_size = 0;
	pkt_info.dma.src_addr = dev_addr;
	pkt_info.dma.dst_addr = dst_data_dev_va;
	pkt_info.dma.dma_dir = DMA_DIR_SRAM_TO_HOST;
	cb_size = hltests_add_dma_pkt(fd, cb, cb_size, &pkt_info);

	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, qid,
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
	assert_int_equal(rc, 0);

	assert_int_equal(*(uint32_t *)src_data, *(uint32_t *)dst_data);

	rc = hltests_free_host_mem(fd, src_data);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, dst_data);
	assert_int_equal(rc, 0);

	/* Set PDMA channel back as HBW (deliberately sent under a unique CS) */
	cb_size = 0;
	cb_size = hltests_add_pdma_ch_bw_config_pkt(fd, cb, cb_size, qid, false);
	rc = hltests_submit_and_wait_cs(fd, cb, cb_size, qid,
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
	assert_int_equal(rc, 0);

	END_TEST;
}

static VOID test_single_mme_dma(struct hltests_state *tests_state, uint8_t mme_idx)
{
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	void *device_addr1, *device_addr2, *src_ptr, *dst_ptr;
	uint32_t dma_dir_down, dma_dir_up, size;
	uint64_t host_src_addr, host_dst_addr;
	int rc, fd = tests_state->fd;
	bool is_huge;

	size = 2 * MME_DMA_SIZE;
	is_huge = !!((size > SZ_32K) && (size < SZ_1G));

	if (!hltests_is_mme_dma_enabled(fd)) {
		printf("MME DMA is disabled so skipping test\n");
		skip();
	}

	if (size > hw_ip->dram_size) {
		printf("DRAM (%lu[B]) less than required allocation (%u[B]) - skip\n",
			hw_ip->dram_size, size);
		skip();
	}

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	device_addr1 = hltests_allocate_device_mem(fd, size, 0, NOT_CONTIGUOUS);
	assert_non_null(device_addr1);

	device_addr2 = hltests_allocate_device_mem(fd, size, 0, NOT_CONTIGUOUS);
	assert_non_null(device_addr2);

	dma_dir_down = DMA_DIR_HOST_TO_DRAM;
	dma_dir_up = DMA_DIR_DRAM_TO_HOST;

	src_ptr = hltests_allocate_host_mem_aligned_flags(fd, size, is_huge, 0, 0);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, size);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem_aligned_flags(fd, size, is_huge, 0, 0);
	assert_non_null(dst_ptr);
	memset(dst_ptr, 0, size);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	/* DMA: host->device */
	rc = hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, host_src_addr,
			(uint64_t) (uintptr_t) device_addr1,
			size, dma_dir_down);
	assert_int_equal(rc, 0);

	/* mme dma dram1 -> dram2 */
	rc = gaudi3_mme_dma(fd, (uint64_t)device_addr1, (uint64_t)device_addr2, mme_idx, size);
	assert_int_equal(rc, 0);

	/* DMA: device(dram2)->host */
	rc = hltests_dma_transfer(fd, hltests_get_dma_up_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, (uint64_t) (uintptr_t) device_addr2,
			host_dst_addr, size, dma_dir_up);
	assert_int_equal(rc, 0);

	/* Compare host memories */
	rc = hltests_mem_compare(src_ptr, dst_ptr, size);
	assert_int_equal(rc, 0);

	/* Cleanup */
	rc = hltests_free_host_mem(fd, dst_ptr);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, src_ptr);
	assert_int_equal(rc, 0);

	rc = hltests_free_device_mem(fd, device_addr1);
	assert_int_equal(rc, 0);
	rc = hltests_free_device_mem(fd, device_addr2);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_mme_dma(void **state)
{
	struct hltests_state *tests_state = *state;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	uint8_t mme_cnt, mme_id;

	/* TODO - remove skip for GAUDI3D once SW-219441 is resolved */
	if (hltests_is_gaudi3d(tests_state->fd))
		skip();

	if (!tests_state->mme) {
		printf("MME is disabled so skipping test\n");
		skip();
	}

	mme_cnt = hltests_get_mme_cnt(tests_state->fd, hw_ip->mme_master_slave_mode);

	for (mme_id = 0 ; mme_id < mme_cnt ; mme_id++) {
		if (!(hw_ip->mme_enabled_mask & (0x1ULL << mme_id)))
			continue;

		CALL_HELPER_FUNC(test_single_mme_dma(tests_state, mme_id));
	}

	END_TEST;
}

VOID test_heavy_dma_on_given_pdma_channels(int fd, int *pdma_ch_arr, int num_of_pdma_ch)
{
	uint64_t host_va[2][MAX_PDMA_CH_NUM], device_va[MAX_PDMA_CH_NUM], seq, cb_size;
	void *host_ptr[2][MAX_PDMA_CH_NUM], *cb[MAX_PDMA_CH_NUM];
	struct hltests_cs_chunk execute_arr[MAX_PDMA_CH_NUM];
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t cb_offset = 0, qid, dma_size = SZ_1K, dma_size_per_pkt = 128;
	int rc, i, j, k, num_of_lindma_pkts = dma_size / dma_size_per_pkt;
	struct hltests_pkt_info pkt_info;
	uint16_t sob[2], mon;

	assert_in_range(num_of_pdma_ch, 1, MAX_PDMA_CH_NUM);
	sob[0] = hltests_get_first_avail_sob(fd);
	sob[1] = sob[0] + 1;
	mon = hltests_get_first_avail_mon(fd);

	cb_size = (uint64_t) num_of_lindma_pkts * hltests_get_max_pkt_size(fd, MB_TRUE, EB_TRUE,
						hltests_get_pdma_qid(fd, 0)) * 2;

	for (j = 0; j < num_of_pdma_ch; j++) {
		cb[j] = hltests_create_cb(fd, cb_size, CB_TYPE_USER, 0);
		assert_non_null(cb[j]);
		for (k = 0; k < 2; k++) {
			host_ptr[k][j] = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
			assert_non_null(host_ptr[k][j]);
			host_va[k][j] = hltests_get_device_va_for_host_ptr(fd, host_ptr[k][j]);
		}
		hltests_fill_rand_values(host_ptr[0][j], dma_size);
		memset(host_ptr[1][j], 0, dma_size);
		device_va[j] = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, dma_size, 0, NOT_CONTIGUOUS);
		assert_non_null(device_va[j]);
	}

	hltests_clear_sobs(fd, 2);
	for (j = 0; j < num_of_pdma_ch; j++) {
		cb_offset = 0;
		qid = hltests_get_pdma_qid(fd, pdma_ch_arr[j]);

		for (k = 0; k < 2; k++) {
			/* increment the sob to trigger dma on all channels at once */
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.qid = qid;
			pkt_info.eb = EB_TRUE;
			pkt_info.mb = MB_TRUE;
			pkt_info.write_to_sob.mode = SOB_ADD;
			pkt_info.write_to_sob.sob_id = sob[k];
			pkt_info.write_to_sob.value = 1;
			cb_offset = hltests_add_write_to_sob_pkt(fd, cb[j], cb_offset, &pkt_info);

			/* mon + fence to wait till all channels wrote to sob */
			memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
			mon_and_fence_info.queue_id = qid;
			mon_and_fence_info.cmdq_fence = false;
			mon_and_fence_info.sob_id = sob[k];
			mon_and_fence_info.mon_id = mon + k * num_of_pdma_ch + j;
			mon_and_fence_info.mon_address = 0;
			mon_and_fence_info.sob_val = num_of_pdma_ch;
			mon_and_fence_info.dec_fence = true;
			mon_and_fence_info.mon_payload = 1;
			mon_and_fence_info.mon_mode = SOB_EQUAL;
			cb_offset = hltests_add_monitor_and_fence(fd, cb[j], cb_offset,
								&mon_and_fence_info);

			/* the DMAs */
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.qid = qid;
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_FALSE;
			pkt_info.dma.size = dma_size_per_pkt;
			if (k == 0) { /* host->dram */
				pkt_info.dma.src_addr = host_va[k][j];
				pkt_info.dma.dst_addr = device_va[j];
				pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_DRAM;
			} else { /* dram->host */
				pkt_info.dma.src_addr = device_va[j];
				pkt_info.dma.dst_addr = host_va[k][j];
				pkt_info.dma.dma_dir = DMA_DIR_DRAM_TO_HOST;
			}

			for (i = 0; i < num_of_lindma_pkts; i++) {
				cb_offset = hltests_add_dma_pkt(fd, cb[j], cb_offset, &pkt_info);
				pkt_info.dma.src_addr += dma_size_per_pkt;
				pkt_info.dma.dst_addr += dma_size_per_pkt;
			}
		}

		execute_arr[j].cb_ptr = cb[j];
		execute_arr[j].cb_size = cb_offset;
		execute_arr[j].queue_index = qid;
	}

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, num_of_pdma_ch, 0, &seq);
	assert_int_equal(rc, 0);

	if (hltests_is_pldm(fd)) /* 5 min timeout in pldm */
		rc = hltests_wait_for_cs(fd, seq, 5 * TIME_1_MIN_IN_USEC);
	else
		rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	if (rc) {
		printf("heavy dma on pdma failed with %d channels (rc = %d)\n", num_of_pdma_ch, rc);
		fail();
	}

	for (j = 0; j < num_of_pdma_ch; j++) {
		rc = hltests_mem_compare(host_ptr[0][j], host_ptr[1][j], dma_size);
		assert_int_equal(rc, 0);
	}

	for (j = 0; j < num_of_pdma_ch; j++) {
		for (k = 0; k < 2; k++) {
			rc = hltests_free_host_mem(fd, host_ptr[k][j]);
			assert_int_equal(rc, 0);
		}

		rc = hltests_free_device_mem(fd, (void *) device_va[j]);
		assert_int_equal(rc, 0);
		rc = hltests_destroy_cb(fd, cb[j]);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_pdma_ch_on_given_die(struct hltests_state *tests_state, int num_ch_to_test, int die)
{
	int pdma_channels[MAX_PDMA_CH_NUM] = {0};
	int fd = tests_state->fd;
	uint8_t num_of_pdma_ch;
	uint32_t qid;
	int i, j;

	num_of_pdma_ch = hltests_get_pdma_ch_cnt(fd);
	for (i = 0, j = 0 ; i < num_of_pdma_ch && j < num_ch_to_test; i++) {
		qid = hltests_get_pdma_qid(fd, i);
		if ((die == 0 && qid < GAUDI3_DIE1_ENGINE_ID_PDMA_0_CH_0) ||
		   (die == 1 && qid >= GAUDI3_DIE1_ENGINE_ID_PDMA_0_CH_0))
			pdma_channels[j++] = i;
	}

	if (j != num_ch_to_test) {
		printf("not enough channels, expected %d, found %d - skip\n", num_ch_to_test, j);
		skip();
	}

	END_TEST_FUNC(test_heavy_dma_on_given_pdma_channels(fd, pdma_channels, num_ch_to_test));
}

VOID test_parallel_pdma_die0(void **state)
{
	struct hltests_state *tests_state = *state;
	/* ch0 is reserved for kernel, so for die0 we have NUM_OF_PDMA_CH_PER_DIE minus 1 */
	int num_of_ch_in_die0 = NUM_OF_PDMA_CH_PER_DIE - 1;

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	END_TEST_FUNC(test_pdma_ch_on_given_die(tests_state, num_of_ch_in_die0, 0));
}

VOID test_parallel_pdma_die1(void **state)
{
	struct hltests_state *tests_state = *state;

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	END_TEST_FUNC(test_pdma_ch_on_given_die(tests_state, NUM_OF_PDMA_CH_PER_DIE, 1));
}

VOID test_pdma_on_all_channels(void **state)
{
	struct hltests_state *tests_state = *state;
	int pdma_channels[MAX_PDMA_CH_NUM];
	int fd = tests_state->fd;
	uint8_t num_of_pdma_ch;
	int i;

	num_of_pdma_ch = hltests_get_pdma_ch_cnt(fd);
	for (i = 0 ; i < num_of_pdma_ch ; i++)
		pdma_channels[i] = i;

	END_TEST_FUNC(test_heavy_dma_on_given_pdma_channels(fd, pdma_channels, num_of_pdma_ch));
}

VOID test_each_pdma_ch_dma(void **state)
{
	uint64_t host_src_va, host_dst_va, device_va;
	struct hltests_state *tests_state = *state;
	void *host_src_ptr, *host_dst_ptr;
	uint32_t qid, dma_size = 128;
	int fd = tests_state->fd;
	uint8_t num_of_pdma_ch;
	int rc, ch;

	host_src_ptr = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
	assert_non_null(host_src_ptr);
	host_src_va = hltests_get_device_va_for_host_ptr(fd, host_src_ptr);

	host_dst_ptr = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
	assert_non_null(host_dst_ptr);
	host_dst_va = hltests_get_device_va_for_host_ptr(fd, host_dst_ptr);

	device_va = (uint64_t) (uintptr_t)
		hltests_allocate_device_mem(fd, dma_size, 0, NOT_CONTIGUOUS);
	assert_non_null(device_va);

	num_of_pdma_ch = hltests_get_pdma_ch_cnt(fd);

	for (ch = 0 ; ch < num_of_pdma_ch ; ch++) {
		qid = hltests_get_pdma_qid(fd, ch);
		hltests_fill_rand_values(host_src_ptr, dma_size);
		memset(host_dst_ptr, 0, dma_size);
		rc = hltests_dma_transfer(fd, qid, EB_FALSE, MB_TRUE, host_src_va, device_va,
						dma_size, DMA_DIR_HOST_TO_DRAM);
		assert_int_equal(rc, 0);
		rc = hltests_dma_transfer(fd, qid, EB_FALSE, MB_TRUE, device_va, host_dst_va,
						dma_size, DMA_DIR_DRAM_TO_HOST);
		assert_int_equal(rc, 0);
		rc = hltests_mem_compare(host_src_ptr, host_dst_ptr, dma_size);
		assert_int_equal(rc, 0);
	}

	rc = hltests_free_host_mem(fd, host_src_ptr);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, host_dst_ptr);
	assert_int_equal(rc, 0);

	rc = hltests_free_device_mem(fd, (void *) device_va);
	assert_int_equal(rc, 0);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest gaudi3_dma_tests[] = {
	cmocka_unit_test_setup(test_cs_pqm_msg_short_to_mon,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_pqm_msg_short_to_sob,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_pqm_msg_long_to_mon,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_pqm_msg_long_to_sob,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_pqm_2000_msg_long_to_sob,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_pqm_q_wrap_around,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_pqm_lin_pdma_host_sob_host,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_mme_dma,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_each_pdma_ch_dma,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_parallel_pdma_die0,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_parallel_pdma_die1,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_pdma_on_all_channels,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"gaudi3_dma [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(gaudi3_dma_tests) / sizeof((gaudi3_dma_tests)[0]);

	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK |
					CAP_ARC_FW_LOAD_MME_MASK |
					CAP_MME_DMA_MASK);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_GAUDI3_ALL,
		       gaudi3_dma_tests, num_tests);

	return hltests_run_group_tests("gaudi3_dma", gaudi3_dma_tests, num_tests,
			hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
