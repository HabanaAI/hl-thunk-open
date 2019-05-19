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

static void test_sm(void **state, bool is_tpc, bool is_wait)
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

	/* Get device information, especially tpc enabled mask */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_tpc) {
		/* Find first available TPC */
		uint8_t tpc_id;
		for (tpc_id = 0;
			(!(hw_ip.tpc_enabled_mask & (0x1 << tpc_id))) &&
			(tpc_id < hltests_get_tpc_cnt(fd, 0));)
			tpc_id++;

		assert_in_range(tpc_id, 0, hltests_get_tpc_cnt(fd, 0) - 1);

		engine_qid = hltests_get_tpc_qid(fd, DCORE0, tpc_id, STREAM0);
	} else {
		engine_qid = hltests_get_mme_qid(fd, DCORE0, 0, STREAM0);
	}

	/* SRAM MAP (base + )
	 * 0x1000 : data
	 * 0x2000 : engine's internal CB (we only use upper CP in this test)
	 */

	device_data_address = hw_ip.sram_base_address + 0x1000;
	cb_engine_address = hw_ip.sram_base_address + 0x2000;

	/* Allocate two buffers on the host for data transfers */
	src_data = hltests_allocate_host_mem(fd, dma_size, false);
	assert_non_null(src_data);
	hltests_fill_rand_values(src_data, dma_size);
	src_data_device_va = hltests_get_device_va_for_host_ptr(fd, src_data);

	dst_data = hltests_allocate_host_mem(fd, dma_size, false);
	assert_non_null(dst_data);
	memset(dst_data, 0, dma_size);
	dst_data_device_va = hltests_get_device_va_for_host_ptr(fd, dst_data);

	/* DMA of data host->sram */
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, DCORE0, STREAM0),
				EB_FALSE, MB_TRUE, src_data_device_va,
				device_data_address, dma_size,
				GOYA_DMA_HOST_TO_SRAM);

	/* Create internal CB for the engine */
	engine_cb = hltests_create_cb(fd, 64, false, cb_engine_address);
	assert_ptr_not_equal(engine_cb, NULL);
	engine_cb_device_va = hltests_get_device_va_for_host_ptr(fd, engine_cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = 0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	engine_cb_size = hltests_add_write_to_sob_pkt(fd, engine_cb,
								0, &pkt_info);

	/* DMA of cb engine host->sram */
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, DCORE0, STREAM0),
				EB_FALSE, MB_TRUE, engine_cb_device_va,
				cb_engine_address,
				engine_cb_size, GOYA_DMA_HOST_TO_SRAM);

	/* Clear SOB 0 */
	hltests_clear_sobs(fd, DCORE0, 1);

	/* Create CB for DMA that waits on internal engine and then performs
	 * a DMA down to the data address on the sram
	 */
	ext_cb = hltests_create_cb(fd, getpagesize(), true, 0);
	assert_ptr_not_equal(ext_cb, NULL);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd,
							DCORE0, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = 0;
	mon_and_fence_info.mon_id = 0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.target_val = 1;
	mon_and_fence_info.dec_val = 1;
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
	execute_arr[0].queue_index = hltests_get_dma_up_qid(fd,
							DCORE0, STREAM0);

	execute_arr[1].cb_ptr = engine_cb;
	execute_arr[1].cb_size = engine_cb_size;
	execute_arr[1].queue_index = engine_qid;

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2, false, &seq);
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

static void test_sm_pingpong_qman(void **state, bool is_tpc)
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

	/* Get device information, especially tpc enabled mask */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_tpc) {
		/* Find first available TPC */
		uint8_t tpc_id;
		for (tpc_id = 0;
			(!(hw_ip.tpc_enabled_mask & (0x1 << tpc_id))) &&
			(tpc_id < hltests_get_tpc_cnt(fd, 0));)
			tpc_id++;

		assert_in_range(tpc_id, 0, hltests_get_tpc_cnt(fd, 0) - 1);

		engine_qid = hltests_get_tpc_qid(fd, DCORE0, tpc_id, STREAM0);
	} else {
		engine_qid = hltests_get_mme_qid(fd, DCORE0, 0, STREAM0);
	}

	/* SRAM MAP (base + )
	 * 0x1000 : data
	 * 0x2000 : engine's internal CB (we only use upper CP in this test)
	 *
	 * Test description:
	 * DMA1 QMAN will transfer data to device and then signal the Engine's
	 * QMAN. It will signal DMA2 QMAN that will transfer the data from the
	 * device to the host.
	 * Setup CB will be used to clear SOB and to download the Engine's CB
	 * to the SRAM
	 */

	device_data_address = hw_ip.sram_base_address + 0x1000;
	engine_cb_sram_addr = hw_ip.sram_base_address + 0x2000;

	/* Allocate two buffers on the host for data transfers */
	src_data = hltests_allocate_host_mem(fd, dma_size, false);
	assert_non_null(src_data);
	hltests_fill_rand_values(src_data, dma_size);
	src_data_device_va = hltests_get_device_va_for_host_ptr(fd, src_data);

	dst_data = hltests_allocate_host_mem(fd, dma_size, false);
	assert_non_null(dst_data);
	memset(dst_data, 0, dma_size);
	dst_data_device_va = hltests_get_device_va_for_host_ptr(fd, dst_data);

	/* Create internal CB for the engine. It will fence on SOB0 and signal
	 * SOB8
	 */
	engine_cb = hltests_create_cb(fd, 512, false, engine_cb_sram_addr);
	assert_ptr_not_equal(engine_cb, NULL);
	engine_cb_device_va = hltests_get_device_va_for_host_ptr(fd, engine_cb);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.dcore_id = 0;
	mon_and_fence_info.queue_id = engine_qid;
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = 0;
	mon_and_fence_info.mon_id = 0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.target_val = 1;
	mon_and_fence_info.dec_val = 1;
	engine_cb_size = hltests_add_monitor_and_fence(fd, engine_cb, 0,
							&mon_and_fence_info);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.write_to_sob.sob_id = 8;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	engine_cb_size = hltests_add_write_to_sob_pkt(fd, engine_cb,
						engine_cb_size, &pkt_info);

	hltests_clear_sobs(fd, DCORE0, 2);
	restore_cb = hltests_create_cb(fd, getpagesize(), true, 0);
	assert_ptr_not_equal(restore_cb, NULL);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = engine_cb_device_va;
	pkt_info.dma.dst_addr = engine_cb_sram_addr;
	pkt_info.dma.size = engine_cb_size;
	pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_SRAM;
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb,
					restore_cb_size, &pkt_info);

	/* Create CB for DMA down that downloads data to device and signal the
	 * engine
	 */
	dmadown_cb = hltests_create_cb(fd, getpagesize(), true, 0);
	assert_ptr_not_equal(dmadown_cb, NULL);

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
	pkt_info.write_to_sob.sob_id = 0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	dmadown_cb_size = hltests_add_write_to_sob_pkt(fd, dmadown_cb,
					dmadown_cb_size, &pkt_info);

	/* Create CB for DMA up that waits on internal engine and then
	 * performs a DMA up of the data address on the sram
	 */
	dmaup_cb = hltests_create_cb(fd, getpagesize(), true, 0);
	assert_ptr_not_equal(dmaup_cb, NULL);
	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.dcore_id = 0;
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd,
							DCORE0, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = 8;
	mon_and_fence_info.mon_id = 1;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.target_val = 1;
	mon_and_fence_info.dec_val = 1;
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

	restore_arr[0].cb_ptr = restore_cb;
	restore_arr[0].cb_size = restore_cb_size;
	restore_arr[0].queue_index = hltests_get_dma_down_qid(fd,
							DCORE0, STREAM0);

	execute_arr[0].cb_ptr = dmaup_cb;
	execute_arr[0].cb_size = dmaup_cb_size;
	execute_arr[0].queue_index = hltests_get_dma_up_qid(fd,
							DCORE0, STREAM0);

	execute_arr[1].cb_ptr = engine_cb;
	execute_arr[1].cb_size = engine_cb_size;
	execute_arr[1].queue_index = engine_qid;

	execute_arr[2].cb_ptr = dmadown_cb;
	execute_arr[2].cb_size = dmadown_cb_size;
	execute_arr[2].queue_index = hltests_get_dma_down_qid(fd,
							DCORE0, STREAM0);

	rc = hltests_submit_cs(fd, restore_arr, 1, execute_arr, 3, true, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_destroy_cb(fd, engine_cb);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, restore_cb);
	assert_int_equal(rc, 0);

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
	test_sm(state, true, true);
}

void test_sm_mme(void **state)
{
	test_sm(state, false, true);
}

void test_sm_pingpong_tpc_qman(void **state)
{
	test_sm_pingpong_qman(state, true);
}

void test_sm_pingpong_mme_qman(void **state)
{
	test_sm_pingpong_qman(state, false);
}

void test_sm_pingpong_tpc_cmdq(void **state)
{
	test_sm_pingpong_cmdq(state, true);
}

void test_sm_pingpong_mme_cmdq(void **state)
{
	test_sm_pingpong_cmdq(state, false);
}

const struct CMUnitTest sm_tests[] = {
	cmocka_unit_test_setup(test_sm_tpc, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_mme, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_pingpong_tpc_qman,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_pingpong_mme_qman,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_pingpong_tpc_cmdq,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_pingpong_mme_cmdq,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"sync_manager [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID, sm_tests,
			sizeof(sm_tests) / sizeof((sm_tests)[0]));

	return cmocka_run_group_tests(sm_tests, hltests_setup,
					hltests_teardown);
}
