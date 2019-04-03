/*
 * Copyright (c) 2019 HabanaLabs Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
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
	uint32_t offset = 0, dma_size = 4, engine_cb_size;
	int rc, engine_qid, fd = tests_state->fd;
	uint64_t seq;

	/* Get device information, especially tpc enabled mask */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_tpc) {
		/* Find first available TPC */
		uint8_t tpc_id;
		for (tpc_id = 0 ;
			(!(hw_ip.tpc_enabled_mask & (0x1 << tpc_id))) &&
			(tpc_id < hltests_get_tpc_cnt(fd, 0)) ; tpc_id++);

		assert_in_range(tpc_id, 0, hltests_get_tpc_cnt(fd, 0) - 1);

		engine_qid = hltests_get_tpc_qid(fd, 0, tpc_id, 0);
	} else {
		engine_qid = hltests_get_mme_qid(fd, 0, 0, 0);
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
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, 0, 0), false,
				true, src_data_device_va, device_data_address,
				dma_size, GOYA_DMA_HOST_TO_SRAM);

	/* Create internal CB for the engine */
	engine_cb = hltests_create_cb(fd, 64, false, cb_engine_address);
	assert_ptr_not_equal(engine_cb, NULL);
	engine_cb_device_va = hltests_get_device_va_for_host_ptr(fd, engine_cb);

	engine_cb_size = hltests_add_write_to_sob_pkt(fd, engine_cb, 0, false,
							true, 0, 1, 1);

	/* DMA of cb engine host->sram */
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, 0, 0), 0, 1,
				engine_cb_device_va, cb_engine_address,
				engine_cb_size, GOYA_DMA_HOST_TO_SRAM);

	/* Create CB for DMA that clears SOB 0 */
	ext_cb = hltests_create_cb(fd, getpagesize(), true, 0);
	assert_ptr_not_equal(ext_cb, NULL);

	offset = hltests_add_set_sob_pkt(fd, ext_cb, 0, false, true, 0, 0, 0);

	hltests_submit_and_wait_cs(fd, ext_cb, offset,
				hltests_get_dma_down_qid(fd, 0, 0), false);

	/* Create CB for DMA that waits on internal engine and then performs
	 * a DMA down to the data address on the sram
	 */
	offset = hltests_add_monitor_and_fence(fd, ext_cb, 0, 0,
					hltests_get_dma_up_qid(fd, 0, 0), false,
					0, 0, 0);

	offset = hltests_add_dma_pkt(fd, ext_cb, offset, false, false,
					device_data_address, dst_data_device_va,
					dma_size, GOYA_DMA_SRAM_TO_HOST);

	execute_arr[0].cb_ptr = ext_cb;
	execute_arr[0].cb_size = offset;
	execute_arr[0].queue_index = hltests_get_dma_up_qid(fd, 0, 0);

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
	uint32_t dma_size = 4, engine_cb_size, restore_cb_size, dmadown_cb_size,
			dmaup_cb_size, i, err_cnt = 0;
	int rc, engine_qid, fd = tests_state->fd;
	uint64_t seq;

	/* Get device information, especially tpc enabled mask */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_tpc) {
		/* Find first available TPC */
		uint8_t tpc_id;
		for (tpc_id = 0 ;
			(!(hw_ip.tpc_enabled_mask & (0x1 << tpc_id))) &&
			(tpc_id < hltests_get_tpc_cnt(fd, 0)) ; tpc_id++);

		assert_in_range(tpc_id, 0, hltests_get_tpc_cnt(fd, 0) - 1);

		engine_qid = hltests_get_tpc_qid(fd, 0, tpc_id, 0);
	} else {
		engine_qid = hltests_get_mme_qid(fd, 0, 0, 0);
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
	 * SOB1
	 */
	engine_cb = hltests_create_cb(fd, 512, false, engine_cb_sram_addr);
	assert_ptr_not_equal(engine_cb, NULL);
	engine_cb_device_va = hltests_get_device_va_for_host_ptr(fd, engine_cb);

	engine_cb_size = hltests_add_monitor_and_fence(fd, engine_cb, 0, 0,
							engine_qid, false, 0,
							0, 0);
	engine_cb_size = hltests_add_write_to_sob_pkt(fd, engine_cb,
							engine_cb_size, false,
							true, 1, 1, 1);

	/* Create Setup CB that clears SOB 0 & 1, and copy the Engine's CB
	 * to the SRAM
	 */
	restore_cb = hltests_create_cb(fd, getpagesize(), true, 0);
	assert_ptr_not_equal(restore_cb, NULL);

	restore_cb_size = hltests_add_set_sob_pkt(fd, restore_cb, 0, false,
							true, 0, 0, 0);
	restore_cb_size = hltests_add_set_sob_pkt(fd, restore_cb,
					restore_cb_size, false, true, 0, 1, 0);
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb, restore_cb_size,
					false, false, engine_cb_device_va,
					engine_cb_sram_addr, engine_cb_size,
					GOYA_DMA_HOST_TO_SRAM);

	/* Create CB for DMA down that downloads data to device and signal the
	 * engine
	 */
	dmadown_cb = hltests_create_cb(fd, getpagesize(), true, 0);
	assert_ptr_not_equal(dmadown_cb, NULL);

	dmadown_cb_size = hltests_add_dma_pkt(fd, dmadown_cb, 0, false, false,
					src_data_device_va, device_data_address,
					dma_size, GOYA_DMA_HOST_TO_SRAM);

	dmadown_cb_size = hltests_add_write_to_sob_pkt(fd, dmadown_cb,
					dmadown_cb_size, true, true, 0, 1, 1);

	/* Create CB for DMA up that waits on internal engine and then
	 * performs a DMA up of the data address on the sram
	 */
	dmaup_cb = hltests_create_cb(fd, getpagesize(), true, 0);
	assert_ptr_not_equal(dmaup_cb, NULL);

	dmaup_cb_size = hltests_add_monitor_and_fence(fd, dmaup_cb, 0, 0,
					hltests_get_dma_up_qid(fd, 0, 0), false,
					1, 1, 0);

	dmaup_cb_size = hltests_add_dma_pkt(fd, dmaup_cb, dmaup_cb_size, false,
						true, device_data_address,
						dst_data_device_va, dma_size,
						GOYA_DMA_SRAM_TO_HOST);

	restore_arr[0].cb_ptr = restore_cb;
	restore_arr[0].cb_size = restore_cb_size;
	restore_arr[0].queue_index = hltests_get_dma_down_qid(fd, 0, 0);

	execute_arr[0].cb_ptr = dmaup_cb;
	execute_arr[0].cb_size = dmaup_cb_size;
	execute_arr[0].queue_index = hltests_get_dma_up_qid(fd, 0, 0);

	execute_arr[1].cb_ptr = engine_cb;
	execute_arr[1].cb_size = engine_cb_size;
	execute_arr[1].queue_index = engine_qid;

	execute_arr[2].cb_ptr = dmadown_cb;
	execute_arr[2].cb_size = dmadown_cb_size;
	execute_arr[2].queue_index = hltests_get_dma_down_qid(fd, 0, 0);

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

static void test_sm_pingpong_cmdq(void **state, bool is_tpc)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_cs_chunk restore_arr[1], execute_arr[3];
	void *host_src, *host_dst, *engine_cmdq_cb, *engine_qman_cb,
		*restore_cb, *dmadown_cb, *dmaup_cb;
	uint64_t seq, host_src_device_va, host_dst_device_va, device_data_addr,
		engine_cmdq_cb_sram_addr, engine_cmdq_cb_device_va,
		engine_qman_cb_sram_addr, engine_qman_cb_device_va;
	uint32_t engine_qid, dma_size, page_size, engine_cmdq_cb_size,
		engine_qman_cb_size, restore_cb_size, dmadown_cb_size,
		dmaup_cb_size;
	int rc, fd = tests_state->fd;

	/* SRAM MAP (base + ):
	 * - 0x1000               : data
	 * - 0x1000 + page_size   : engine's internal CB (CMDQ)
	 * - 0x1000 + 2*page_size : engine's internal CB (QMAN)
	 *
	 * Test Description:
	 * - First DMA QMAN transfers data from host to SRAM and then signals
	 *   SOB0.
	 * - Engine QMAN process CP_DMA packet and transfer internal CB to CMDQ.
	 * - Engine CMDQ fences on SOB0, processes NOP packet, and then signals
	 *   SOB1.
	 * - Second DMA QMAN fences on SOB1 and then transfers data from SRAM to
	 *   host.
	 * - Setup CB is used to clear SOB 0-1 and to DMA the internal CBs to
	 *   SRAM.
	 */

	dma_size = 4;
	page_size = sysconf(_SC_PAGESIZE);

	/* Set engine queue ID and SRAM addresses */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (is_tpc) {
		/* Find first available TPC */
		uint8_t tpc_id;
		for (tpc_id = 0 ;
			(!(hw_ip.tpc_enabled_mask & (0x1 << tpc_id))) &&
			(tpc_id < hltests_get_tpc_cnt(fd, 0)) ; tpc_id++);

		assert_in_range(tpc_id, 0, hltests_get_tpc_cnt(fd, 0) - 1);

		engine_qid = hltests_get_tpc_qid(fd, 0, tpc_id, 0);
	} else {
		engine_qid = hltests_get_mme_qid(fd, 0, 0, 0);
	}

	device_data_addr = hw_ip.sram_base_address + 0x1000;
	engine_cmdq_cb_sram_addr = device_data_addr + page_size;
	engine_qman_cb_sram_addr = engine_cmdq_cb_sram_addr + page_size;

	/* Allocate two buffers on the host for data transfers */
	host_src = hltests_allocate_host_mem(fd, dma_size, false);
	assert_non_null(host_src);
	hltests_fill_rand_values(host_src, dma_size);
	host_src_device_va = hltests_get_device_va_for_host_ptr(fd, host_src);

	host_dst = hltests_allocate_host_mem(fd, dma_size, false);
	assert_non_null(host_dst);
	memset(host_dst, 0, dma_size);
	host_dst_device_va = hltests_get_device_va_for_host_ptr(fd, host_dst);

	/* Internal CB for engine CMDQ: fence on SOB0 + NOP + signal SOB1 */
	engine_cmdq_cb = hltests_create_cb(fd, page_size, false,
						engine_cmdq_cb_sram_addr);
	assert_ptr_not_equal(engine_cmdq_cb, NULL);
	engine_cmdq_cb_device_va = hltests_get_device_va_for_host_ptr(fd,
								engine_cmdq_cb);
	engine_cmdq_cb_size = 0;
	engine_cmdq_cb_size = hltests_add_monitor_and_fence(fd, engine_cmdq_cb,
							engine_cmdq_cb_size,
							0, engine_qid, true, 0,
							0, 0);
	engine_cmdq_cb_size = hltests_add_nop_pkt(fd, engine_cmdq_cb,
							engine_cmdq_cb_size,
							false, true);
	engine_cmdq_cb_size = hltests_add_write_to_sob_pkt(fd, engine_cmdq_cb,
							engine_cmdq_cb_size,
							false, false, 1, 1, 1);

	/* Internal CB for engine QMAN: CP_DMA */
	engine_qman_cb = hltests_create_cb(fd, page_size, false,
						engine_qman_cb_sram_addr);
	assert_ptr_not_equal(engine_qman_cb, NULL);
	engine_qman_cb_device_va = hltests_get_device_va_for_host_ptr(fd,
								engine_qman_cb);
	engine_qman_cb_size = 0;
	engine_qman_cb_size = hltests_add_cp_dma_pkt(fd, engine_qman_cb,
						engine_qman_cb_size, false,
						false, engine_cmdq_cb_sram_addr,
						engine_cmdq_cb_size);

	/* Setup CB: Clear SOB 0-1 + DMA the internal CBs to SRAM */
	restore_cb =  hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(restore_cb, NULL);
	restore_cb_size = 0;
	restore_cb_size = hltests_add_set_sob_pkt(fd, restore_cb,
							restore_cb_size, false,
							false, 0, 0, 0);
	restore_cb_size = hltests_add_set_sob_pkt(fd, restore_cb,
							restore_cb_size, false,
							true, 0, 1, 0);
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb, restore_cb_size,
						false, true,
						engine_cmdq_cb_device_va,
						engine_cmdq_cb_sram_addr,
						engine_cmdq_cb_size,
						GOYA_DMA_HOST_TO_SRAM);
	restore_cb_size = hltests_add_dma_pkt(fd, restore_cb, restore_cb_size,
						false, true,
						engine_qman_cb_device_va,
						engine_qman_cb_sram_addr,
						engine_qman_cb_size,
						GOYA_DMA_HOST_TO_SRAM);

	/* CB for first DMA QMAN:
	 * Transfer data from host to SRAM + signal SOB0.
	 */
	dmadown_cb = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(dmadown_cb, NULL);
	dmadown_cb_size = 0;
	dmadown_cb_size = hltests_add_dma_pkt(fd, dmadown_cb, dmadown_cb_size,
						false, false,
						host_src_device_va,
						device_data_addr, dma_size,
						GOYA_DMA_HOST_TO_SRAM);
	dmadown_cb_size = hltests_add_write_to_sob_pkt(fd, dmadown_cb,
							dmadown_cb_size, true,
							false, 0, 1, 1);

	/* CB for second DMA QMAN:
	 * Fence on SOB1 + transfer data from SRAM to host.
	 */
	dmaup_cb = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(dmaup_cb, NULL);
	dmaup_cb_size = 0;
	dmaup_cb_size = hltests_add_monitor_and_fence(fd, dmaup_cb,
					dmaup_cb_size, 0,
					hltests_get_dma_up_qid(fd, 0, 0),
					false, 1, 1, 0);
	dmaup_cb_size = hltests_add_dma_pkt(fd, dmaup_cb, dmaup_cb_size,
						false, true, device_data_addr,
						host_dst_device_va, dma_size,
						GOYA_DMA_SRAM_TO_HOST);

	/* Submit CS and wait for completion */
	restore_arr[0].cb_ptr = restore_cb;
	restore_arr[0].cb_size = restore_cb_size;
	restore_arr[0].queue_index = hltests_get_dma_down_qid(fd, 0, 0);

	execute_arr[0].cb_ptr = dmadown_cb;
	execute_arr[0].cb_size = dmadown_cb_size;
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, 0, 0);

	execute_arr[1].cb_ptr = engine_qman_cb;
	execute_arr[1].cb_size = engine_qman_cb_size;
	execute_arr[1].queue_index = engine_qid;

	execute_arr[2].cb_ptr = dmaup_cb;
	execute_arr[2].cb_size = dmaup_cb_size;
	execute_arr[2].queue_index = hltests_get_dma_up_qid(fd, 0, 0);

	rc = hltests_submit_cs(fd, restore_arr, 1, execute_arr, 3, true, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Compare host memories */
	rc = hltests_mem_compare(host_src, host_dst, dma_size);
	assert_int_equal(rc, 0);

	/* Cleanup */
	rc = hltests_destroy_cb(fd, engine_cmdq_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, engine_qman_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, restore_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, dmadown_cb);
	assert_int_equal(rc, 0);
	rc = hltests_destroy_cb(fd, dmaup_cb);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, host_dst);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, host_src);
	assert_int_equal(rc, 0);
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
