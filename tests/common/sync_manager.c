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
			(tpc_id < hltests_get_tpc_cnt(fd)) ; tpc_id++);

		assert_in_range(tpc_id, 0, hltests_get_tpc_cnt(fd) - 1);

		engine_qid = hltests_get_tpc_qid(fd, tpc_id, 0);
	} else {
		engine_qid = hltests_get_mme_qid(fd, 0, 0);
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
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, 0), 0, 1,
				src_data_device_va, device_data_address,
				dma_size, GOYA_DMA_HOST_TO_SRAM,
				WAIT_FOR_CS_DEFAULT_TIMEOUT);

	engine_cb = hltests_create_cb(fd, 64, false, cb_engine_address);
	assert_ptr_not_equal(engine_cb, NULL);
	engine_cb_device_va = hltests_get_device_va_for_host_ptr(fd, engine_cb);

	engine_cb_size = hltests_add_write_to_sob_pkt(fd, engine_cb, 0, 0, 1, 0,
							1, 1);

	/* DMA of cb engine host->sram */
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, 0), 0, 1,
				engine_cb_device_va, cb_engine_address,
				engine_cb_size, GOYA_DMA_HOST_TO_SRAM,
				WAIT_FOR_CS_DEFAULT_TIMEOUT);

/*
	packet_msg_short *write_to_so_0 =
	                (packet_msg_short *) lindma_copy_engine_cb.src_addr;
	write_to_so_0->eng_barrier = 0x0;
	write_to_so_0->reg_barrier = 0x1;
	write_to_so_0->msg_barrier = 0x1;
	write_to_so_0->opcode = PACKET_MSG_SHORT;
	write_to_so_0->op = 0; //Read from value
	write_to_so_0->base = 1; //Sync object base
	write_to_so_0->so_upd.mode = 1;
	write_to_so_0->msg_addr_offset = 0;
	write_to_so_0->so_upd.sync_value = 1;*/

	ext_cb = hltests_create_cb(tests_state->fd, getpagesize(), true, 0);
	assert_ptr_not_equal(ext_cb, NULL);

	offset = hltests_add_set_sob_pkt(tests_state->fd, ext_cb, 0, false,
						true, 0, 0);

	hltests_submit_and_wait_cs(tests_state->fd, ext_cb, offset,
				hltests_get_dma_down_qid(tests_state->fd, 0),
				WAIT_FOR_CS_DEFAULT_TIMEOUT, false);

/*
	packet_msg_long clear_so;
	clear_so.opcode = PACKET_MSG_LONG;
	clear_so.eng_barrier = 0;
	clear_so.reg_barrier = 1;
	clear_so.msg_barrier = 1;
	clear_so.op = 0;
	clear_so.addr = CFG_BASE + mmSYNC_MNGR_SOB_OBJ_0;
	clear_so.value = 0;
*/

	offset = hltests_add_monitor_and_fence(tests_state->fd, ext_cb, 0,
				hltests_get_dma_down_qid(tests_state->fd, 0),
				false, 0, 0, 0);

	offset = hltests_add_dma_pkt(tests_state->fd, ext_cb, offset, false,
					false, device_data_address,
					dst_data_device_va, dma_size,
					GOYA_DMA_SRAM_TO_HOST);

	hltests_submit_and_wait_cs(tests_state->fd, ext_cb, offset,
				hltests_get_dma_down_qid(tests_state->fd, 0),
				WAIT_FOR_CS_DEFAULT_TIMEOUT, false);

	execute_arr[0].cb_ptr = ext_cb;
	execute_arr[0].cb_size = offset;
	execute_arr[0].queue_index =
			hltests_get_dma_down_qid(tests_state->fd, 0);

	execute_arr[1].cb_ptr = engine_cb;
	execute_arr[1].cb_size = engine_cb_size;
	execute_arr[1].queue_index = engine_qid;

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2, false, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, engine_cb);
	assert_int_equal(rc, 0);

	if (is_wait) {
		uint32_t i, err_cnt = 0;

		rc = hltests_wait_for_cs(fd, seq, WAIT_FOR_CS_DEFAULT_TIMEOUT);
		assert_int_equal(rc, 0);

		rc = hltests_destroy_cb(fd, ext_cb);
		assert_int_equal(rc, 0);

		for (i = 0 ; (i < dma_size) && (err_cnt < 100) ; i += 4) {
			if (((uint32_t *) src_data)[i] !=
						((uint32_t *) dst_data)[i]) {
				err_cnt++;
			}
		}

		assert_int_equal(err_cnt, 0);
	}
}

void test_sm_tpc(void **state)
{
	test_sm(state, true, true);
}

void test_sm_mme(void **state)
{
	test_sm(state, false, true);
}

const struct CMUnitTest sm_tests[] = {
	cmocka_unit_test(test_sm_tpc),
	cmocka_unit_test(test_sm_mme),
};

int main(void)
{
	char *test_names_to_run;
	int rc;

	test_names_to_run = getenv("HLTHUNK_TESTS_NAMES");
	if (test_names_to_run)
		cmocka_set_test_filter(test_names_to_run);

	rc = cmocka_run_group_tests(sm_tests, hltests_setup,
					hltests_teardown);

	return rc;
}
