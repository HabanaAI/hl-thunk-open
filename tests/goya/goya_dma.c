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
#include <pthread.h>

void test_dma_4_queues(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_cs_chunk restore_arr[1], execute_arr[4];
	void *host_src, *host_dst, *dram_addr[2], *restore_cb, *dma_cb[4];
	uint64_t host_src_device_va, host_dst_device_va, sram_addr, seq;
	uint32_t dma_size, page_size, restore_cb_size = 0, dma_cb_size[4];
	int rc, fd = tests_state->fd, i;

	/* SRAM MAP (base + ):
	 * - 0x1000: data
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
	 * - Setup CB is used to clear SOB 0-2.
	 */

	dma_size = 128;
	page_size = sysconf(_SC_PAGESIZE);
	memset(dma_cb_size, 0, sizeof(dma_cb_size));

	/* Allocate memory on host and DRAM and set the SRAM address */
	host_src = hltests_allocate_host_mem(fd, dma_size, false);
	assert_non_null(host_src);
	hltests_fill_rand_values(host_src, dma_size);
	host_src_device_va = hltests_get_device_va_for_host_ptr(fd, host_src);

	host_dst = hltests_allocate_host_mem(fd, dma_size, false);
	assert_non_null(host_dst);
	memset(host_dst, 0, dma_size);
	host_dst_device_va = hltests_get_device_va_for_host_ptr(fd, host_dst);

	for (i = 0 ; i < 2 ; i++) {
		dram_addr[i] = hltests_allocate_device_mem(fd, dma_size);
		assert_non_null(dram_addr[i]);
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	assert_int_equal(hw_ip.dram_enabled, 1);
	sram_addr = hw_ip.sram_base_address + 0x1000;

	/* Setup CB: clear SOB 0-2 */
	restore_cb = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(restore_cb, NULL);

	restore_cb_size = hltests_add_set_sob_pkt(fd, restore_cb,
					restore_cb_size, false, false, 0, 0, 0);
	restore_cb_size = hltests_add_set_sob_pkt(fd, restore_cb,
					restore_cb_size, false, true, 0, 1, 0);
	restore_cb_size = hltests_add_set_sob_pkt(fd, restore_cb,
					restore_cb_size, false, true, 0, 2, 0);

	/* CB for first DMA QMAN:
	 * Transfer data from host to DRAM + signal SOB0.
	 */
	dma_cb[0] = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(dma_cb[0], NULL);

	dma_cb_size[0] = hltests_add_dma_pkt(fd, dma_cb[0], dma_cb_size[0],
					false, true, host_src_device_va,
					(uint64_t) (uintptr_t) dram_addr[0],
					dma_size, GOYA_DMA_HOST_TO_DRAM);
	dma_cb_size[0] = hltests_add_write_to_sob_pkt(fd, dma_cb[0],
					dma_cb_size[0], true, false, 0, 1, 1);

	/* CB for second DMA QMAN:
	 * Fence on SOB0 + transfer data from DRAM to SRAM + signal SOB1.
	 */
	dma_cb[1] = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(dma_cb[1], NULL);

	dma_cb_size[1] = hltests_add_monitor_and_fence(fd, dma_cb[1],
				dma_cb_size[1], 0,
				hltests_get_dma_dram_to_sram_qid(fd, 0, 0),
				false, 0, 0, 0);
	dma_cb_size[1] = hltests_add_dma_pkt(fd, dma_cb[1], dma_cb_size[1],
					false, true,
					(uint64_t) (uintptr_t) dram_addr[0],
					sram_addr, dma_size,
					GOYA_DMA_DRAM_TO_SRAM);
	dma_cb_size[1] = hltests_add_write_to_sob_pkt(fd, dma_cb[1],
					dma_cb_size[1], true, false, 1, 1, 1);

	/* CB for third DMA QMAN:
	 * Fence on SOB1 + transfer data from SRAM to DRAM + signal SOB2.
	 */
	dma_cb[2] = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(dma_cb[2], NULL);

	dma_cb_size[2] = hltests_add_monitor_and_fence(fd, dma_cb[2],
				dma_cb_size[2], 0,
				hltests_get_dma_sram_to_dram_qid(fd, 0, 0),
				false, 1, 1, 0);
	dma_cb_size[2] = hltests_add_dma_pkt(fd, dma_cb[2], dma_cb_size[2],
					false, true, sram_addr,
					(uint64_t) (uintptr_t) dram_addr[1],
					dma_size, GOYA_DMA_SRAM_TO_DRAM);
	dma_cb_size[2] = hltests_add_write_to_sob_pkt(fd, dma_cb[2],
					dma_cb_size[2], true, false, 2, 1, 1);

	/* CB for forth DMA QMAN:
	 * Fence on SOB2 + transfer data from DRAM to host.
	 */
	dma_cb[3] = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(dma_cb[3], NULL);

	dma_cb_size[3] = hltests_add_monitor_and_fence(fd, dma_cb[3],
					dma_cb_size[3], 0,
					hltests_get_dma_up_qid(fd, 0, 0),
					false, 2, 2, 0);
	dma_cb_size[3] = hltests_add_dma_pkt(fd, dma_cb[3], dma_cb_size[3],
					false, true,
					(uint64_t) (uintptr_t) dram_addr[1],
					host_dst_device_va,
					dma_size, GOYA_DMA_DRAM_TO_HOST);

	/* Submit CS and wait for completion */
	restore_arr[0].cb_ptr = restore_cb;
	restore_arr[0].cb_size = restore_cb_size;
	restore_arr[0].queue_index = hltests_get_dma_down_qid(fd, 0, 0);

	execute_arr[0].cb_ptr = dma_cb[0];
	execute_arr[0].cb_size = dma_cb_size[0];
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, 0, 0);

	execute_arr[1].cb_ptr = dma_cb[1];
	execute_arr[1].cb_size = dma_cb_size[1];
	execute_arr[1].queue_index = hltests_get_dma_dram_to_sram_qid(fd, 0, 0);

	execute_arr[2].cb_ptr = dma_cb[2];
	execute_arr[2].cb_size = dma_cb_size[2];
	execute_arr[2].queue_index = hltests_get_dma_sram_to_dram_qid(fd, 0, 0);

	execute_arr[3].cb_ptr = dma_cb[3];
	execute_arr[3].cb_size = dma_cb_size[3];
	execute_arr[3].queue_index = hltests_get_dma_up_qid(fd, 0, 0);

	rc = hltests_submit_cs(fd, restore_arr, 1, execute_arr, 4, true, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Compare host memories */
	rc = hltests_mem_compare(host_src, host_dst, dma_size);
	assert_int_equal(rc, 0);

	/* Cleanup */
	for (i = 0 ; i < 4 ; i++) {
		rc = hltests_destroy_cb(fd, dma_cb[i]);
		assert_int_equal(rc, 0);
	}

	rc = hltests_destroy_cb(fd, restore_cb);
	assert_int_equal(rc, 0);

	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_free_device_mem(fd, dram_addr[i]);
		assert_int_equal(rc, 0);
	}

	rc = hltests_free_host_mem(fd, host_dst);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, host_src);
	assert_int_equal(rc, 0);
}

const struct CMUnitTest goya_dma_tests[] = {
	cmocka_unit_test_setup(test_dma_4_queues,
				hl_tests_ensure_device_operational)
};

static const char *const usage[] = {
    "goya_dma [options]",
    NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_GOYA, goya_dma_tests,
			sizeof(goya_dma_tests) / sizeof((goya_dma_tests)[0]));

	return cmocka_run_group_tests(goya_dma_tests, hltests_setup,
					hltests_teardown);
}
