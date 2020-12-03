// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "common/hlthunk_tests.h"

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
	struct hltests_cs_chunk execute_arr[4];
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	void *host_src, *host_dst, *dram_addr[2], *dma_cb[4];
	uint64_t host_src_device_va, host_dst_device_va, sram_addr, seq;
	uint32_t dma_size, dma_cb_size[4];
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
	 */

	dma_size = 128;

	memset(dma_cb_size, 0, sizeof(dma_cb_size));

	/* Allocate memory on host and DRAM and set the SRAM address */
	host_src = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
	assert_non_null(host_src);
	hltests_fill_rand_values(host_src, dma_size);
	host_src_device_va = hltests_get_device_va_for_host_ptr(fd, host_src);

	host_dst = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
	assert_non_null(host_dst);
	memset(host_dst, 0, dma_size);
	host_dst_device_va = hltests_get_device_va_for_host_ptr(fd, host_dst);

	for (i = 0 ; i < 2 ; i++) {
		dram_addr[i] = hltests_allocate_device_mem(fd, dma_size,
								NOT_CONTIGUOUS);
		assert_non_null(dram_addr[i]);
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);
	assert_int_equal(hw_ip.dram_enabled, 1);
	sram_addr = hw_ip.sram_base_address + 0x1000;


	/* Setup CB: clear SOB 0-2 */
	hltests_clear_sobs(fd, 3);

	/* CB for first DMA QMAN:
	 * Transfer data from host to DRAM + signal SOB0.
	 */
	dma_cb[0] = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(dma_cb[0]);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = host_src_device_va;
	pkt_info.dma.dst_addr = (uint64_t) (uintptr_t) dram_addr[0];
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_DRAM;
	dma_cb_size[0] = hltests_add_dma_pkt(fd, dma_cb[0], dma_cb_size[0],
					&pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = 0;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	dma_cb_size[0] = hltests_add_write_to_sob_pkt(fd, dma_cb[0],
					dma_cb_size[0], &pkt_info);

	/* CB for second DMA QMAN:
	 * Fence on SOB0 + transfer data from DRAM to SRAM + signal SOB1.
	 */
	dma_cb[1] = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(dma_cb[1]);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_ddma_qid(fd, 0, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = 0;
	mon_and_fence_info.mon_id = 0;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	dma_cb_size[1] = hltests_add_monitor_and_fence(fd, dma_cb[1],
				dma_cb_size[1], &mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = (uint64_t) (uintptr_t) dram_addr[0];
	pkt_info.dma.dst_addr = sram_addr;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = GOYA_DMA_DRAM_TO_SRAM;
	dma_cb_size[1] = hltests_add_dma_pkt(fd, dma_cb[1], dma_cb_size[1],
					&pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = 1;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	dma_cb_size[1] = hltests_add_write_to_sob_pkt(fd, dma_cb[1],
					dma_cb_size[1], &pkt_info);

	/* CB for third DMA QMAN:
	 * Fence on SOB1 + transfer data from SRAM to DRAM + signal SOB2.
	 */
	dma_cb[2] = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(dma_cb[2]);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_ddma_qid(fd, 1, STREAM0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = 1;
	mon_and_fence_info.mon_id = 1;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	dma_cb_size[2] = hltests_add_monitor_and_fence(fd, dma_cb[2],
				dma_cb_size[2], &mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = sram_addr;
	pkt_info.dma.dst_addr = (uint64_t) (uintptr_t) dram_addr[1];
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = GOYA_DMA_SRAM_TO_DRAM;
	dma_cb_size[2] = hltests_add_dma_pkt(fd, dma_cb[2], dma_cb_size[2],
					&pkt_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_FALSE;
	pkt_info.write_to_sob.sob_id = 2;
	pkt_info.write_to_sob.value = 1;
	pkt_info.write_to_sob.mode = SOB_ADD;
	dma_cb_size[2] = hltests_add_write_to_sob_pkt(fd, dma_cb[2],
					dma_cb_size[2], &pkt_info);

	/* CB for forth DMA QMAN:
	 * Fence on SOB2 + transfer data from DRAM to host.
	 */
	dma_cb[3] = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(dma_cb[3]);

	memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
	mon_and_fence_info.queue_id = hltests_get_dma_up_qid(fd, 0);
	mon_and_fence_info.cmdq_fence = false;
	mon_and_fence_info.sob_id = 2;
	mon_and_fence_info.mon_id = 2;
	mon_and_fence_info.mon_address = 0;
	mon_and_fence_info.sob_val = 1;
	mon_and_fence_info.dec_fence = true;
	mon_and_fence_info.mon_payload = 1;
	dma_cb_size[3] = hltests_add_monitor_and_fence(fd, dma_cb[3],
					dma_cb_size[3], &mon_and_fence_info);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = (uint64_t) (uintptr_t) dram_addr[1];
	pkt_info.dma.dst_addr = host_dst_device_va;
	pkt_info.dma.size = dma_size;
	pkt_info.dma.dma_dir = GOYA_DMA_DRAM_TO_HOST;
	dma_cb_size[3] = hltests_add_dma_pkt(fd, dma_cb[3], dma_cb_size[3],
					&pkt_info);

	execute_arr[0].cb_ptr = dma_cb[0];
	execute_arr[0].cb_size = dma_cb_size[0];
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	execute_arr[1].cb_ptr = dma_cb[1];
	execute_arr[1].cb_size = dma_cb_size[1];
	execute_arr[1].queue_index = hltests_get_ddma_qid(fd, 0, STREAM0);

	execute_arr[2].cb_ptr = dma_cb[2];
	execute_arr[2].cb_size = dma_cb_size[2];
	execute_arr[2].queue_index = hltests_get_ddma_qid(fd, 1, STREAM0);

	execute_arr[3].cb_ptr = dma_cb[3];
	execute_arr[3].cb_size = dma_cb_size[3];
	execute_arr[3].queue_index =
				hltests_get_dma_up_qid(fd, STREAM0);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 4,
					HL_CS_FLAGS_FORCE_RESTORE, &seq);
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
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"goya_dma [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(goya_dma_tests) / sizeof((goya_dma_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_GOYA, goya_dma_tests,
			num_tests);

	return hltests_run_group_tests("goya_dma", goya_dma_tests, num_tests,
					hltests_setup, hltests_teardown);
}
