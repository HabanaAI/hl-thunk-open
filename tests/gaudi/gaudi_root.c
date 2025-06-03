// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "gaudi_nic.h"
#include "hlthunk_tests.h"

#include <unistd.h>
#include <pthread.h>

#define RL_WREG32(reg, val)	WRITE32(CFG_BASE + reg, val)
#define RL_RREG32(reg)		READ32(CFG_BASE + reg)

#define NUM_OF_INT_Q		6

static void *tpc_corner_activation(void *args)
{
	int i;

	for (i = 0 ; i < 65000 ; i++)
		test_sm_pingpong_common_cp(&args, true, false, 3);

	printf("tpc corner thread done\n");

	return args;
}

static void *write_hbm(void *args)
{
	struct hltests_state *tests_state = (struct hltests_state *) args;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	uint64_t hbm_address;

	assert_int_equal_ret_ptr(hw_ip->dram_enabled, 1);

	for (hbm_address = hw_ip->dram_base_address;
			hbm_address < (hw_ip->dram_base_address + 0x2800000);
			hbm_address += 4)
		WRITE32(hbm_address, (uint32_t) hbm_address);

	printf("write hbm thread done\n");

	return args;
}

static void *read_sram(void *args)
{
	struct hltests_state *tests_state = (struct hltests_state *) args;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	uint64_t sram_address;
	uint32_t val;

	for (sram_address = hw_ip->sram_base_address + 0x100000;
			sram_address < (hw_ip->sram_base_address + 0xf00000);
			sram_address += 4)
		val = READ32(sram_address);

	printf("read sram thread done\n");

	return args;
}

VOID test_tpc_corner_with_inbound_pci_hbw(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int i, rc, num_of_threads = 3;
	pthread_t *thread_id;
	void *retval;

	/* Allocate arrays for threads management */
	thread_id = (pthread_t *) hlthunk_malloc(num_of_threads *
							sizeof(*thread_id));
	assert_non_null(thread_id);

	/* Create and execute threads */
	rc = pthread_create(&thread_id[0], NULL, tpc_corner_activation,
				tests_state);
	assert_int_equal(rc, 0);

	rc = pthread_create(&thread_id[1], NULL, write_hbm, tests_state);
	assert_int_equal(rc, 0);

	rc = pthread_create(&thread_id[2], NULL, read_sram, tests_state);
	assert_int_equal(rc, 0);

	/* Wait for the termination of the threads */
	for (i = 0 ; i < num_of_threads ; i++) {
		rc = pthread_join(thread_id[i], &retval);
		assert_int_equal(rc, 0);
		assert_non_null(retval);
	}

	hlthunk_free(thread_id);

	END_TEST;
}

VOID activate_all2all_dma_channels(void **state, uint64_t *dram_addr,
					uint32_t dma_size,
					struct hlthunk_hw_ip_info *hw_ip)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk restore_arr[1], execute_arr[NUM_OF_INT_Q + 1];
	uint32_t cp_dma_cb_size[NUM_OF_INT_Q] = {0},
		common_cb_buf_size[NUM_OF_INT_Q] = {0}, nop_cb_size = 0;
	uint32_t restore_cb_size = 0, queue;
	uint64_t seq, common_cb_device_va[NUM_OF_INT_Q],
		cp_dma_cb_device_va[NUM_OF_INT_Q],
		sram_base, cp_dma_sram_addr;
	void *restore_cb, *nop_cb, *common_cb_buf[NUM_OF_INT_Q],
		*cp_dma_cb[NUM_OF_INT_Q];
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	int rc, fd = tests_state->fd, i, j;

	sram_base = hw_ip->sram_base_address;

	restore_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(restore_cb);

	nop_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(nop_cb);

	hltests_clear_sobs(fd, 512);

	/* prepare internal DMAs */
	queue = GAUDI_QUEUE_ID_DMA_2_0;

	for (i = 0 ; i < NUM_OF_INT_Q ; i++, queue += 4) {
		common_cb_buf[i] = hltests_allocate_host_mem(fd, 0x1000,
				NOT_HUGE_MAP);
		assert_non_null(common_cb_buf[i]);
		memset(common_cb_buf[i], 0, 0x1000);
		common_cb_buf_size[i] = 0;
		common_cb_device_va[i] =
				hltests_get_device_va_for_host_ptr(fd,
						common_cb_buf[i]);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = dram_addr[i * 2];
		pkt_info.dma.dst_addr = dram_addr[i * 2 + 1];
		pkt_info.dma.size = dma_size;
		pkt_info.dma.dma_dir = DMA_DIR_DRAM_TO_DRAM;

		for (j = 0 ; j < 100 ; j++)
			common_cb_buf_size[i] = hltests_add_dma_pkt(fd,
					common_cb_buf[i],
					common_cb_buf_size[i],
					&pkt_info);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.sob_id = i * 8;
		pkt_info.write_to_sob.value = 1;
		pkt_info.write_to_sob.mode = SOB_SET;
		common_cb_buf_size[i] = hltests_add_write_to_sob_pkt(fd,
				common_cb_buf[i],
				common_cb_buf_size[i],
				&pkt_info);

		cp_dma_sram_addr = sram_base + (NUM_OF_INT_Q * 0x1000) +
							(i * 0x20);

		cp_dma_cb[i] = hltests_create_cb(fd, SZ_4K, INTERNAL,
							cp_dma_sram_addr);
		assert_non_null(cp_dma_cb[i]);
		cp_dma_cb_device_va[i] =
				hltests_get_device_va_for_host_ptr(fd,
						cp_dma_cb[i]);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.cp_dma.src_addr = sram_base + i * 0x1000;
		pkt_info.cp_dma.size = common_cb_buf_size[i];
		cp_dma_cb_size[i] = hltests_add_cp_dma_pkt
				(fd, cp_dma_cb[i], cp_dma_cb_size[i],
						&pkt_info);

		execute_arr[i].cb_ptr = cp_dma_cb[i];
		execute_arr[i].cb_size = cp_dma_cb_size[i];
		execute_arr[i].queue_index = queue;

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = cp_dma_cb_device_va[i];
		pkt_info.dma.dst_addr = cp_dma_sram_addr;
		pkt_info.dma.size = cp_dma_cb_size[i];
		pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;
		restore_cb_size = hltests_add_dma_pkt(fd, restore_cb,
							restore_cb_size,
							&pkt_info);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = common_cb_device_va[i];
		pkt_info.dma.dst_addr = sram_base + i * 0x1000;
		pkt_info.dma.size = common_cb_buf_size[i];
		pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;
		restore_cb_size = hltests_add_dma_pkt(fd, restore_cb,
							restore_cb_size,
							&pkt_info);

		memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
		mon_and_fence_info.queue_id =
					hltests_get_dma_down_qid(fd, STREAM0);
		mon_and_fence_info.cmdq_fence = false;
		mon_and_fence_info.sob_id = i * 8;
		mon_and_fence_info.mon_id = i;
		mon_and_fence_info.mon_address = 0;
		mon_and_fence_info.sob_val = 1;
		mon_and_fence_info.dec_fence = true;
		mon_and_fence_info.mon_payload = 1;
		mon_and_fence_info.mon_mode = SOB_EQUAL;
		nop_cb_size = hltests_add_monitor_and_fence(fd, nop_cb,
					nop_cb_size, &mon_and_fence_info);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		nop_cb_size = hltests_add_nop_pkt(fd, nop_cb, nop_cb_size,
							&pkt_info);
	}

	restore_arr[0].cb_ptr = restore_cb;
	restore_arr[0].cb_size = restore_cb_size;
	restore_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	execute_arr[NUM_OF_INT_Q].cb_ptr = nop_cb;
	execute_arr[NUM_OF_INT_Q].cb_size = nop_cb_size;
	execute_arr[NUM_OF_INT_Q].queue_index =
				hltests_get_dma_down_qid(fd, STREAM0);

	/* execute internal DMAs */
	rc = hltests_submit_cs(fd, restore_arr, 1, execute_arr,
			NUM_OF_INT_Q + 1, HL_CS_FLAGS_FORCE_RESTORE, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	for (i = 0 ; i < NUM_OF_INT_Q ; i++) {
		rc = hltests_destroy_cb(fd, cp_dma_cb[i]);
		assert_int_equal(rc, 0);

		rc = hltests_free_host_mem(fd, common_cb_buf[i]);
		assert_int_equal(rc, 0);
	}

	rc = hltests_destroy_cb(fd, nop_cb);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, restore_cb);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_dma_all2all_stress(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	void *data_buf[NUM_OF_INT_Q * 2];
	uint64_t dram_addr[NUM_OF_INT_Q * 2],
		data_buf_va[NUM_OF_INT_Q * 2];
	uint32_t dma_size = 1 << 31;
	int rc, fd = tests_state->fd, i;

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	/* SRAM MAP (base + ):
	 * - 0x0000 - CB of common CP
	 * - 0x1000 - CB of common CP
	 * - 0x2000 - CB of common CP
	 * - 0x3000 - CB of common CP
	 * - 0x4000 - CB of common CP
	 * - 0x5000 - CB of common CP
	 * - 0x6000 - CB of upper CP
	 * - 0x6020 - CB of upper CP
	 * - 0x6040 - CB of upper CP
	 * - 0x6060 - CB of upper CP
	 * - 0x6080 - CB of upper CP
	 * - 0x60A0 - CB of upper CP
	 * - 0x7000 - Data
	 *
	 * Test description:
	 * - On each of the available internal queues a DMA will take place.
	 * - Each queue transfers data from source DRAM address to destination
	 *   DRAM address.
	 * - The data is different for each queue, and was transferred from
	 *   host to the source DRAM address for each queue.
	 * - All of the above DMA transfers happen concurrently.
	 * - Each queue signals to SOB when upon completion.
	 * - An external CB with NOP packet waits for all queues to finish in
	 *   order to signal the user that the CS has finished.
	 * - At the end of these DMAs, an external DMA from DRAM to host will
	 *   execute to compare the transferred data.
	 */

	assert_true(hw_ip->dram_enabled);

	assert_true(dma_size * NUM_OF_INT_Q < hw_ip->dram_size);

	/* prepare external data buffers */
	for (i = 0 ; i < NUM_OF_INT_Q ; i++) {
		data_buf[i * 2] = hltests_allocate_host_mem(fd, dma_size,
							NOT_HUGE_MAP);
		assert_non_null(data_buf[i * 2]);
		data_buf_va[i * 2] = hltests_get_device_va_for_host_ptr(fd,
							data_buf[i * 2]);
		hltests_fill_rand_values(data_buf[i * 2], dma_size);

		data_buf[i * 2 + 1] = hltests_allocate_host_mem(fd, dma_size,
							NOT_HUGE_MAP);
		assert_non_null(data_buf[i * 2 + 1]);
		data_buf_va[i * 2 + 1] = hltests_get_device_va_for_host_ptr(fd,
							data_buf[i * 2 + 1]);
		memset(data_buf[i * 2 + 1], 0, dma_size);
	}

	/* Allocate device memory */
	for (i = 0 ; i < NUM_OF_INT_Q ; i++) {
		dram_addr[i * 2] = (uint64_t) hltests_allocate_device_mem(
						fd, dma_size, 0, CONTIGUOUS);
		assert_int_not_equal(dram_addr[i * 2], 0);

		dram_addr[i * 2 + 1] =
				(uint64_t) hltests_allocate_device_mem(fd,
						dma_size, 0, CONTIGUOUS);
		assert_int_not_equal(dram_addr[i * 2 + 1], 0);
	}

	/* transfer data to DRAM */
	for (i = 0 ; i < NUM_OF_INT_Q ; i++) {
		rc = hltests_dma_transfer(fd,
				hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE, data_buf_va[i * 2],
				dram_addr[i * 2], dma_size,
				DMA_DIR_HOST_TO_DRAM);
		assert_int_equal(rc, 0);
	}

	activate_all2all_dma_channels(state, dram_addr, dma_size, hw_ip);

	/* Copy data back to host */
	for (i = 0 ; i < NUM_OF_INT_Q ; i++) {
		rc = hltests_dma_transfer(fd,
				hltests_get_dma_up_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE, dram_addr[i * 2 + 1],
				data_buf_va[i * 2 + 1], dma_size,
				DMA_DIR_DRAM_TO_HOST);
		assert_int_equal(rc, 0);
	}

	/* Compare host memories */
	for (i = 0 ; i < NUM_OF_INT_Q ; i++) {
		rc = hltests_mem_compare(data_buf[i * 2], data_buf[i * 2 + 1],
						dma_size);
		assert_int_equal(rc, 0);
	}

	for (i = 0 ; i < NUM_OF_INT_Q ; i++) {
		rc = hltests_free_host_mem(fd, data_buf[i * 2]);
		assert_int_equal(rc, 0);

		rc = hltests_free_host_mem(fd, data_buf[i * 2 + 1]);
		assert_int_equal(rc, 0);
	}

	for (i = 0 ; i < NUM_OF_INT_Q ; i++) {
		rc = hltests_free_device_mem(fd, (void *) dram_addr[i * 2]);
		assert_int_equal(rc, 0);

		rc = hltests_free_device_mem(fd,
					(void *) dram_addr[i * 2 + 1]);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_dma_all2all_stress_minimum_host_memory(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	void *data_buf;
	uint64_t dram_addr[NUM_OF_INT_Q * 2], data_buf_va;
	uint32_t host_size = 1 << 28, dma_size = 1 << 31;
	int rc, fd = tests_state->fd, i, j;

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	/* SRAM MAP (base + ):
	 * - 0x0000 - CB of common CP
	 * - 0x1000 - CB of common CP
	 * - 0x2000 - CB of common CP
	 * - 0x3000 - CB of common CP
	 * - 0x4000 - CB of common CP
	 * - 0x5000 - CB of common CP
	 * - 0x6000 - CB of upper CP
	 * - 0x6020 - CB of upper CP
	 * - 0x6040 - CB of upper CP
	 * - 0x6060 - CB of upper CP
	 * - 0x6080 - CB of upper CP
	 * - 0x60A0 - CB of upper CP
	 * - 0x7000 - Data
	 *
	 * Test description:
	 * - On each of the available internal queues a DMA will take place.
	 * - Each queue transfers data from source DRAM address to destination
	 *   DRAM address.
	 * - The data is different for each queue, and was transferred from
	 *   host to the source DRAM address for each queue.
	 * - All of the above DMA transfers happen concurrently.
	 * - Each queue signals to SOB when upon completion.
	 * - An external CB with NOP packet waits for all queues to finish in
	 *   order to signal the user that the CS has finished.
	 * - There is no compare of the data at the end of the test
	 * - The test using minimum memory allocation on the host to allow
	 *   running this in hosts with small amount of memory
	 */
	assert_true(hw_ip->dram_enabled);
	assert_true(dma_size * NUM_OF_INT_Q < hw_ip->dram_size);

	/* prepare external data buffer */
	data_buf = hltests_allocate_host_mem(fd, host_size, NOT_HUGE_MAP);
	assert_non_null(data_buf);
	data_buf_va = hltests_get_device_va_for_host_ptr(fd, data_buf);

	/* Allocate device memory */
	for (i = 0 ; i < NUM_OF_INT_Q ; i++) {
		dram_addr[i * 2] = (uint64_t) hltests_allocate_device_mem(
						fd, dma_size, 0, CONTIGUOUS);
		assert_int_not_equal(dram_addr[i * 2], 0);

		dram_addr[i * 2 + 1] =
				(uint64_t) hltests_allocate_device_mem(fd,
						dma_size, 0, CONTIGUOUS);
		assert_int_not_equal(dram_addr[i * 2 + 1], 0);
	}

	/* transfer data to DRAM */
	for (i = 0 ; i < NUM_OF_INT_Q ; i++)
		for (j = 0 ; j < (dma_size / host_size) ; j++) {
			hltests_fill_rand_values(data_buf, host_size);

			hltests_dma_transfer(fd,
				hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE, data_buf_va,
				dram_addr[i * 2] + j * host_size, host_size,
				DMA_DIR_HOST_TO_DRAM);
		}

	activate_all2all_dma_channels(state, dram_addr, dma_size, hw_ip);

	rc = hltests_free_host_mem(fd, data_buf);
	assert_int_equal(rc, 0);

	for (i = 0 ; i < NUM_OF_INT_Q ; i++) {
		rc = hltests_free_device_mem(fd, (void *) dram_addr[i * 2]);
		assert_int_equal(rc, 0);

		rc = hltests_free_device_mem(fd,
					(void *) dram_addr[i * 2 + 1]);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID activate_super_stress_dma_channels(void **state,
					struct hlthunk_hw_ip_info *hw_ip,
					int num_of_iterations)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk restore_arr[1], execute_arr[NUM_OF_INT_Q + 1];
	uint32_t cb_common_size, queue, cp_dma_cb_size[NUM_OF_INT_Q] = {0},
		common_cb_buf_size[NUM_OF_INT_Q] = {0}, nop_cb_size = 0,
		restore_cb_size = 0;
	uint64_t seq, common_cb_device_va[NUM_OF_INT_Q],
		cp_dma_cb_device_va[NUM_OF_INT_Q],
		sram_base, cp_dma_sram_addr, dma_size = 1 << 29;
	void *restore_cb, *nop_cb, *common_cb_buf[NUM_OF_INT_Q],
		*cp_dma_cb[NUM_OF_INT_Q];
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	int rc, fd = tests_state->fd, i, j, loop_cnt;
	double *all2all_perf_outcome;
	struct timespec begin, end;

	/* 31.5GB * X */
	loop_cnt = (hw_ip->dram_size / dma_size) * num_of_iterations;
	assert_true(loop_cnt < 42000);

	sram_base = hw_ip->sram_base_address;

	restore_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(restore_cb);

	nop_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(nop_cb);

	hltests_clear_sobs(fd, 512);

	/* prepare internal DMAs */
	queue = GAUDI_QUEUE_ID_DMA_2_0;

	cb_common_size = 0x100000;

	for (i = 0 ; i < NUM_OF_INT_Q ; i++, queue += 4) {
		uint64_t dma_ch_start_addr = hw_ip->dram_base_address +
						i * 0x100000000ull;

		common_cb_buf[i] = hltests_allocate_host_mem(fd, cb_common_size,
								NOT_HUGE_MAP);
		assert_non_null(common_cb_buf[i]);
		memset(common_cb_buf[i], 0, cb_common_size);
		common_cb_buf_size[i] = 0;
		common_cb_device_va[i] = hltests_get_device_va_for_host_ptr(fd,
							common_cb_buf[i]);

		for (j = 0 ; j < loop_cnt ; j++) {
			uint64_t dst_addr = dma_ch_start_addr + dma_size;

			if (dst_addr >= hw_ip->dram_base_address +
							hw_ip->dram_size)
				dst_addr = hw_ip->dram_base_address;

			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_FALSE;
			pkt_info.dma.src_addr = dma_ch_start_addr;
			pkt_info.dma.dst_addr = dst_addr;
			pkt_info.dma.size = dma_size;
			pkt_info.dma.dma_dir = DMA_DIR_DRAM_TO_DRAM;

			common_cb_buf_size[i] = hltests_add_dma_pkt(fd,
							common_cb_buf[i],
							common_cb_buf_size[i],
							&pkt_info);

			dma_ch_start_addr += dma_size;
			if (dma_ch_start_addr >= hw_ip->dram_base_address +
							hw_ip->dram_size)
				dma_ch_start_addr = hw_ip->dram_base_address;
		}

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.sob_id = i * 8;
		pkt_info.write_to_sob.value = 1;
		pkt_info.write_to_sob.mode = SOB_SET;
		common_cb_buf_size[i] = hltests_add_write_to_sob_pkt(fd,
						common_cb_buf[i],
						common_cb_buf_size[i],
						&pkt_info);

		cp_dma_sram_addr = sram_base + (NUM_OF_INT_Q * cb_common_size) +
								(i * 0x20);

		cp_dma_cb[i] = hltests_create_cb(fd, SZ_4K, INTERNAL,
							cp_dma_sram_addr);
		assert_non_null(cp_dma_cb[i]);
		cp_dma_cb_device_va[i] = hltests_get_device_va_for_host_ptr(fd,
								cp_dma_cb[i]);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.cp_dma.src_addr = sram_base + i * cb_common_size;
		pkt_info.cp_dma.size = common_cb_buf_size[i];
		cp_dma_cb_size[i] = hltests_add_cp_dma_pkt(fd, cp_dma_cb[i],
					cp_dma_cb_size[i], &pkt_info);

		execute_arr[i].cb_ptr = cp_dma_cb[i];
		execute_arr[i].cb_size = cp_dma_cb_size[i];
		execute_arr[i].queue_index = queue;

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = cp_dma_cb_device_va[i];
		pkt_info.dma.dst_addr = cp_dma_sram_addr;
		pkt_info.dma.size = cp_dma_cb_size[i];
		pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;
		restore_cb_size = hltests_add_dma_pkt(fd, restore_cb,
							restore_cb_size,
							&pkt_info);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = common_cb_device_va[i];
		pkt_info.dma.dst_addr = sram_base + i * cb_common_size;
		pkt_info.dma.size = common_cb_buf_size[i];
		pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;
		restore_cb_size = hltests_add_dma_pkt(fd, restore_cb,
							restore_cb_size,
							&pkt_info);

		memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
		mon_and_fence_info.queue_id =
					hltests_get_dma_down_qid(fd, STREAM0);
		mon_and_fence_info.cmdq_fence = false;
		mon_and_fence_info.sob_id = i * 8;
		mon_and_fence_info.mon_id = i;
		mon_and_fence_info.mon_address = 0;
		mon_and_fence_info.sob_val = 1;
		mon_and_fence_info.dec_fence = true;
		mon_and_fence_info.mon_payload = 1;
		mon_and_fence_info.mon_mode = SOB_EQUAL;
		nop_cb_size = hltests_add_monitor_and_fence(fd, nop_cb,
					nop_cb_size, &mon_and_fence_info);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		nop_cb_size = hltests_add_nop_pkt(fd, nop_cb, nop_cb_size,
							&pkt_info);
	}

	restore_arr[0].cb_ptr = restore_cb;
	restore_arr[0].cb_size = restore_cb_size;
	restore_arr[0].queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	execute_arr[NUM_OF_INT_Q].cb_ptr = nop_cb;
	execute_arr[NUM_OF_INT_Q].cb_size = nop_cb_size;
	execute_arr[NUM_OF_INT_Q].queue_index =
				hltests_get_dma_down_qid(fd, STREAM0);

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	/* execute internal DMAs */
	rc = hltests_submit_cs(fd, restore_arr, 1, execute_arr,
			NUM_OF_INT_Q + 1, HL_CS_FLAGS_FORCE_RESTORE, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);

	all2all_perf_outcome =
		&tests_state->perf_outcomes[RESULTS_DMA_PERF_ALL2ALL_SUPER_STRESS];

	/* We multiply the result by 2 because the read and write of the DMA
	 * are both from DRAM
	 */
	*all2all_perf_outcome = get_bw_gigabyte_per_sec(
			dma_size * loop_cnt * NUM_OF_INT_Q * 2,
			&begin, &end);

	printf("Bandwidth result: %lf GB/Sec\n", *all2all_perf_outcome);

	for (i = 0 ; i < NUM_OF_INT_Q ; i++) {
		rc = hltests_destroy_cb(fd, cp_dma_cb[i]);
		assert_int_equal(rc, 0);

		rc = hltests_free_host_mem(fd, common_cb_buf[i]);
		assert_int_equal(rc, 0);
	}

	rc = hltests_destroy_cb(fd, nop_cb);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, restore_cb);
	assert_int_equal(rc, 0);

	END_TEST;
}

enum dma_super_stress_modes {
	DMA_MODE_RANDOM,
	DMA_MODE_SEQUENTIAL,
	DMA_MODE_PATTERN
};

struct dma_super_stress_cfg {
	enum dma_super_stress_modes mode;
	int num_of_iterations;
	uint64_t pattern_phases[8];
};

static int dma_super_stress_parsing_handler(void *user, const char *section,
					const char *name, const char *value)
{
	struct dma_super_stress_cfg *cfg = (struct dma_super_stress_cfg *) user;
	char *tmp;

	if (MATCH("dma_super_stress", "mode")) {
		tmp = strdup(value);
		if (!tmp)
			return 1;

		if (!strcmp("random", tmp)) {
			cfg->mode = DMA_MODE_RANDOM;
		} else if (!strcmp("sequential", tmp)) {
			cfg->mode = DMA_MODE_SEQUENTIAL;
		} else if (!strcmp("pattern", tmp)) {
			cfg->mode = DMA_MODE_PATTERN;
		} else {
			printf("invalid mode %s for super stress test\n", tmp);
			free(tmp);
			return 0;
		}
		free(tmp);
	} else if (MATCH("dma_super_stress", "num_of_iterations")) {
		cfg->num_of_iterations = atoi(value);
	} else if (MATCH("dma_super_stress", "pattern_phase1")) {
		cfg->pattern_phases[0] = strtoul(value, NULL, 0);
	} else if (MATCH("dma_super_stress", "pattern_phase2")) {
		cfg->pattern_phases[1] = strtoul(value, NULL, 0);
	} else if (MATCH("dma_super_stress", "pattern_phase3")) {
		cfg->pattern_phases[2] = strtoul(value, NULL, 0);
	} else if (MATCH("dma_super_stress", "pattern_phase4")) {
		cfg->pattern_phases[3] = strtoul(value, NULL, 0);
	} else if (MATCH("dma_super_stress", "pattern_phase5")) {
		cfg->pattern_phases[4] = strtoul(value, NULL, 0);
	} else if (MATCH("dma_super_stress", "pattern_phase6")) {
		cfg->pattern_phases[5] = strtoul(value, NULL, 0);
	} else if (MATCH("dma_super_stress", "pattern_phase7")) {
		cfg->pattern_phases[6] = strtoul(value, NULL, 0);
	} else if (MATCH("dma_super_stress", "pattern_phase8")) {
		cfg->pattern_phases[7] = strtoul(value, NULL, 0);
	} else {
		return 0; /* unknown section/name, error */
	}

	return 1;
}

VOID test_dma_all2all_super_stress(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	struct dma_super_stress_cfg cfg = {0};
	void *data_buf;
	uint64_t seq, data_buf_va;
	uint32_t host_size = 1 << 28, dma_size = 1 << 29;
	int rc, fd = tests_state->fd, i, j, k;
	char mode[30];

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	if (!config_filename)
		fail_msg("User didn't supply a configuration file name!\n");

	cfg.mode = DMA_MODE_RANDOM;

	if (ini_parse(config_filename, dma_super_stress_parsing_handler,
								&cfg) < 0)
		fail_msg("Can't load %s\n", config_filename);

	if (cfg.mode == DMA_MODE_RANDOM)
		sprintf(mode, "random");
	else if (cfg.mode == DMA_MODE_SEQUENTIAL)
		sprintf(mode, "sequential");
	else if (cfg.mode == DMA_MODE_PATTERN)
		sprintf(mode, "pattern");

	printf("Configuration loaded from %s:\n", config_filename);
	printf("mode = %s, num of iterations = %d (size per dma ch %.1fGB)\n",
		mode, cfg.num_of_iterations, cfg.num_of_iterations * 31.5f);

	/* SRAM MAP (base + ):
	 * - 0x000000 - CB of common CP
	 * - 0x100000 - CB of common CP
	 * - 0x200000 - CB of common CP
	 * - 0x300000 - CB of common CP
	 * - 0x400000 - CB of common CP
	 * - 0x500000 - CB of common CP
	 * - 0x600000 - CB of upper CP
	 * - 0x600020 - CB of upper CP
	 * - 0x600040 - CB of upper CP
	 * - 0x600060 - CB of upper CP
	 * - 0x600080 - CB of upper CP
	 * - 0x6000A0 - CB of upper CP
	 *
	 * Test description:
	 * - On each of the available internal queues a DMA will take place.
	 * - Each queue transfers data from source DRAM address to destination
	 *   DRAM address.
	 * - The data is different for each queue, and was transferred from
	 *   host to the source DRAM address for each queue.
	 * - All of the above DMA transfers happen concurrently.
	 * - Each queue signals to SOB when upon completion.
	 * - An external CB with NOP packet waits for all queues to finish in
	 *   order to signal the user that the CS has finished.
	 * - There is no compare of the data at the end of the test
	 * - The test using minimum memory allocation on the host to allow
	 *   running this in hosts with small amount of memory
	 */

	assert_true(hw_ip->dram_enabled);
	assert_true(hw_ip->dram_size > NUM_OF_INT_Q * 0x100000000ull);

	/* prepare external data buffer */
	data_buf = hltests_allocate_host_mem(fd, host_size, NOT_HUGE_MAP);
	assert_non_null(data_buf);
	data_buf_va = hltests_get_device_va_for_host_ptr(fd, data_buf);

	/* No need to allocate device memory - we use everything */

	/* initialize data for sequential and fixed */
	if (cfg.mode == DMA_MODE_PATTERN)
		for (i = 0 ; i < (host_size / 8) ; i++)
			((uint64_t *) data_buf)[i] = cfg.pattern_phases[i % 8];

	/* transfer data to DRAM */
	for (i = 0, seq = 0 ; i < NUM_OF_INT_Q ; i++) {
		uint64_t dram_ch_start_address =
				hw_ip->dram_base_address + i * 0x100000000ull;

		for (j = 0 ; j < (dma_size / host_size) ; j++) {
			if (cfg.mode == DMA_MODE_RANDOM) {
				hltests_fill_rand_values(data_buf, host_size);
			} else if (cfg.mode == DMA_MODE_SEQUENTIAL) {
				for (k = 0 ; k < (host_size / 8) ; k++)
					((uint64_t *) data_buf)[k] = seq++;
			}

			hltests_dma_transfer(fd,
				hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE, data_buf_va,
				dram_ch_start_address + j * host_size,
				host_size,
				DMA_DIR_HOST_TO_DRAM);
		}
	}

	activate_super_stress_dma_channels(state, hw_ip,
						cfg.num_of_iterations);

	rc = hltests_free_host_mem(fd, data_buf);
	assert_int_equal(rc, 0);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest gaudi_root_tests[] = {
	cmocka_unit_test_setup(test_tpc_corner_with_inbound_pci_hbw,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_all2all_stress,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_all2all_stress_minimum_host_memory,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_all2all_super_stress,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"gaudi_root [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(gaudi_root_tests) /
			sizeof((gaudi_root_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_GAUDI_ALL,
			gaudi_root_tests, num_tests);

	if (!can_open_debugfs(true))
		return 0;

	return hltests_run_group_tests("gaudi_root", gaudi_root_tests,
		num_tests, hltests_root_nic_setup, hltests_root_nic_teardown);
}

#endif /* HLTESTS_LIB_MODE */
