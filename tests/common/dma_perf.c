// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "ini.h"

#include <stddef.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#define MAX_DMA_CH		MAX_PDMA_CH_NUM

#define LIN_DMA_SIZE_FOR_HOST	SZ_64K	/* 64KB per LIN_DMA packet */

static inline uint64_t available_dram_for_test(int fd, uint64_t dram_page_size, uint32_t num_ch)
{
	uint64_t tested_dram_size = hltests_get_total_avail_device_mem(fd);
	/*
	 * All CBs in these tests should be moved to HBM, we need to take this space out of the
	 * tested area. for each channel we do 2 allocations each has page_size length.
	 */
	uint64_t reserved_size = dram_page_size * num_ch * 2;

	assert_true(tested_dram_size > reserved_size);

	return tested_dram_size - reserved_size;
}

static inline uint64_t random_aligned_offset(uint64_t memory_size, uint32_t alignment)
{
	uint64_t num_of_buckets = memory_size / alignment;

	assert_true(num_of_buckets > 0);
	return (hltests_rand_u32() % num_of_buckets) * alignment;
}

struct dma_perf_cfg {
	uint32_t dma_size;
};

static int dma_perf_parser(void *user, const char *section, const char *name,
				const char *value)
{
	struct dma_perf_cfg *dma_cfg = (struct dma_perf_cfg *) user;

	if (MATCH("dma_perf", "host_dma_size"))
		dma_cfg->dma_size = strtoul(value, NULL, 0);
	else
		return 0; /* unknown section/name, error */

	return 1;
}

VOID test_host_sram_perf(void **state)
{
	struct hltests_state *tests_state = *state;
	const char *config_filename = hltests_get_config_filename();
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	struct dma_perf_transfer transfer;
	uint64_t host_addr, sram_addr;
	int fd = tests_state->fd;
	struct dma_perf_cfg cfg;
	double *outcome;
	void *src_ptr;

	cfg.dma_size = hltests_is_gaudi3(fd) ? SZ_256K : LIN_DMA_SIZE_FOR_HOST;

	if (config_filename) {
		if (ini_parse(config_filename, dma_perf_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		printf("Configuration loaded from %s:\n", config_filename);
		printf("dma_size = 0x%x\n", cfg.dma_size);
	}

	if (!hw_ip->sram_size)
		skip();

	if (hltests_get_parser_mini_suite())
		skip();

	assert_in_range(cfg.dma_size, 1, hw_ip->sram_size);

	sram_addr = hw_ip->sram_base_address;

	src_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE_MAP);
	assert_non_null(src_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	outcome = &tests_state->perf_outcomes[RESULTS_DMA_PERF_HOST2SRAM];

	transfer.queue_index = hltests_get_dma_down_qid(fd, STREAM0);
	transfer.src_addr = host_addr;
	transfer.dst_addr = sram_addr;
	transfer.size = cfg.dma_size;
	transfer.dma_dir = DMA_DIR_HOST_TO_SRAM;

	*outcome = hltests_dma_transfer_perf(fd, &transfer);

	hltests_free_host_mem(fd, src_ptr);

	END_TEST;
}

VOID test_sram_host_perf(void **state)
{
	struct hltests_state *tests_state = *state;
	const char *config_filename = hltests_get_config_filename();
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	struct dma_perf_transfer transfer;
	uint64_t host_addr, sram_addr;
	struct dma_perf_cfg cfg;
	int fd = tests_state->fd;
	double *outcome;
	void *dst_ptr;

	cfg.dma_size = hltests_is_gaudi3(fd) ? SZ_256K : LIN_DMA_SIZE_FOR_HOST;

	if (config_filename) {
		if (ini_parse(config_filename, dma_perf_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		printf("Configuration loaded from %s:\n", config_filename);
		printf("dma_size = 0x%x\n", cfg.dma_size);
	}

	if (!hw_ip->sram_size)
		skip();

	if (hltests_get_parser_mini_suite())
		skip();

	assert_in_range(cfg.dma_size, 1, hw_ip->sram_size);

	sram_addr = hw_ip->sram_base_address;

	dst_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE_MAP);
	assert_non_null(dst_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	outcome = &tests_state->perf_outcomes[RESULTS_DMA_PERF_SRAM2HOST];

	transfer.queue_index = hltests_get_dma_up_qid(fd, STREAM0);
	transfer.src_addr = sram_addr;
	transfer.dst_addr = host_addr;
	transfer.size = cfg.dma_size;
	transfer.dma_dir = DMA_DIR_SRAM_TO_HOST;

	*outcome = hltests_dma_transfer_perf(fd, &transfer);

	hltests_free_host_mem(fd, dst_ptr);

	END_TEST;
}

VOID test_host_dram_perf(void **state)
{
	struct hltests_state *tests_state = *state;
	const char *config_filename = hltests_get_config_filename();
	struct dma_perf_cfg cfg;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	void *src_ptr, *dram_addr;
	uint64_t host_addr;
	int fd = tests_state->fd;
	double *outcome;

	cfg.dma_size = hltests_is_gaudi3(fd) ? SZ_256K : LIN_DMA_SIZE_FOR_HOST;

	if (config_filename) {
		if (ini_parse(config_filename, dma_perf_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		printf("Configuration loaded from %s:\n", config_filename);
		printf("dma_size = 0x%x\n", cfg.dma_size);
	}

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	if (hltests_get_parser_mini_suite())
		skip();

	assert_in_range(cfg.dma_size, 1, hw_ip->dram_size);
	dram_addr = hltests_allocate_device_mem(fd, cfg.dma_size, 0, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	src_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE_MAP);
	assert_non_null(src_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	outcome = &tests_state->perf_outcomes[RESULTS_DMA_PERF_HOST2DRAM];

	transfer.queue_index = hltests_get_dma_down_qid(fd, STREAM0);
	transfer.src_addr = host_addr;
	transfer.dst_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.size = cfg.dma_size;
	transfer.dma_dir = DMA_DIR_HOST_TO_DRAM;

	*outcome = hltests_dma_transfer_perf(fd, &transfer);

	hltests_free_host_mem(fd, src_ptr);
	hltests_free_device_mem(fd, dram_addr);

	END_TEST;
}

VOID test_dram_host_perf(void **state)
{
	struct hltests_state *tests_state = *state;
	const char *config_filename = hltests_get_config_filename();
	struct dma_perf_cfg cfg;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	void *dst_ptr, *dram_addr;
	uint64_t host_addr;
	int fd = tests_state->fd;
	double *outcome;

	cfg.dma_size = hltests_is_gaudi3(fd) ? SZ_256K : LIN_DMA_SIZE_FOR_HOST;

	if (config_filename) {
		if (ini_parse(config_filename, dma_perf_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		printf("Configuration loaded from %s:\n", config_filename);
		printf("dma_size = 0x%x\n", cfg.dma_size);
	}

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	if (hltests_get_parser_mini_suite())
		skip();

	assert_in_range(cfg.dma_size, 1, hw_ip->dram_size);
	dram_addr = hltests_allocate_device_mem(fd, cfg.dma_size, 0, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	dst_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE_MAP);
	assert_non_null(dst_ptr);

	host_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	outcome = &tests_state->perf_outcomes[RESULTS_DMA_PERF_DRAM2HOST];

	transfer.queue_index = hltests_get_dma_up_qid(fd, STREAM0);
	transfer.src_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.dst_addr = host_addr;
	transfer.size = cfg.dma_size;
	transfer.dma_dir = DMA_DIR_DRAM_TO_HOST;

	*outcome = hltests_dma_transfer_perf(fd, &transfer);

	hltests_free_host_mem(fd, dst_ptr);
	hltests_free_device_mem(fd, dram_addr);

	END_TEST;
}

static double mme_dma_perf_test(int fd, uint32_t num_of_mme_ch, struct dma_perf_transfer *transfer,
				int num_of_lindma_pkts, uint64_t timeout)
{
	struct hltests_cs_chunk execute_arr[MAX_NUM_OF_MME];
	uint32_t qid, alloc_size, cb_size = 0;
	uint64_t total_dma_size = 0, seq;
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_monitor mon_info;
	uint16_t start_sob, start_mon;
	struct timespec begin, end;
	int rc, i, ch, mme_id = -1;/* mme_id is incremented to the next enabled mme idx */
	void *cb[MAX_NUM_OF_MME];
	uint8_t max_mme_cnt;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	for (ch = 0; ch < num_of_mme_ch; ch++) {

		assert_false(transfer[ch].size < MME_DMA_SIZE);
		/* MME dma operations are much slower on simulator because of 2 things:
		 *   1. dma max size is 1M.
		 *   2. dma operation is not an atomic and need to use sync mechanism between
		 *      requests.
		 * Hence, limiting transfer size in simulator.
		 */
		if (hltests_is_simulator(fd)) {
			if (num_of_mme_ch > 1)
				transfer[ch].size = MME_DMA_SIZE;
			else
				transfer[ch].size = 2 * MME_DMA_SIZE;
		}
		total_dma_size += transfer[ch].size;
	}

	max_mme_cnt = hltests_get_mme_cnt(fd, hw_ip.mme_master_slave_mode);
	assert_in_range(num_of_mme_ch, 1, max_mme_cnt);

	start_sob = hltests_get_first_avail_sob(fd);
	start_mon = hltests_get_first_avail_mon(fd);
	hltests_clear_sobs(fd, 1);

	/*
	 * we iterate the number of parallel channels with the 'ch' var. The 'mme_id' var
	 * is the index of the next enabled mme and should be sent to the function
	 * hltests_prepare_mme_dma_req.
	 */
	for (ch = 0 ; ch < num_of_mme_ch ; ch++) {
		do {
			mme_id++;
		} while (!(hw_ip.mme_enabled_mask & BIT_ULL(mme_id)));

		alloc_size = hltests_get_mme_dma_cb_size(fd, num_of_lindma_pkts, transfer[ch].size);

		cb[ch] = hltests_create_cb(fd, alloc_size, EXTERNAL, 0);
		assert_non_null(cb[ch]);

		/* note - for mme we don't have the qid in transfer[ch].queue_index */
		qid = hltests_get_mme_qid(fd, mme_id, STREAM0);

		/* Just configure and ARM the monitor but don't put the fence */
		memset(&mon_info, 0, sizeof(mon_info));
		mon_info.qid = qid;
		mon_info.sob_id = start_sob;
		mon_info.mon_id = start_mon + ch;
		mon_info.mon_address = hltests_get_fence_addr(fd, qid, true);
		mon_info.sob_val = num_of_mme_ch;
		mon_info.mon_payload = 1;
		mon_info.mon_mode = SOB_EQUAL;
		cb_size = hltests_add_monitor(fd, cb[ch], 0, &mon_info);

		/* increment the 'number of channels' sob */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = qid;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.mode = SOB_ADD;
		pkt_info.write_to_sob.sob_id = start_sob;
		pkt_info.write_to_sob.value = 1;
		cb_size = hltests_add_write_to_sob_pkt(fd, cb[ch], cb_size, &pkt_info);

		/* put the fence of the monitor we configured before */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = qid;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.fence.dec_val = 1;
		pkt_info.fence.gate_val = 1;
		pkt_info.fence.fence_id = 0;
		cb_size = hltests_add_fence_pkt(fd, cb[ch], cb_size, &pkt_info);
		for (i = 0 ; i < num_of_lindma_pkts ; i++)
			cb_size = hltests_prepare_mme_dma_req(fd, cb[ch], cb_size,
								transfer[ch].src_addr,
								transfer[ch].dst_addr, mme_id,
								transfer[ch].size);

		if (hltests_is_pldm(fd))
			hltests_zero_dram_memory(fd, transfer[ch].src_addr, transfer[ch].size);

		execute_arr[ch].cb_ptr = cb[ch];
		execute_arr[ch].cb_size = cb_size;
		execute_arr[ch].queue_index = qid;
		cb_size = 0;
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, num_of_mme_ch, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs(fd, seq, TIME_1_MIN_IN_USEC);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);

	for (ch = 0; ch < num_of_mme_ch; ch++) {
		rc = hltests_destroy_cb(fd, cb[ch]);
		assert_int_equal(rc, 0);
	}

	/* return value in GB/Sec */
	return get_bw_gigabyte_per_sec(total_dma_size * num_of_lindma_pkts, &begin, &end);
}

static double indirect_perf_test(int fd, uint32_t num_of_dma_ch,
				struct dma_perf_transfer *transfer,
				int num_of_lindma_pkts, uint64_t timeout)
{
	void *cp_dma_cb[MAX_DMA_CH] = {}, *external_cb = NULL, *lower_cb[MAX_DMA_CH] = {},
			*lower_cb_dram_ptr[MAX_DMA_CH] = {}, *cp_dma_cb_dram_ptr[MAX_DMA_CH] = {};
	uint64_t lower_cb_device_va[MAX_DMA_CH] = {}, total_dma_size = 0,
			cp_dma_cb_device_va[MAX_DMA_CH] = {};
	uint32_t cp_dma_cb_offset = 0, cb_offset = 0, lower_cb_offset = 0, exec_arr_size;
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint16_t finish_sob, start_sob, finish_mon, start_mon;
	struct hltests_cs_chunk execute_arr[MAX_DMA_CH + 1];
	bool need_external_sync = hltests_is_gaudi(fd);
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor mon_info;
	struct timespec begin, end;
	uint64_t seq = 0;
	int rc, i, ch;

	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		cp_dma_cb[ch] = NULL;
		lower_cb[ch] = NULL;
		lower_cb_dram_ptr[ch] = NULL;
		cp_dma_cb_dram_ptr[ch] = NULL;
		cp_dma_cb_device_va[ch] = 0;
		lower_cb_device_va[ch] = 0;
		transfer[ch].size = (transfer[ch].size - 0x80) & ~0x7F;
		transfer[ch].src_addr =	(transfer[ch].src_addr + 0x7F) & ~0x7F;
		transfer[ch].dst_addr =	(transfer[ch].dst_addr + 0x7F) & ~0x7F;
		total_dma_size += transfer[ch].size;
	}

	/* start_sob - a sob to sync between the different channels and make sure they all start
	 * together. Each channel increments start_sob by 1 and waits until it reaches the
	 * number of channels.
	 * finish_sob - in case an external syncing is needed (currently only gaudi)
	 * then each channel increments it after finishing all DMAs and the external syncer
	 * waits until it reaches the number of channels.
	 */
	start_sob = hltests_get_first_avail_sob(fd);
	finish_sob = start_sob + 1;
	finish_mon = hltests_get_first_avail_mon(fd);
	start_mon = finish_mon + 1;

	/* Clear SOB before we start */
	hltests_clear_sobs(fd, 2);

	/* Setup lower CB for internal DMA engine */
	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		uint64_t cb_size = (uint64_t) num_of_lindma_pkts *
					hltests_get_max_pkt_size(fd, MB_TRUE, EB_TRUE,
									transfer[ch].queue_index);

		if (hltests_is_legacy_mode_enabled(fd)) {
			lower_cb[ch] = hltests_allocate_host_mem(fd, cb_size, HUGE_MAP);

			lower_cb_device_va[ch] = hltests_get_device_va_for_host_ptr(fd,
					lower_cb[ch]);

			lower_cb_dram_ptr[ch] =
					hltests_allocate_device_mem(fd, cb_size, 0, NOT_CONTIGUOUS);
			assert_non_null(lower_cb_dram_ptr[ch]);
		} else {
			lower_cb[ch] = hltests_create_cb(fd, cb_size * 2, EXTERNAL, 0);
		}
		assert_non_null(lower_cb[ch]);

		/* Just configure and ARM the monitor but don't put the fence */
		memset(&mon_info, 0, sizeof(mon_info));
		mon_info.qid = transfer[ch].queue_index;
		mon_info.sob_id = start_sob;
		mon_info.mon_id = start_mon + ch;
		mon_info.mon_address = hltests_get_fence_addr(fd,
						transfer[ch].queue_index, true);
		mon_info.sob_val = num_of_dma_ch;
		mon_info.mon_payload = 1;
		mon_info.mon_mode = SOB_EQUAL;

		lower_cb_offset = hltests_add_monitor(fd,
					lower_cb[ch], 0, &mon_info);

		/* increment the 'number of channels' sob */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = transfer[ch].queue_index;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.mode = SOB_ADD;
		pkt_info.write_to_sob.sob_id = start_sob;
		pkt_info.write_to_sob.value = 1;
		lower_cb_offset = hltests_add_write_to_sob_pkt(fd, lower_cb[ch],
						lower_cb_offset, &pkt_info);

		/* put the fence of the monitor we configured before */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = transfer[ch].queue_index;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.fence.dec_val = 1;
		pkt_info.fence.gate_val = 1;
		pkt_info.fence.fence_id = 0;
		lower_cb_offset = hltests_add_fence_pkt(fd, lower_cb[ch],
						lower_cb_offset, &pkt_info);

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = transfer[ch].queue_index;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_FALSE;
		pkt_info.dma.src_addr = transfer[ch].src_addr;
		pkt_info.dma.dst_addr = transfer[ch].dst_addr;
		pkt_info.dma.size = transfer[ch].size;
		pkt_info.dma.dma_dir = transfer[ch].dma_dir;

		for (i = 0 ; i < num_of_lindma_pkts ; i++)
			lower_cb_offset = hltests_add_dma_pkt(fd, lower_cb[ch],
						lower_cb_offset, &pkt_info);

		/*
		 * this last write to 'finish_sob' is needed only for external sync (gaudi)
		 * to signal when all channels finished.
		 */
		if (need_external_sync) {
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.qid = transfer[ch].queue_index;
			pkt_info.eb = EB_TRUE;
			pkt_info.mb = MB_TRUE;
			pkt_info.write_to_sob.sob_id = finish_sob;
			pkt_info.write_to_sob.value = 1;
			pkt_info.write_to_sob.mode = SOB_ADD;
			lower_cb_offset = hltests_add_write_to_sob_pkt(fd, lower_cb[ch],
							lower_cb_offset, &pkt_info);
		}

		if (hltests_is_legacy_mode_enabled(fd)) {
			/* Setup upper CB for internal DMA engine (cp_dma) */
			cp_dma_cb[ch] = hltests_allocate_host_mem(fd, SZ_4K, HUGE_MAP);
			assert_non_null(cp_dma_cb[ch]);
			cp_dma_cb_device_va[ch] =
				hltests_get_device_va_for_host_ptr(fd, cp_dma_cb[ch]);

			cp_dma_cb_dram_ptr[ch] =
					hltests_allocate_device_mem(fd, SZ_4K, 0, NOT_CONTIGUOUS);
			assert_non_null(cp_dma_cb_dram_ptr[ch]);

			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_FALSE;
			pkt_info.cp_dma.src_addr = (uint64_t)(uintptr_t)lower_cb_dram_ptr[ch];
			pkt_info.cp_dma.size = lower_cb_offset;
			cp_dma_cb_offset = hltests_add_cp_dma_pkt(fd, cp_dma_cb[ch],
									0, &pkt_info);

			execute_arr[ch].cb_ptr = (void *) cp_dma_cb_dram_ptr[ch];
			execute_arr[ch].cb_size = cp_dma_cb_offset;
			execute_arr[ch].queue_index = transfer[ch].queue_index;

		} else {
			execute_arr[ch].cb_ptr = lower_cb[ch];
			execute_arr[ch].cb_size = lower_cb_offset;
			execute_arr[ch].queue_index = transfer[ch].queue_index;
		}

		/* zero dram memory first to avoid ECC error on pldm (see SW-54271) */
		if (hltests_is_pldm(fd) && hltests_is_dma_dir_from_dram(transfer[ch].dma_dir))
			hltests_zero_dram_memory(fd, transfer[ch].src_addr, transfer[ch].size);

		if (hltests_is_legacy_mode_enabled(fd)) {
			/* Copy the command buffer and CP DMA buffer to dram */
			rc = hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
					EB_FALSE, MB_TRUE, lower_cb_device_va[ch],
					(uint64_t) (uintptr_t) lower_cb_dram_ptr[ch],
					lower_cb_offset, DMA_DIR_HOST_TO_DRAM);
			assert_int_equal(rc, 0);

			rc = hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
					EB_FALSE, MB_TRUE, cp_dma_cb_device_va[ch],
					(uint64_t) (uintptr_t) cp_dma_cb_dram_ptr[ch],
					cp_dma_cb_offset, DMA_DIR_HOST_TO_DRAM);
			assert_int_equal(rc, 0);
		}
	}

	if (need_external_sync) {
		uint32_t external_qid = hltests_get_dma_down_qid(fd, STREAM0);

		external_cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
		assert_non_null(external_cb);

		/* Wait for channels to announce they finished */
		memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
		mon_and_fence_info.queue_id = external_qid;
		mon_and_fence_info.cmdq_fence = false;
		mon_and_fence_info.sob_id = finish_sob;
		mon_and_fence_info.mon_id = finish_mon;
		mon_and_fence_info.mon_address = 0;
		mon_and_fence_info.sob_val = num_of_dma_ch;
		mon_and_fence_info.dec_fence = true;
		mon_and_fence_info.mon_payload = 1;
		mon_and_fence_info.mon_mode = SOB_EQUAL;
		cb_offset = hltests_add_monitor_and_fence(fd, external_cb, cb_offset,
							&mon_and_fence_info);

		execute_arr[num_of_dma_ch].cb_ptr = external_cb;
		execute_arr[num_of_dma_ch].cb_size = cb_offset;
		execute_arr[num_of_dma_ch].queue_index = external_qid;
	}

	clock_gettime(CLOCK_MONOTONIC_RAW, &begin);

	exec_arr_size = need_external_sync ? num_of_dma_ch + 1 : num_of_dma_ch;
	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, exec_arr_size, 0, &seq);
	assert_int_equal(rc, 0);

	if (timeout)
		rc = hltests_wait_for_cs(fd, seq, timeout);
	else
		rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	clock_gettime(CLOCK_MONOTONIC_RAW, &end);
	if (need_external_sync)
		hltests_destroy_cb(fd, external_cb);
	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		if (hltests_is_legacy_mode_enabled(fd)) {
			hltests_free_host_mem(fd, lower_cb[ch]);
			hltests_free_host_mem(fd, cp_dma_cb[ch]);
			hltests_free_device_mem(fd, cp_dma_cb_dram_ptr[ch]);
			hltests_free_device_mem(fd, lower_cb_dram_ptr[ch]);
		} else {
			hltests_destroy_cb(fd, lower_cb[ch]);
		}
	}

	/* return value in GB/Sec */
	return get_bw_gigabyte_per_sec(total_dma_size * num_of_lindma_pkts,
								&begin, &end);
}

typedef double (*dma_perf_test_cb)(int fd, uint32_t num_of_dma_ch,
					struct dma_perf_transfer *transfer, int num_of_lindma_pkts,
					uint64_t timeout);
struct dma_params {
	dma_perf_test_cb perf_cb;
	enum hltests_test_results type;
	uint32_t total_dma_size;
	int num_ch;
};

static VOID test_sram_dram_single_ch(void **state, struct dma_params *params)
{
	struct hltests_state *tests_state = *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int fd = tests_state->fd;
	uint64_t sram_addr;
	double *outcome;
	void *dram_addr;
	uint32_t size = params->total_dma_size;

	if (!hw_ip->sram_size)
		skip();

	if (hltests_is_gaudi3(fd)) {
		printf("skip sram<->dram tests for gaudi3\n");
		skip();
	}

	/* TODO - remove once SW-174350 will be resolved */
	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("skip sram<->dram tests for non legacy mode\n");
		skip();
	}

	if (hltests_get_parser_mini_suite())
		skip();

	sram_addr = hw_ip->sram_base_address;

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	} else if (hltests_is_simulator(fd) && size > hw_ip->dram_size) {
		printf("SIM's DRAM (%lu[B]) is smaller than required allocation (%u[B]) - skip\n",
			hw_ip->dram_size, size);
		skip();
	}
	assert_in_range(size, 1, hw_ip->dram_size);

	dram_addr = hltests_allocate_device_mem(fd, size, 0, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	outcome = &tests_state->perf_outcomes[params->type];

	transfer.queue_index = hltests_get_ddma_qid(fd, 0, STREAM0);
	transfer.src_addr = sram_addr;
	transfer.dst_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.size = size;
	transfer.dma_dir = DMA_DIR_SRAM_TO_DRAM;

	if (hltests_is_goya(fd)) {
		*outcome = hltests_dma_transfer_perf(fd, &transfer);
	} else {
		int num_of_lindma_pkts;

		if (hltests_is_pldm(fd))
			num_of_lindma_pkts = 1;
		else if (hltests_is_simulator(fd))
			num_of_lindma_pkts = 10;
		else
			num_of_lindma_pkts = 30000;

		*outcome = params->perf_cb(fd, 1, &transfer, num_of_lindma_pkts, 0);
	}

	hltests_free_device_mem(fd, dram_addr);

	END_TEST;
}

VOID test_sram_dram_single_ch_perf(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd;
	struct dma_params params = { 0 };

	if (!hltests_get_ddma_cnt(fd))
		skip();

	params.perf_cb = indirect_perf_test;
	params.type = RESULTS_DMA_PERF_SRAM2DRAM_SINGLE_CH;
	params.num_ch = 1;

	if (hltests_is_pldm(fd))
		params.total_dma_size = SZ_4K;
	else
		params.total_dma_size = tests_state->hw_ip.sram_size;

	END_TEST_FUNC(test_sram_dram_single_ch(state, &params));
}

static VOID test_dram_sram_single_ch(void **state, struct dma_params *params)
{
	struct hltests_state *tests_state = *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	uint32_t size = params->total_dma_size;
	int fd = tests_state->fd;
	uint64_t sram_addr;
	double *outcome;
	void *dram_addr;

	if (!hw_ip->sram_size)
		skip();

	if (hltests_is_gaudi3(fd)) {
		printf("skip sram<->dram tests for gaudi3\n");
		skip();
	}

	/* TODO - remove once SW-174350 will be resolved */
	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("skip dram<->sram tests for non legacy mode\n");
		skip();
	}

	if (hltests_get_parser_mini_suite())
		skip();

	sram_addr = hw_ip->sram_base_address;

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	} else {
		if (hltests_is_simulator(fd) && size > hw_ip->dram_size) {
			printf(
				"SIM's DRAM (%lu[B]) is smaller than required allocation (%u[B]) so skipping test\n",
				hw_ip->dram_size, size);
			skip();
		}
		assert_in_range(size, 1, hw_ip->dram_size);
	}

	dram_addr = hltests_allocate_device_mem(fd, size, 0, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	outcome = &tests_state->perf_outcomes[params->type];

	transfer.queue_index = hltests_get_ddma_qid(fd, 0, STREAM0);
	transfer.src_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.dst_addr = sram_addr;
	transfer.size = size;
	transfer.dma_dir = DMA_DIR_DRAM_TO_SRAM;

	if (hltests_is_goya(fd)) {
		*outcome = hltests_dma_transfer_perf(fd, &transfer);
	} else {
		int num_of_lindma_pkts;

		if (hltests_is_pldm(fd))
			num_of_lindma_pkts = 1;
		else if (hltests_is_simulator(fd))
			num_of_lindma_pkts = 10;
		else
			num_of_lindma_pkts = 30000;

		*outcome = params->perf_cb(fd, 1, &transfer, num_of_lindma_pkts, 0);
	}

	hltests_free_device_mem(fd, dram_addr);

	END_TEST;
}

VOID test_dram_sram_single_ch_perf(void **state)
{
	struct dma_params params = { 0 };
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd;

	if (!hltests_get_ddma_cnt(fd))
		skip();

	params.perf_cb = indirect_perf_test;
	params.type = RESULTS_DMA_PERF_DRAM2SRAM_SINGLE_CH;
	params.num_ch = 1;

	if (hltests_is_pldm(fd))
		params.total_dma_size = SZ_4K;
	else
		params.total_dma_size = tests_state->hw_ip.sram_size;

	END_TEST_FUNC(test_dram_sram_single_ch(state, &params));
}

static VOID test_dram_dram_single_ch(void **state, struct dma_params *params)
{
	struct hltests_state *tests_state = *state;
	struct dma_perf_transfer transfer;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	uint32_t size = params->total_dma_size;
	int fd = tests_state->fd;
	void *dram_addr;
	double *outcome;

	if (hltests_get_parser_mini_suite())
		skip();

	/* TODO - remove once SW-174350 will be resolved */
	if (hltests_is_gaudi2(fd) && !hltests_is_legacy_mode_enabled(fd)) {
		printf("skip dram<->dram tests for non legacy mode\n");
		skip();
	}

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	} else {
		if (hltests_is_simulator(fd) && (2 * size) > hw_ip->dram_size) {
			printf(
				"SIM's DRAM (%lu[B]) is smaller than required allocation (%u[B]) so skipping test\n",
				hw_ip->dram_size, 2 * size);
			skip();
		}
		assert_in_range(size, 1, hw_ip->dram_size);
	}

	dram_addr = hltests_allocate_device_mem(fd, size * 2, 0, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	outcome = &tests_state->perf_outcomes[params->type];

	transfer.queue_index = hltests_get_ddma_qid(fd, 0, STREAM0);
	transfer.src_addr = (uint64_t) (uintptr_t) dram_addr;
	transfer.dst_addr = ((uint64_t) (uintptr_t) dram_addr) + size;
	transfer.size = size;
	transfer.dma_dir = DMA_DIR_DRAM_TO_DRAM;

	if (hltests_is_goya(fd)) {
		*outcome = hltests_dma_transfer_perf(fd, &transfer);
	} else {
		int num_of_lindma_pkts;

		if (hltests_is_pldm(fd))
			num_of_lindma_pkts = 1;
		else if (hltests_is_simulator(fd))
			num_of_lindma_pkts = 10;
		else
			num_of_lindma_pkts = 130000;

		*outcome = params->perf_cb(fd, 1, &transfer, num_of_lindma_pkts, 0);
	}

	hltests_free_device_mem(fd, dram_addr);

	END_TEST;
}

VOID test_dram_dram_single_ch_mme_dma_perf(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd;
	struct dma_params params = { 0 };

	/* TODO - remove skip for GAUDI3D once SW-219441 is resolved */
	if (!hltests_is_mme_dma_enabled(fd) || hltests_is_gaudi3d(fd))
		skip();

	params.perf_cb = mme_dma_perf_test;
	params.type = RESULTS_DMA_PERF_DRAM2DRAM_SINGLE_CH_MME_DMA;
	params.num_ch = 1;

	params.total_dma_size = MME_DMA_SIZE;

	END_TEST_FUNC(test_dram_dram_single_ch(state, &params));
}

VOID test_dram_dram_single_ch_perf(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd;
	struct dma_params params = { 0 };

	if (!hltests_get_ddma_cnt(fd))
		skip();

	params.perf_cb = indirect_perf_test;
	params.type = RESULTS_DMA_PERF_DRAM2DRAM_SINGLE_CH;
	params.num_ch = 1;

	if (hltests_is_pldm(fd))
		params.total_dma_size = SZ_4K;
	else
		params.total_dma_size = SZ_4M;

	END_TEST_FUNC(test_dram_dram_single_ch(state, &params));
}

static VOID test_sram_dram_multi_ch(void **state, struct dma_params *params)
{
	int num_of_lindma_pkts, ch, fd, num_of_dma_ch = params->num_ch;
	uint32_t total_dma_size = params->total_dma_size;
	uint64_t dram_addr, sram_addr, tested_dram_size;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	struct hltests_state *tests_state = *state;
	struct hlthunk_hw_ip_info *hw_ip;
	double *outcome;

	fd = tests_state->fd;
	hw_ip = &tests_state->hw_ip;

	/* This test can't run on Goya */
	if (hltests_is_goya(fd)) {
		printf("Test is skipped for GOYA\n");
		skip();
	}

	if (!hw_ip->sram_size)
		skip();

	if (hltests_is_gaudi3(fd)) {
		printf("skip sram<->dram tests for gaudi3\n");
		skip();
	}

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	if (hltests_is_simulator(fd)) {
		printf("Multi channels perf tests are skipped for simulators\n");
		skip();
	}

	if (hltests_is_gaudi2(fd) && !hltests_is_legacy_mode_enabled(fd)) {
		printf("Multi channels perf tests are temporarily skipped for gaudi2 ARC mode\n");
		skip();
	}

	sram_addr = hw_ip->sram_base_address;
	tested_dram_size = available_dram_for_test(fd, hw_ip->dram_page_size, num_of_dma_ch);
	num_of_lindma_pkts = 60000;

	if (hltests_is_pldm(fd))
		num_of_lindma_pkts = 1;
	else if (hltests_is_simulator(fd))
		num_of_lindma_pkts = 10;

	assert_in_range(total_dma_size, 1, tested_dram_size);
	assert_in_range(num_of_dma_ch, 1, MAX_DMA_CH);

	outcome = &tests_state->perf_outcomes[params->type];

	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, tested_dram_size, 0, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];

		t->queue_index = hltests_get_ddma_qid(fd, ch, STREAM0);
		t->size = total_dma_size / num_of_dma_ch;
		t->src_addr = sram_addr + ch * t->size;
		t->dst_addr = dram_addr + random_aligned_offset(tested_dram_size, t->size);

		assert_in_range(t->dst_addr, dram_addr,
				dram_addr + tested_dram_size);
		assert_in_range(t->dst_addr + t->size,
				dram_addr, dram_addr + tested_dram_size);
	}

	*outcome = params->perf_cb(fd, num_of_dma_ch, transfer, num_of_lindma_pkts, 0);

	hltests_free_device_mem(fd, (void *) dram_addr);

	END_TEST;
}

VOID test_sram_dram_multi_ch_perf(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd;
	struct dma_params params = { 0 };

	if (!hltests_get_ddma_cnt(fd))
		skip();

	params.perf_cb = indirect_perf_test;
	params.type = RESULTS_DMA_PERF_SRAM2DRAM_MULTI_CH;
	params.total_dma_size = tests_state->hw_ip.sram_size;
	params.num_ch = hltests_get_ddma_cnt(fd);

	if (hltests_is_pldm(fd)) {
		params.total_dma_size = SZ_4K;
		params.num_ch = 1;
	}

	END_TEST_FUNC(test_sram_dram_multi_ch(state, &params));
}

static VOID test_dram_sram_multi_ch(void **state, struct dma_params *params)
{
	int num_of_lindma_pkts, ch, fd, num_of_dma_ch = params->num_ch;
	uint32_t total_dma_size = params->total_dma_size;
	uint64_t dram_addr, sram_addr, tested_dram_size;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	struct hltests_state *tests_state = *state;
	struct hlthunk_hw_ip_info *hw_ip;
	double *outcome;

	fd = tests_state->fd;
	hw_ip = &tests_state->hw_ip;

	/* This test can't run on Goya */
	if (hltests_is_goya(fd)) {
		printf("Test is skipped for GOYA\n");
		skip();
	}

	if (!hw_ip->sram_size)
		skip();

	if (hltests_is_gaudi3(fd)) {
		printf("skip sram<->dram tests for gaudi3\n");
		skip();
	}

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	if (hltests_is_simulator(fd)) {
		printf("Multi channels perf tests are skipped for simulators\n");
		skip();
	}

	if (hltests_is_gaudi2(fd) && !hltests_is_legacy_mode_enabled(fd)) {
		printf("Multi channels perf tests are temporarily skipped for gaudi2 ARC mode\n");
		skip();
	}

	sram_addr = hw_ip->sram_base_address;
	tested_dram_size = available_dram_for_test(fd, hw_ip->dram_page_size, num_of_dma_ch);

	num_of_lindma_pkts = 60000;

	if (hltests_is_pldm(fd))
		num_of_lindma_pkts = 1;
	else if (hltests_is_simulator(fd))
		num_of_lindma_pkts = 10;

	assert_in_range(total_dma_size, 1, tested_dram_size);
	assert_in_range(num_of_dma_ch, 1, MAX_DMA_CH);

	outcome = &tests_state->perf_outcomes[params->type];

	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, tested_dram_size, 0, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];

		t->queue_index = hltests_get_ddma_qid(fd, ch, STREAM0);
		t->size = total_dma_size / num_of_dma_ch;
		t->src_addr = dram_addr + random_aligned_offset(tested_dram_size, t->size);
		t->dst_addr = sram_addr + ch * t->size;

		assert_in_range(t->src_addr, dram_addr,
				dram_addr + tested_dram_size);
		assert_in_range(t->src_addr + t->size,
				dram_addr, dram_addr + tested_dram_size);
	}

	*outcome = params->perf_cb(fd, num_of_dma_ch, transfer, num_of_lindma_pkts, 0);

	hltests_free_device_mem(fd, (void *) dram_addr);

	END_TEST;
}

VOID test_dram_sram_multi_ch_perf(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd;
	struct dma_params params = { 0 };

	if (!hltests_get_ddma_cnt(fd))
		skip();

	params.perf_cb = indirect_perf_test;
	params.type = RESULTS_DMA_PERF_DRAM2SRAM_MULTI_CH;
	params.num_ch = hltests_get_ddma_cnt(fd);

	if (hltests_is_pldm(fd))
		params.total_dma_size = SZ_4K;
	else
		params.total_dma_size = tests_state->hw_ip.sram_size;

	END_TEST_FUNC(test_dram_sram_multi_ch(state, &params));
}

VOID test_host_to_or_from_dram_multi_ch(struct hltests_state *tests_state,
						struct dma_params *params, bool host_to_dram)
{
	int num_of_lindma_pkts, ch, fd = tests_state->fd, num_of_dma_ch = params->num_ch;
	uint64_t timeout = hltests_is_pldm(fd) ? 10 * TIME_1_MIN_IN_USEC : 3 * TIME_1_MIN_IN_USEC;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	uint64_t dram_va, host_va, tested_dram_size;
	uint32_t total_dma_size;
	void *host_ptr;

	if (!hltests_is_gaudi3(fd)) {
		printf("Test is only for Gaudi3\n");
		skip();
	}

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	if (hltests_is_simulator(fd)) {
		printf("Multi channels perf tests are skipped for simulators\n");
		skip();
	}

	if (hltests_is_gaudi2(fd) && !hltests_is_legacy_mode_enabled(fd)) {
		printf("Multi channels perf tests are temporarily skipped for gaudi2 ARC mode\n");
		skip();
	}

	total_dma_size = params->total_dma_size;
	tested_dram_size = available_dram_for_test(fd, hw_ip->dram_page_size, num_of_dma_ch);
	assert_in_range(num_of_dma_ch, 1, MAX_DMA_CH);

	if (hltests_is_pldm(fd))
		num_of_lindma_pkts = 1;
	else if (hltests_is_simulator(fd))
		num_of_lindma_pkts = 5;
	else
		num_of_lindma_pkts = 0x400000000ull / total_dma_size;

	assert_in_range(total_dma_size, 1, tested_dram_size);

	host_ptr = hltests_allocate_host_mem(fd, total_dma_size, HUGE_MAP);
	assert_non_null(host_ptr);
	host_va = hltests_get_device_va_for_host_ptr(fd, host_ptr);

	dram_va = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, tested_dram_size, 0, NOT_CONTIGUOUS);
	assert_non_null(dram_va);

	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];
		uint64_t host_addr, dram_addr;

		t->queue_index = hltests_get_pdma_qid(fd, ch);
		t->size = total_dma_size / num_of_dma_ch;

		host_addr = host_va + ch * t->size;
		dram_addr = dram_va + random_aligned_offset(tested_dram_size, t->size);

		if (host_to_dram) {
			t->src_addr = host_addr;
			t->dst_addr = dram_addr;
			t->dma_dir = DMA_DIR_HOST_TO_DRAM;
		} else {
			t->src_addr = dram_addr;
			t->dst_addr = host_addr;
			t->dma_dir = DMA_DIR_DRAM_TO_HOST;
		}

		assert_in_range(host_addr, host_va, host_va + total_dma_size - 1);
		assert_in_range(host_addr + t->size, host_va, host_va + total_dma_size);

		assert_in_range(dram_addr, dram_va, dram_va + tested_dram_size - 1);
		assert_in_range(dram_addr + t->size, dram_va, dram_va + tested_dram_size);
	}

	tests_state->perf_outcomes[params->type] =
		params->perf_cb(fd, num_of_dma_ch, transfer, num_of_lindma_pkts, timeout);

	hltests_free_device_mem(fd, (void *) dram_va);
	hltests_free_host_mem(fd, host_ptr);

	END_TEST;
}

VOID test_host_dram_multi_ch(void **state, bool host_to_dram)
{
	struct hltests_state *tests_state = *state;
	struct dma_params params = { 0 };
	int fd = tests_state->fd;
	uint32_t size_per_ch;

	if (!hltests_is_gaudi3(fd)) {
		printf("Test is only for Gaudi3\n");
		skip();
	}

	params.perf_cb = indirect_perf_test;
	params.type = host_to_dram ? RESULTS_DMA_PERF_HOST2DRAM_MULTI_CH :
				RESULTS_DMA_PERF_DRAM2HOST_MULTI_CH;
	params.num_ch = hltests_get_pdma_ch_cnt(fd);

	size_per_ch = LIN_DMA_SIZE_FOR_HOST;
	params.total_dma_size = params.num_ch * size_per_ch;

	END_TEST_FUNC(test_host_to_or_from_dram_multi_ch(tests_state, &params, host_to_dram));
}

VOID test_host_dram_multi_ch_perf(void **state)
{
	END_TEST_FUNC(test_host_dram_multi_ch(state, true));
}

VOID test_dram_host_multi_ch_perf(void **state)
{
	END_TEST_FUNC(test_host_dram_multi_ch(state, false));
}

static VOID test_dram_dram_multi_ch(void **state, struct dma_params *params)
{
	int num_of_lindma_pkts, ch, fd, num_of_dma_ch = params->num_ch;
	uint32_t total_dma_size = params->total_dma_size;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	struct hltests_state *tests_state = *state;
	uint64_t dram_addr, tested_dram_size;
	struct hlthunk_hw_ip_info *hw_ip;

	fd = tests_state->fd;
	hw_ip = &tests_state->hw_ip;

	/* This test can't run on Goya */
	if (hltests_is_goya(fd)) {
		printf("Test is skipped for GOYA\n");
		skip();
	}

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	if (hltests_is_simulator(fd)) {
		printf("Multi channels perf tests are skipped for simulators\n");
		skip();
	}

	if (hltests_is_gaudi2(fd) && !hltests_is_legacy_mode_enabled(fd)) {
		printf("Multi channels perf tests are temporarily skipped for gaudi2 ARC mode\n");
		skip();
	}

	tested_dram_size = available_dram_for_test(fd, hw_ip->dram_page_size, num_of_dma_ch);
	num_of_lindma_pkts = 40000;

	/* Note that the number of MME_DMAs matches the number of DDMAs only by accident,
	 * so remember it on every attempt to reuse this function with other engines.
	 */
	assert_in_range(num_of_dma_ch, 1, MAX_DMA_CH);

	if (hltests_is_pldm(fd))
		num_of_lindma_pkts = 1;

	if (hltests_is_simulator(fd)) {
		if (total_dma_size > tested_dram_size) {
			printf("SIM's DRAM (%lu[B]) is smaller than dma size (%u[B]) - skip\n",
				hw_ip->dram_size, total_dma_size);
			skip();
		}
		num_of_lindma_pkts = 10;
	}

	assert_in_range(total_dma_size, 1, tested_dram_size);

	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, tested_dram_size, 0, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];

		/* It's incorrect to address a DDMA when in MME_DMA context */
		if (params->type != RESULTS_DMA_PERF_DRAM2DRAM_SINGLE_CH_MME_DMA &&
				params->type != RESULTS_DMA_PERF_DRAM2DRAM_MULTI_CH_MME_DMA)
			t->queue_index = hltests_get_ddma_qid(fd, ch, STREAM0);

		t->size = total_dma_size / num_of_dma_ch;
		t->src_addr = dram_addr + random_aligned_offset(tested_dram_size, t->size);
		t->dst_addr = dram_addr + random_aligned_offset(tested_dram_size, t->size);

		assert_in_range(t->src_addr, dram_addr,
				dram_addr + tested_dram_size);
		assert_in_range(t->src_addr + t->size,
				dram_addr, dram_addr + tested_dram_size);
		assert_in_range(t->dst_addr, dram_addr,
				dram_addr + tested_dram_size);
		assert_in_range(t->dst_addr + t->size,
				dram_addr, dram_addr + tested_dram_size);
	}

	tests_state->perf_outcomes[params->type] = params->perf_cb(fd, num_of_dma_ch, transfer,
		num_of_lindma_pkts, 0);

	hltests_free_device_mem(fd, (void *) dram_addr);

	END_TEST;
}

VOID test_dram_dram_multi_ch_mme_dma_perf(void **state)
{
	struct hltests_state *tests_state = *state;
	uint32_t size_per_ch, max_mme_cnt;
	struct hlthunk_hw_ip_info *hw_ip;
	int fd = tests_state->fd;
	struct dma_params params = { 0 };
	int i;

	/* TODO - remove skip for GAUDI3D once SW-219441 is resolved */
	if (!hltests_is_mme_dma_enabled(fd) || hltests_is_gaudi3d(fd))
		skip();

	hw_ip = &tests_state->hw_ip;

	params.perf_cb = mme_dma_perf_test;
	params.type = RESULTS_DMA_PERF_DRAM2DRAM_MULTI_CH_MME_DMA;

	max_mme_cnt = hltests_get_mme_cnt(tests_state->fd, hw_ip->mme_master_slave_mode);

	for (i = 0 ; i < max_mme_cnt ; i++)
		if (hw_ip->mme_enabled_mask & (0x1ULL << i))
			params.num_ch++;
	assert_int_not_equal(params.num_ch, 0);

	if (hltests_is_pldm(fd))
		size_per_ch = MME_DMA_SIZE;
	else
		size_per_ch = ALIGN_DOWN(40 * SZ_1M / params.num_ch, MME_DMA_SIZE);

	params.total_dma_size = params.num_ch * size_per_ch;

	END_TEST_FUNC(test_dram_dram_multi_ch(state, &params));
}

VOID test_dram_dram_multi_ch_perf(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd;
	struct dma_params params = { 0 };

	if (!hltests_get_ddma_cnt(fd))
		skip();

	params.perf_cb = indirect_perf_test;
	params.type = RESULTS_DMA_PERF_DRAM2DRAM_MULTI_CH;
	params.num_ch = hltests_get_ddma_cnt(fd);

	if (hltests_is_pldm(fd))
		params.total_dma_size = SZ_4K;
	else if (hltests_is_simulator(fd))
		params.total_dma_size = SZ_1M;
	else
		/* size is decided to be 40M, see SW-109961 */
		params.total_dma_size = 40 * SZ_1M;

	END_TEST_FUNC(test_dram_dram_multi_ch(state, &params));
}

static VOID test_sram_dram_bidirectional_full_multi_ch(void **state, struct dma_params *params)
{
	int num_of_lindma_pkts, ch, fd, num_of_dma_ch = params->num_ch;
	uint32_t total_dma_size = params->total_dma_size;
	uint64_t dram_addr, sram_addr, tested_dram_size;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	struct hltests_state *tests_state = *state;
	struct hlthunk_hw_ip_info *hw_ip;
	double *outcome;

	fd = tests_state->fd;
	hw_ip = &tests_state->hw_ip;

	if (hltests_is_pldm(fd))
		skip();

	if (hltests_is_goya(fd)) {
		printf("Test is skipped for GOYA\n");
		skip();
	}

	if (!hw_ip->sram_size)
		skip();

	if (hltests_is_gaudi3(fd)) {
		printf("skip sram<->dram tests for gaudi3\n");
		skip();
	}

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	if (hltests_is_simulator(fd)) {
		printf("Multi channels perf tests are skipped for simulators\n");
		skip();
	}

	if (hltests_is_gaudi2(fd) && !hltests_is_legacy_mode_enabled(fd)) {
		printf("Multi channels perf tests are temporarily skipped for gaudi2 ARC mode\n");
		skip();
	}

	sram_addr = hw_ip->sram_base_address;
	tested_dram_size = available_dram_for_test(fd, hw_ip->dram_page_size, num_of_dma_ch);
	num_of_lindma_pkts = 60000;

	if (hltests_is_simulator(fd))
		num_of_lindma_pkts = 10;

	assert_in_range(total_dma_size, 1, tested_dram_size);
	assert_in_range(num_of_dma_ch, 1, MAX_DMA_CH);

	outcome = &tests_state->perf_outcomes[params->type];

	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, tested_dram_size, 0, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];
		uint64_t sram_addr_for_ch, dram_addr_for_ch;

		t->queue_index = hltests_get_ddma_qid(fd, ch, STREAM0);
		t->size = total_dma_size / num_of_dma_ch;

		sram_addr_for_ch = sram_addr + ch * t->size;
		dram_addr_for_ch = dram_addr + random_aligned_offset(tested_dram_size, t->size);

		if ((ch == 1) || (ch == 2) || (ch == 5)) {
			t->src_addr = sram_addr_for_ch;
			t->dst_addr = dram_addr_for_ch;

			assert_in_range(t->dst_addr, dram_addr,
					dram_addr + tested_dram_size);
			assert_in_range(t->dst_addr + t->size,
					dram_addr,
					dram_addr + tested_dram_size);
		} else {
			t->dst_addr = sram_addr_for_ch;
			t->src_addr = dram_addr_for_ch;

			assert_in_range(t->src_addr, dram_addr,
					dram_addr + tested_dram_size);
			assert_in_range(t->src_addr + t->size,
					dram_addr,
					dram_addr + tested_dram_size);
		}
	}

	*outcome = params->perf_cb(fd, num_of_dma_ch, transfer, num_of_lindma_pkts, 0);

	hltests_free_device_mem(fd, (void *) dram_addr);

	END_TEST;
}

VOID test_sram_dram_bidirectional_full_multi_ch_perf(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd;
	struct dma_params params = { 0 };

	if (!hltests_get_ddma_cnt(fd))
		skip();

	params.total_dma_size = tests_state->hw_ip.sram_size;
	params.perf_cb = indirect_perf_test;
	params.type = RESULTS_DMA_PERF_SRAM_DRAM_BIDIR_FULL_CH;
	params.num_ch = hltests_get_ddma_cnt(fd);

	END_TEST_FUNC(test_sram_dram_bidirectional_full_multi_ch(state, &params));
}

static VOID test_dram_sram_5ch(void **state, struct dma_params *params)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int num_of_lindma_pkts, ch, fd = tests_state->fd;
	struct dma_perf_transfer transfer[MAX_DMA_CH];
	uint32_t size = params->total_dma_size, queue_index[5] = {0, 1, 2, 3, 4};
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	uint64_t dram_addr, sram_addr, tested_dram_size;
	int num_of_dma_ch = params->num_ch;
	double *outcome;

	/* This test runs on Gaudi */
	if (!hltests_is_gaudi(fd)) {
		printf("Test is only for GAUDI\n");
		skip();
	}

	if (hltests_is_pldm(fd))
		num_of_lindma_pkts = 1;
	else if (hltests_is_simulator(fd))
		num_of_lindma_pkts = 10;
	else
		num_of_lindma_pkts = 60000;

	if (!hw_ip->sram_size)
		skip();

	if (hltests_is_gaudi3(fd)) {
		printf("skip sram<->dram tests for gaudi3\n");
		skip();
	}

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	if (hltests_is_simulator(fd) && hltests_is_gaudi(fd)) {
		printf("skip for gaudi simulator\n");
		skip();
	}

	sram_addr = hw_ip->sram_base_address;

	outcome = &tests_state->perf_outcomes[params->type];

	tested_dram_size = available_dram_for_test(fd, hw_ip->dram_page_size, num_of_dma_ch);

	assert_in_range(size, 1, hw_ip->dram_size);
	dram_addr = (uint64_t) (uintptr_t)
			hltests_allocate_device_mem(fd, tested_dram_size, 0, NOT_CONTIGUOUS);
	assert_non_null(dram_addr);

	for (ch = 0 ; ch < num_of_dma_ch ; ch++) {
		struct dma_perf_transfer *t = &transfer[ch];

		t->queue_index = hltests_get_ddma_qid(fd, queue_index[ch],
							STREAM0);
		t->size = size / num_of_dma_ch;
		t->src_addr = dram_addr + random_aligned_offset(tested_dram_size, t->size);
		t->dst_addr = sram_addr + ch * t->size;

		assert_in_range(t->src_addr, dram_addr,
				dram_addr + tested_dram_size);
		assert_in_range(t->src_addr + t->size,
				dram_addr, dram_addr + tested_dram_size);
	}

	*outcome = params->perf_cb(fd, num_of_dma_ch, transfer, num_of_lindma_pkts, 0);
	hltests_free_device_mem(fd, (void *) dram_addr);

	END_TEST;
}

VOID test_dram_sram_5ch_perf(void **state)
{
	struct hltests_state *tests_state = *state;
	int fd = tests_state->fd;
	struct dma_params params = { 0 };

	if (!hltests_get_ddma_cnt(fd))
		skip();

	if (hltests_is_pldm(fd))
		params.total_dma_size = SZ_4K;
	else
		params.total_dma_size = tests_state->hw_ip.sram_size;

	params.perf_cb = indirect_perf_test;
	params.type = RESULTS_DMA_PERF_DRAM2SRAM_5_CH;
	params.num_ch = 5;
	END_TEST_FUNC(test_dram_sram_5ch(state, &params));
}

VOID test_host_sram_bidirectional_perf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct dma_perf_transfer host_to_sram_transfer, sram_to_host_transfer;
	uint64_t host_src_addr, host_dst_addr, sram_addr1, sram_addr2;
	struct dma_perf_cfg cfg;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	void *src_ptr, *dst_ptr;
	int fd = tests_state->fd;
	double *outcome;

	cfg.dma_size = hltests_is_gaudi3(fd) ? SZ_256K : LIN_DMA_SIZE_FOR_HOST;

	if (config_filename) {
		if (ini_parse(config_filename, dma_perf_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		printf("Configuration loaded from %s:\n", config_filename);
		printf("dma_size = 0x%x\n", cfg.dma_size);
	}

	if (!hw_ip->sram_size)
		skip();

	assert_in_range(cfg.dma_size, 1, hw_ip->sram_size / 2);

	sram_addr1 = hw_ip->sram_base_address;
	sram_addr2 = sram_addr1 + cfg.dma_size;

	src_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE_MAP);
	assert_non_null(src_ptr);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE_MAP);
	assert_non_null(dst_ptr);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	outcome = &tests_state->perf_outcomes[RESULTS_DMA_PERF_HOST_SRAM_BIDIR];

	host_to_sram_transfer.queue_index =
			hltests_get_dma_down_qid(fd, STREAM0);
	host_to_sram_transfer.src_addr = host_src_addr;
	host_to_sram_transfer.dst_addr = sram_addr1;
	host_to_sram_transfer.size = cfg.dma_size;
	host_to_sram_transfer.dma_dir = DMA_DIR_HOST_TO_SRAM;

	sram_to_host_transfer.queue_index =
			hltests_get_dma_up_qid(fd, STREAM0);
	sram_to_host_transfer.src_addr = sram_addr2;
	sram_to_host_transfer.dst_addr = host_dst_addr;
	sram_to_host_transfer.size = cfg.dma_size;
	sram_to_host_transfer.dma_dir = DMA_DIR_SRAM_TO_HOST;

	*outcome = hltests_dma_transfer_perf_bidirectional(fd,
				&host_to_sram_transfer, &sram_to_host_transfer);

	hltests_free_host_mem(fd, src_ptr);
	hltests_free_host_mem(fd, dst_ptr);

	END_TEST;
}

VOID test_host_dram_bidirectional_perf(void **state)
{
	struct dma_perf_transfer host_to_dram_transfer, dram_to_host_transfer;
	const char *config_filename = hltests_get_config_filename();
	void *src_ptr, *dst_ptr, *dram_ptr1, *dram_ptr2;
	struct hltests_state *tests_state = *state;
	uint64_t host_src_addr, host_dst_addr;
	struct hlthunk_hw_ip_info *hw_ip;
	int fd = tests_state->fd;
	struct dma_perf_cfg cfg;
	double *outcome;

	hw_ip = &tests_state->hw_ip;

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	cfg.dma_size = hltests_is_gaudi3(fd) ? SZ_256K : LIN_DMA_SIZE_FOR_HOST;

	if (config_filename) {
		if (ini_parse(config_filename, dma_perf_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		printf("Configuration loaded from %s:\n", config_filename);
		printf("dma_size = 0x%x\n", cfg.dma_size);
	}

	assert_in_range(cfg.dma_size + cfg.dma_size, 1, hw_ip->dram_size);

	if ((2 * hw_ip->device_mem_alloc_default_page_size) > hw_ip->dram_size) {
		printf(
			"DRAM (%lu[B]) is smaller than required allocation (%lu[B]) so skipping test\n",
			hw_ip->dram_size, 2 * hw_ip->device_mem_alloc_default_page_size);
		skip();
	}

	dram_ptr1 = hltests_allocate_device_mem(fd, cfg.dma_size, 0, NOT_CONTIGUOUS);
	assert_non_null(dram_ptr1);
	dram_ptr2 = hltests_allocate_device_mem(fd, cfg.dma_size, 0, NOT_CONTIGUOUS);
	assert_non_null(dram_ptr2);

	src_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE_MAP);
	assert_non_null(src_ptr);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, cfg.dma_size, HUGE_MAP);
	assert_non_null(dst_ptr);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	outcome = &tests_state->perf_outcomes[RESULTS_DMA_PERF_HOST_DRAM_BIDIR];

	host_to_dram_transfer.queue_index =
			hltests_get_dma_down_qid(fd, STREAM0);
	host_to_dram_transfer.src_addr = host_src_addr;
	host_to_dram_transfer.dst_addr = (uint64_t) (uintptr_t) dram_ptr1;
	host_to_dram_transfer.size = cfg.dma_size;
	host_to_dram_transfer.dma_dir = DMA_DIR_HOST_TO_DRAM;

	dram_to_host_transfer.queue_index =
			hltests_get_dma_up_qid(fd, STREAM0);
	dram_to_host_transfer.src_addr = (uint64_t) (uintptr_t) dram_ptr2;
	dram_to_host_transfer.dst_addr = host_dst_addr;
	dram_to_host_transfer.size = cfg.dma_size;
	dram_to_host_transfer.dma_dir = DMA_DIR_DRAM_TO_HOST;

	*outcome = hltests_dma_transfer_perf_bidirectional(fd,
				&host_to_dram_transfer, &dram_to_host_transfer);

	hltests_free_host_mem(fd, src_ptr);
	hltests_free_host_mem(fd, dst_ptr);

	hltests_free_device_mem(fd, dram_ptr1);
	hltests_free_device_mem(fd, dram_ptr2);

	END_TEST;
}

/* compiler doesn't recognize function passed as argument as usage */
static __attribute__((unused)) int hltests_perf_teardown(void **state)
{
	struct hltests_state *tests_state = *state;
	double *perf_outcomes;
	int fd;

	if (!tests_state)
		return -EINVAL;

	perf_outcomes = tests_state->perf_outcomes;
	fd = tests_state->fd;

	printf("========\n");
	printf("RESULTS:\n");
	printf("========\n");
	printf("HOST->SRAM             %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_HOST2SRAM]);
	printf("SRAM->HOST             %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_SRAM2HOST]);
	printf("HOST->DRAM             %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_HOST2DRAM]);
	printf("DRAM->HOST             %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_DRAM2HOST]);
	printf("HOST<->SRAM            %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_HOST_SRAM_BIDIR]);
	printf("HOST<->DRAM            %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_HOST_DRAM_BIDIR]);

	printf("SRAM->DRAM   Single DMA %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_SRAM2DRAM_SINGLE_CH]);
	printf("DRAM->SRAM   Single DMA %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_DRAM2SRAM_SINGLE_CH]);
	printf("DRAM->DRAM   Single DMA %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_DRAM2DRAM_SINGLE_CH]);

	printf("SRAM->DRAM   Multi  DMA %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_SRAM2DRAM_MULTI_CH]);
	printf("DRAM->SRAM   Multi  DMA %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_DRAM2SRAM_MULTI_CH]);
	printf("HOST->DRAM   Multi  DMA %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_HOST2DRAM_MULTI_CH]);
	printf("DRAM->HOST   Multi  DMA %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_DRAM2HOST_MULTI_CH]);
	printf("DRAM->DRAM   Multi  DMA %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_DRAM2DRAM_MULTI_CH]);
	printf("SRAM<->DRAM  Multi  DMA %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_SRAM_DRAM_BIDIR_FULL_CH]);

	printf("DRAM->SRAM   5-ch   DMA %7.2lf GB/Sec\n",
			perf_outcomes[RESULTS_DMA_PERF_DRAM2SRAM_5_CH]);

	if (hltests_is_mme_dma_enabled(fd)) {
		printf("DRAM->DRAM   Single MME DMA %7.2lf GB/Sec\n",
				perf_outcomes[RESULTS_DMA_PERF_DRAM2DRAM_SINGLE_CH_MME_DMA]);
		printf("DRAM->DRAM   Multi  MME DMA %7.2lf GB/Sec\n",
				perf_outcomes[RESULTS_DMA_PERF_DRAM2DRAM_MULTI_CH_MME_DMA]);
	}
	return hltests_teardown(state);
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest dma_perf_tests[] = {
	cmocka_unit_test_setup(test_host_sram_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sram_host_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_host_dram_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_host_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_host_sram_bidirectional_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_host_dram_bidirectional_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sram_dram_single_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_sram_single_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_dram_single_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sram_dram_multi_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_sram_multi_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_host_dram_multi_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_host_multi_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_dram_multi_ch_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(
			test_sram_dram_bidirectional_full_multi_ch_perf,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_sram_5ch_perf,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_dram_single_ch_mme_dma_perf,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dram_dram_multi_ch_mme_dma_perf,
				hltests_ensure_device_operational),

};

static const char *const usage[] = {
	"dma_perf [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(dma_perf_tests) /
				sizeof((dma_perf_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE,
			dma_perf_tests, num_tests);

	if (hltests_get_parser_run_disabled_tests())
		printf("Running in debug mode, stress tests enabled!\n");

	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK |
				CAP_ARC_FW_LOAD_PDMA_MASK |
				CAP_ARC_FW_LOAD_EDMA_MASK |
				CAP_ARC_FW_LOAD_MME_MASK |
				CAP_MME_DMA_MASK);
	return hltests_run_group_tests("dma_perf", dma_perf_tests, num_tests,
					hltests_setup, hltests_perf_teardown);
}

#endif /* HLTESTS_LIB_MODE */
