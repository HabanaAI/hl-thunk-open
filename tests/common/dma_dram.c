// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "kvec.h"
#include "ini.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <inttypes.h>

#define DMA_ENTIRE_DRAM_PLDM_TIMEOUT_USEC_PER_MB	4000000
#define DMA_ENTIRE_DRAM_SIM_TIMEOUT_USEC_PER_MB		100000

#define DMA_ENTIRE_DRAM_MONITOR_DMA_VERBOSE_SEC		30		/* 30 seconds */
#define DMA_ENTIRE_DRAM_MONITOR_DMA_NON_VERBOSE_SEC	(20 * 60)	/* 20 minutes */

struct dma_chunk {
	void *input;
	void *output;
	uint64_t input_device_va;
	uint64_t output_device_va;
	uint64_t dram_addr;
};

struct dma_entire_dram_cfg {
	uint64_t dma_size;
	uint64_t zone_size;
};

static int dma_dram_parser(void *user, const char *section, const char *name,
				const char *value)
{
	struct dma_entire_dram_cfg *dma_cfg =
			(struct dma_entire_dram_cfg *) user;

	if (MATCH("dma_entire_dram_test", "dma_size"))
		dma_cfg->dma_size = strtoul(value, NULL, 0);
	else if (MATCH("dma_entire_dram_test", "zone_size"))
		dma_cfg->zone_size = strtoul(value, NULL, 0);
	else
		return 0; /* unknown section/name, error */

	return 1;
}

static void entire_dram_dump_mismatch(struct hltests_state *tests_state, void *host_src,
					uint64_t dram_base, uint64_t offset)
{
	uint32_t *host_p, dram_val;
	uint64_t dram_addr;
	int i;


	host_p = (uint32_t *)((uint64_t)host_src + offset);
	dram_addr = dram_base + offset;
	print_and_flush("Dump mismatch: DRAM base: %#lx, offset: %#lx\n", dram_base, offset);
	for (i = 0; i < 20; i++) {
		dram_val = READ32(dram_addr);
		print_and_flush("    %#lx: host: %#x, hbm: %#x\n", dram_addr, *host_p, dram_val);
		dram_addr += sizeof(uint32_t);
		host_p++;
	}
}

static int prepare_cb_for_dma_engines(int fd, uint64_t dma_size, void *array, void **cb,
		uint32_t *cb_size, struct hltests_cs_chunk *execute_arr,
		uint16_t *qid_down, uint16_t *qid_up)
{
	struct hltests_monitor_and_fence mon_and_fence_info;
	uint32_t dma_idx, j, packets_size, vec_len, qid;
	struct hltests_pkt_info pkt_info;
	uint16_t chunks_sob, chunks_mon;
	struct dma_chunk chunk;
	bool dir_down;

	kvec_t(struct dma_chunk) *arr = array;
	vec_len = kv_size(*arr);

	chunks_sob = hltests_get_first_avail_sob(fd);
	chunks_mon = hltests_get_first_avail_mon(fd);

	/* Clear SOB before we start */
	hltests_clear_sobs(fd, 2);

	/*
	 * CB[0]- will contain the down DMA operations
	 * CB[1]- will contain the up DMA operations
	 * Down DMA engine will transfer chunk of data to device DRAM then will signal
	 * The Up DMA engine to start the Up transfer of this chunk and the other chunks
	 * which already transferred.
	 * CB[0] will look like this: lin_dma -> inc SOB -> lin_dma -> inc sob ....
	 * CB[1] will look like this: mon_fence -> lin_dma -> mon_fence -> lin_dma...
	 * Note the monitor and fence works in greater_equal mode.
	 * since we cannot guarantee the timing of the cmds, where several chunks of down
	 * DMA finished and only then the up dma starts, in such case
	 * the monitor in mode equal won't work.
	 */
	for (dma_idx = 0 ; dma_idx < 2 ; dma_idx++) {
		if (dma_idx) {
			qid = *qid_up = hltests_get_dma_up_qid(fd, STREAM0);
			dir_down = false;
		} else {
			qid = *qid_down = hltests_get_dma_down_qid(fd, STREAM0);
			dir_down = true;
		}

		/*
		 * Note about packets_size: we used vec_len * 4 as it's large enough to hold
		 * all the required packets (lin_dma and sync packets)
		 * every time we need to add more packets to the CB we need to make sure this size
		 * is enough and update accordingly.
		 */
		packets_size = hltests_get_max_pkt_size(fd, MB_TRUE, EB_FALSE, qid) * (vec_len * 4);
		packets_size += hltests_get_cq_patch_size(fd, qid);

		cb_size[dma_idx] = 0;

		cb[dma_idx] = hltests_create_cb(fd, packets_size, EXTERNAL, 0);
		assert_non_null(cb[dma_idx]);

		for (j = 0 ; j < vec_len ; j++) {
			chunk = kv_A(*arr, j);

			if (dma_idx) {
				/* Add monitor and fence */
				memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
				mon_and_fence_info.queue_id = qid;
				mon_and_fence_info.cmdq_fence = false;
				mon_and_fence_info.sob_id = chunks_sob;
				mon_and_fence_info.mon_id = chunks_mon;
				mon_and_fence_info.mon_address = 0;
				mon_and_fence_info.sob_val = j + 1;
				mon_and_fence_info.dec_fence = true;
				mon_and_fence_info.mon_payload = 1;
				mon_and_fence_info.mon_mode = SOB_GREATER_OR_EQUAL;
				cb_size[dma_idx] = hltests_add_monitor_and_fence(fd, cb[dma_idx],
						cb_size[dma_idx], &mon_and_fence_info);
			}

			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.dma.src_addr = dir_down ? chunk.input_device_va :
					(uint64_t) (uintptr_t) chunk.dram_addr;
			pkt_info.dma.dst_addr = dir_down ? (uint64_t) (uintptr_t) chunk.dram_addr :
					chunk.output_device_va;
			pkt_info.dma.size = dma_size;
			pkt_info.qid = qid;
			pkt_info.eb = EB_TRUE;
			pkt_info.mb = MB_TRUE;
			pkt_info.dma.dma_dir =
					dir_down ? DMA_DIR_HOST_TO_DRAM : DMA_DIR_DRAM_TO_HOST;
			cb_size[dma_idx] = hltests_add_dma_pkt(fd, cb[dma_idx], cb_size[dma_idx],
						&pkt_info);

			if (!dma_idx) {
				/* increment the 'chunks' sob */
				memset(&pkt_info, 0, sizeof(pkt_info));
				pkt_info.qid = qid;
				pkt_info.eb = EB_TRUE;
				pkt_info.mb = MB_TRUE;
				pkt_info.write_to_sob.mode = SOB_ADD;
				pkt_info.write_to_sob.sob_id = chunks_sob;
				pkt_info.write_to_sob.value = 1;
				cb_size[dma_idx] = hltests_add_write_to_sob_pkt(fd, cb[dma_idx],
						cb_size[dma_idx], &pkt_info);
			}
		}

		execute_arr[dma_idx].cb_ptr = cb[dma_idx];
		execute_arr[dma_idx].cb_size = cb_size[dma_idx];
		execute_arr[dma_idx].queue_index = qid;
	}

	return 0;
}

VOID dma_entire_dram_random(void **state, uint64_t zone_size, uint64_t dma_size)
{
	uint64_t dram_size, dram_addr, dram_addr_end, device_va[2], seq, copy_size_mb, timeout_us,
		*page_arr = NULL;
	int i, rc, verbose, fd, device_addr_arr_size, actual_arr_size = 0, poll_interval_sec = 0;
	bool debugfs_opened, monitor_dma, is_pldm, dbg_h9_mismatch, mix_pages_alloc;
	const char *config_filename = hltests_get_config_filename();
	uint32_t offset, cb_size[2], vec_len, max_zone_offset;
	struct hltests_state *tests_state = *state;
	uint16_t dma_down_qid = 0, dma_up_qid = 0;
	void *buf[2], *cb[2] = {NULL}, *dram_ptr;
	struct hltests_cs_chunk execute_arr[2];
	struct monitor_dma_test mon_dma[2];
	struct hlthunk_hw_ip_info *hw_ip;
	uint64_t *device_addr_arr = NULL;
	struct dma_entire_dram_cfg cfg;
	kvec_t(struct dma_chunk) array;
	struct timespec begin, end;
	struct dma_chunk chunk;
	uint8_t page_arr_size;

	hw_ip = &tests_state->hw_ip;
	fd = tests_state->fd;

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	debugfs_opened = can_open_debugfs(false);

	/* As of 02/06/2021 entire DRAM test on GOYA-16GB cards
	 * will fail, due to [SW-40881], *possible hw issue.
	 * For now skip it to prevent ci failures, unless explicitly
	 * enabled.
	 * GOYA-16GB ram will actually be reported as 15.5GB, due to
	 * the lower DRAM being reserved, hence the formula.
	 */
	if (hw_ip->dram_size >= (SZ_16G - SZ_512M) && hltests_is_goya(fd) &&
					!hltests_get_parser_run_disabled_tests())
		skip();

	is_pldm = hltests_is_pldm(fd);
	verbose = hltests_get_verbose_enabled();
	mix_pages_alloc = hltests_is_gaudi3(fd);
	monitor_dma = is_pldm;
	if (monitor_dma)
		poll_interval_sec = verbose ? DMA_ENTIRE_DRAM_MONITOR_DMA_VERBOSE_SEC :
						DMA_ENTIRE_DRAM_MONITOR_DMA_NON_VERBOSE_SEC;

	/*
	 * this flag is added to be able to debug the failure of this test
	 * It fix the randomization so that constant addresses will be used
	 * and trigger will potentially can be taken for further investigation.
	 * this will be removed once this investigation path will be over
	 * all addresses matching this test can be found at:
	 * https://vlsi-pldm-web.habana-labs.com/logs/pldm_tools_IDC3_20220719_000120.html
	 */
	dbg_h9_mismatch = is_pldm && verbose && hltests_is_gaudi3(fd);

	if (dbg_h9_mismatch)
		hltests_set_rand_seed(0x62D5E0EA);

	cfg.dma_size = dma_size;
	cfg.zone_size = zone_size;

	if (config_filename) {
		if (ini_parse(config_filename, dma_dram_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);

		printf("Configuration loaded from %s:\n", config_filename);
		printf("dma_size = 0x%lx, zone_size = 0x%lx\n",
				cfg.dma_size, cfg.zone_size);
	}

	assert_true(IS_POWER_OF_TWO(cfg.zone_size));

	kv_init(array);

	/* check alignment to 8B */
	assert_true(IS_8B_ALIGNED(cfg.dma_size));
	assert_true(IS_8B_ALIGNED(cfg.zone_size));

	assert_true(2 * cfg.dma_size <= cfg.zone_size);

	dram_size = hltests_get_total_avail_device_mem(fd);

	/* if "default allocation page size" is a power of 2 align dram_size to zone size */
	if (IS_POWER_OF_TWO(hw_ip->device_mem_alloc_default_page_size))
		dram_size = rounddown(dram_size, cfg.zone_size);

	assert_true(cfg.zone_size < dram_size);

	/*
	 * The mixed pages are relevant to asics that support several page sizes.
	 * Currently only Gaudi3 supports several page sizes (32M and 1G).
	 */
	if (mix_pages_alloc) {
		/* read supported page sizes */
		hltests_build_memalloc_page_size_array(fd, &page_arr, &page_arr_size);
		assert_int_not_equal(page_arr_size, 0);
		assert_non_null(page_arr);

		/* avoid complicated requirement, dram_size must be aligned to smallest page */
		assert_int_equal((dram_size % page_arr[0]), 0);

		device_addr_arr_size = dram_size / page_arr[0];
		device_addr_arr = hlthunk_malloc(device_addr_arr_size * sizeof(uint64_t));
		assert_non_null(device_addr_arr);

		hlthunk_free(page_arr);
		rc = hltests_allocate_device_mem_mix_page_size(fd, dram_size,
					device_addr_arr, device_addr_arr_size, &actual_arr_size);

		assert_int_equal(rc, 0);
		assert_int_not_equal(actual_arr_size, 0);

		dram_ptr = (void *)(device_addr_arr[0]);
	} else {
		dram_ptr = hltests_allocate_device_mem(fd, dram_size, 0, CONTIGUOUS);
	}

	assert_non_null(dram_ptr);
	dram_addr = (uint64_t) (uintptr_t) dram_ptr;
	dram_addr_end = dram_addr + dram_size;

	/* round addresses to zone size */
	dram_addr = ALIGN_UP(dram_addr, cfg.zone_size);
	dram_addr_end = ALIGN_DOWN(dram_addr_end, cfg.zone_size);

	assert_true(dram_addr_end >= (dram_addr + cfg.zone_size));

	if (verbose) {
		print_and_flush("dma_size: %" PRIu64 "KB\nzone_size: %" PRIu64 "MB\n"
			"dram_size: %" PRIu64 "MB\ndram_addr: 0x%" PRIX64 "\n"
			"seed: 0x%X\n", cfg.dma_size / SZ_1K,
			cfg.zone_size / SZ_1M, dram_size / SZ_1M, dram_addr,
			hltests_get_cur_seed());
		clock_gettime(CLOCK_MONOTONIC_RAW, &begin);
	}

	/*
	 * we limit offset within the zone to make sure DMA does not overflows
	 * outside zone's boundaries
	 */
	max_zone_offset = cfg.zone_size - cfg.dma_size;

	i = 0;
	while (dram_addr < (dram_addr_end - cfg.dma_size)) {
		buf[0] = hltests_allocate_host_mem(fd, cfg.dma_size, NOT_HUGE_MAP);
		assert_non_null(buf[0]);
		if (dbg_h9_mismatch)
			hltests_fill_addr_chunk(buf[0], cfg.dma_size, dram_addr, i);
		else
			hltests_fill_rand_values(buf[0], cfg.dma_size);
		device_va[0] = hltests_get_device_va_for_host_ptr(fd, buf[0]);

		buf[1] = hltests_allocate_host_mem(fd, cfg.dma_size, NOT_HUGE_MAP);
		assert_non_null(buf[1]);
		memset(buf[1], 0, cfg.dma_size);
		device_va[1] = hltests_get_device_va_for_host_ptr(fd, buf[1]);

		/* need an 8B aligned offset inside a zone */
		offset = ALIGN_DOWN(hltests_rand_u32() % max_zone_offset, 8);

		chunk.input = buf[0];
		chunk.output = buf[1];
		chunk.input_device_va = device_va[0];
		chunk.output_device_va = device_va[1];
		chunk.dram_addr = dram_addr + offset;

		if (verbose)
			printf("chunk[%d].dram_addr: 0x%" PRIX64 "\n"
				"chunk[%d].input_device_va: 0x%" PRIX64 "\n"
				"chunk[%d].output_device_va: 0x%" PRIX64 "\n"
				"chunk[%d].input: %p\nchunk[%d].output: %p\n",
				i, chunk.dram_addr, i, chunk.input_device_va,
				i, chunk.output_device_va, i, chunk.input,
				i, chunk.output);
		i++;

		kv_push(struct dma_chunk, array, chunk);

		dram_addr += cfg.zone_size;
	}

	if (verbose) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		print_and_flush("mem allocations took %u seconds.\n"
			"dma_size: %" PRIu64 "KB\nzone_size: %" PRIu64 "MB\n"
			"dram_size: %" PRIu64 "MB\ndram_addr: 0x%" PRIX64 "\n"
			"seed: 0x%X\n",
			(unsigned int) get_timediff_sec(&begin, &end),
			cfg.dma_size / SZ_1K,
			cfg.zone_size / SZ_1M, dram_size / SZ_1M, dram_addr,
			hltests_get_cur_seed());
	}

	vec_len = kv_size(array);

	/* build the DOWN/UP DMA CBs */
	prepare_cb_for_dma_engines(fd, dma_size, &array, cb, cb_size, execute_arr,
						&dma_down_qid, &dma_up_qid);

	if (verbose) {
		print_with_ts_and_flush("DMA down/up...\n");
		clock_gettime(CLOCK_MONOTONIC_RAW, &begin);
	}

	if (is_pldm || hltests_is_simulator(fd)) {
		copy_size_mb = (kv_size(array) * cfg.dma_size) / SZ_1M;
		if (is_pldm)
			timeout_us = copy_size_mb * DMA_ENTIRE_DRAM_PLDM_TIMEOUT_USEC_PER_MB;
		else
			timeout_us = copy_size_mb * DMA_ENTIRE_DRAM_SIM_TIMEOUT_USEC_PER_MB;

		if (verbose)
			print_and_flush("timeout: %lu seconds.\n", timeout_us / 1000000);

		rc = hltests_submit_cs_timeout(fd, NULL, 0, execute_arr, 2, 0,
						timeout_us / 1000000, &seq);
		assert_int_equal(rc, 0);

		if (monitor_dma) {
			hltests_monitor_dma_start(&mon_dma[0], fd, dma_down_qid, poll_interval_sec);
			hltests_monitor_dma_start(&mon_dma[1], fd, dma_up_qid, poll_interval_sec);
		}

		rc = hltests_wait_for_cs(fd, seq, timeout_us);
		assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

		if (monitor_dma) {
			hltests_monitor_dma_stop(&mon_dma[0]);
			hltests_monitor_dma_stop(&mon_dma[1]);
		}
	} else {
		rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2, 0, &seq);
		assert_int_equal(rc, 0);
		rc = hltests_wait_for_cs_until_not_busy(fd, seq);
		assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);
	}

	if (verbose) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);

		print_with_ts_and_flush("DMA took %u sec.\n",
			(unsigned int) get_timediff_sec(&begin, &end));
	}

	/* compare host memories */
	if (verbose) {
		print_and_flush("comparing...\n");
		clock_gettime(CLOCK_MONOTONIC_RAW, &begin);
	}

	for (i = 0 ; i < vec_len ; i++) {
		int ret;
		uint64_t mismatch_off;

		chunk = kv_A(array, i);
		ret = hltests_mem_compare_offset(chunk.input, chunk.output, cfg.dma_size,
							&mismatch_off);
		rc |= ret;
		if (ret && verbose) {
			print_and_flush("compare failed in chunk %d/%u.\n"
				"chunk.dram_addr: 0x%" PRIX64 "\n"
				"chunk.input_device_va: 0x%" PRIX64 "\n"
				"chunk.output_device_va: 0x%" PRIX64 "\n"
				"chunk.input: %p\nchunk.output: %p\n", i, vec_len-1,
				chunk.dram_addr, chunk.input_device_va,
				chunk.output_device_va, chunk.input, chunk.output);

			if (debugfs_opened)
				entire_dram_dump_mismatch(tests_state, chunk.input, chunk.dram_addr,
								mismatch_off);
		}

		if (!dbg_h9_mismatch)
			assert_int_equal(rc, 0);
	}

	/*
	 * TODO: remove once when dbg_h9_mismatch is resolved.
	 * a mismatch occurs dump all chunks to get a better view on the issue.
	 */
	if (dbg_h9_mismatch)
		assert_int_equal(rc, 0);

	/* cleanup */
	if (verbose) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		print_and_flush("comparison took %u seconds.\n",
			(unsigned int) get_timediff_sec(&begin, &end));
		clock_gettime(CLOCK_MONOTONIC_RAW, &begin);
	}

	for (i = 0 ; i < 2 ; i++) {
		rc = hltests_destroy_cb(fd, cb[i]);
		assert_int_equal(rc, 0);
	}

	for (i = 0 ; i < vec_len ; i++) {
		chunk = kv_A(array, i);
		rc = hltests_free_host_mem(fd, chunk.input);
		assert_int_equal(rc, 0);

		rc = hltests_free_host_mem(fd, chunk.output);
		assert_int_equal(rc, 0);
	}

	if (verbose) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		print_and_flush("cleanup took %u seconds.\n",
				(unsigned int) get_timediff_sec(&begin, &end));
	}

	if (mix_pages_alloc) {
		rc = hltests_free_device_mem_mix_page_size(fd, device_addr_arr, actual_arr_size);
		assert_int_equal(rc, 0);

		hlthunk_free(device_addr_arr);
	} else {
		rc = hltests_free_device_mem(fd, dram_ptr);
		assert_int_equal(rc, 0);
	}

	kv_destroy(array);

	END_TEST;
}

VOID test_dma_entire_dram_random_256KB(void **state)
{
	if (!hltests_get_parser_run_disabled_tests())
		skip();

	END_TEST_FUNC(dma_entire_dram_random(state, SZ_16M, SZ_256K));
}

VOID test_dma_entire_dram_random_512KB(void **state)
{
	if (!hltests_get_parser_run_disabled_tests())
		skip();

	END_TEST_FUNC(dma_entire_dram_random(state, SZ_16M, SZ_512K));
}

VOID test_dma_entire_dram_random_1MB(void **state)
{
	if (!hltests_get_parser_run_disabled_tests())
		skip();

	END_TEST_FUNC(dma_entire_dram_random(state, SZ_16M, SZ_1M));
}

VOID test_dma_entire_dram_random_2MB(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;

	if (hltests_is_pldm(fd) && !hltests_get_parser_run_disabled_tests())
		skip();

	END_TEST_FUNC(dma_entire_dram_random(state, SZ_16M, SZ_2M));
}

DMA_TEST_INC_DRAM(test_dma_dram_size_1KB, state, 1 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_2KB, state, 2 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_3KB, state, 3 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_4KB, state, 4 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_5KB, state, 5 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_6KB, state, 6 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_7KB, state, 7 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_8KB, state, 8 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_9KB, state, 9 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_10KB, state, 10 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_11KB, state, 11 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_12KB, state, 12 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_13KB, state, 13 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_14KB, state, 14 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_15KB, state, 15 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_16KB, state, 16 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_20KB, state, 20 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_24KB, state, 24 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_28KB, state, 28 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_32KB, state, 32 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_36KB, state, 36 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_40KB, state, 40 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_44KB, state, 44 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_48KB, state, 48 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_52KB, state, 52 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_56KB, state, 56 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_60KB, state, 60 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_64KB, state, 64 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_96KB, state, 96 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_128KB, state, 128 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_160KB, state, 160 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_192KB, state, 192 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_224KB, state, 224 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_256KB, state, 256 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_288KB, state, 288 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_320KB, state, 320 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_352KB, state, 352 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_384KB, state, 384 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_416KB, state, 416 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_448KB, state, 448 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_480KB, state, 480 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_512KB, state, 512 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_640KB, state, 640 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_768KB, state, 768 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_896KB, state, 896 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_1024KB, state, 1024 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_1152KB, state, 1152 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_1280KB, state, 1280 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_1408KB, state, 1408 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_1536KB, state, 1536 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_1664KB, state, 1664 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_1792KB, state, 1792 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_1920KB, state, 1920 * SZ_1K)
DMA_TEST_INC_DRAM(test_dma_dram_size_2MB, state, 2 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_3MB, state, 3 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_4MB, state, 4 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_5MB, state, 5 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_6MB, state, 6 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_7MB, state, 7 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_8MB, state, 8 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_9MB, state, 9 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_10MB, state, 10 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_11MB, state, 11 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_12MB, state, 12 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_13MB, state, 13 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_14MB, state, 14 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_15MB, state, 15 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_16MB, state, 16 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_20MB, state, 20 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_24MB, state, 24 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_28MB, state, 28 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_32MB, state, 32 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_36MB, state, 36 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_40MB, state, 40 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_44MB, state, 44 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_48MB, state, 48 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_64MB, state, 64 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_128MB, state, 128 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_192MB, state, 192 * SZ_1M)
DMA_TEST_INC_DRAM(test_dma_dram_size_256MB, state, 256 * SZ_1M)
DMA_TEST_INC_DRAM_FRAG(test_dma_dram_frag_size_64MB, state, 64 * SZ_1M)
DMA_TEST_INC_DRAM_FRAG(test_dma_dram_frag_size_128MB, state, 128 * SZ_1M)
DMA_TEST_INC_DRAM_FRAG(test_dma_dram_frag_size_192MB, state, 192 * SZ_1M)
DMA_TEST_INC_DRAM_FRAG(test_dma_dram_frag_size_256MB, state, 256 * SZ_1M)
DMA_TEST_INC_DRAM_FRAG(test_dma_dram_frag_size_512MB, state, 512 * SZ_1M)
DMA_TEST_INC_DRAM_FRAG(test_dma_dram_frag_size_1GB, state, 1024 * SZ_1M)
DMA_TEST_INC_DRAM_HIGH(test_dma_dram_high_size_64MB, state, 64 * SZ_1M)
DMA_TEST_INC_DRAM_HIGH(test_dma_dram_high_size_128MB, state, 128 * SZ_1M)
DMA_TEST_INC_DRAM_HIGH(test_dma_dram_high_size_192MB, state, 192 * SZ_1M)
DMA_TEST_INC_DRAM_HIGH(test_dma_dram_high_size_256MB, state, 256 * SZ_1M)
DMA_TEST_INC_DRAM_HIGH(test_dma_dram_high_size_512MB, state, 512 * SZ_1M)
DMA_TEST_INC_DRAM_HIGH(test_dma_dram_high_size_1GB, state, SZ_1G)

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest dma_dram_tests[] = {
	cmocka_unit_test_setup(test_dma_entire_dram_random_256KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_entire_dram_random_512KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_entire_dram_random_1MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_entire_dram_random_2MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_2KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_3KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_4KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_5KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_6KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_7KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_8KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_9KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_10KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_11KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_12KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_13KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_14KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_15KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_16KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_20KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_24KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_28KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_32KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_36KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_40KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_44KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_48KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_52KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_56KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_60KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_64KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_96KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_128KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_160KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_192KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_224KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_256KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_288KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_320KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_352KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_384KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_416KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_448KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_480KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_512KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_640KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_768KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_896KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1024KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1152KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1280KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1408KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1536KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1664KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1792KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_1920KB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_2MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_3MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_4MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_5MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_6MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_7MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_8MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_9MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_10MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_11MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_12MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_13MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_14MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_15MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_16MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_20MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_24MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_28MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_32MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_36MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_40MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_44MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_48MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_64MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_128MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_192MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_size_256MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_frag_size_64MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_frag_size_128MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_frag_size_192MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_frag_size_256MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_frag_size_512MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_frag_size_1GB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_high_size_64MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_high_size_128MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_high_size_192MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_high_size_256MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_high_size_512MB,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_dram_high_size_1GB,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"dma_dram [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(dma_dram_tests) / sizeof((dma_dram_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE,
			dma_dram_tests, num_tests);
	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK |
				CAP_ARC_FW_LOAD_PDMA_MASK);
	return hltests_run_group_tests("dma_dram", dma_dram_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
