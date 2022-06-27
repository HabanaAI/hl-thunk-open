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
#define DMA_ENTIRE_DRAM_SIM_TIMEOUT_USEC_PER_MB		10000

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

VOID dma_entire_dram_random(void **state, uint64_t zone_size, uint64_t dma_size)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t offset, cb_size[2], vec_len, packets_size, max_zone_offset;
	uint64_t dram_size, dram_addr, dram_addr_end, device_va[2], seq;
	const char *config_filename = hltests_get_config_filename();
	bool monitor_dma, is_pldm, split_cs = false;
	int i, rc, verbose, fd = tests_state->fd;
	void *buf[2], *cb[2] = {NULL}, *dram_ptr;
	struct hltests_cs_chunk execute_arr[2];
	uint64_t copy_size_mb, timeout_us;
	uint16_t dma_down_qid, dma_up_qid;
	struct hltests_pkt_info pkt_info;
	struct monitor_dma_test mon_dma;
	struct hlthunk_hw_ip_info hw_ip;
	struct dma_entire_dram_cfg cfg;
	kvec_t(struct dma_chunk) array;
	struct timespec begin, end;
	struct dma_chunk chunk;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	/* As of 02/06/2021 entire DRAM test on GOYA-16GB cards
	 * will fail, due to [SW-40881], *possible hw issue.
	 * For now skip it to prevent ci failures, unless explicitly
	 * enabled.
	 * GOYA-16GB ram will actually be reported as 15.5GB, due to
	 * the lower DRAM being reserved, hence the formula.
	 */
	if (hw_ip.dram_size >= (SZ_16G - SZ_512M) && hltests_is_goya(fd) &&
					!hltests_get_parser_run_disabled_tests()) {
		printf("Test is disabled on this device due to [SW-40881].\n");
		printf("To explicitly enable it, run with -d flag.\n");
		skip();
	}

	is_pldm = hltests_is_pldm(fd);
	verbose = hltests_get_verbose_enabled();
	monitor_dma = is_pldm && verbose;

	/* if mmu is disabled split to 2 cb's */
	if (!tests_state->mmu)
		split_cs = true;

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

	/* if dram page size is not power of 2 align dram_size to dram_page_size
	 * else align it to zone_size
	 */
	if (hw_ip.device_mem_alloc_default_page_size &&
			!IS_POWER_OF_TWO(hw_ip.device_mem_alloc_default_page_size))
		dram_size = rounddown(dram_size, hw_ip.device_mem_alloc_default_page_size);
	else
		dram_size = rounddown(dram_size, cfg.zone_size);

	assert_true(cfg.zone_size < dram_size);

	dram_ptr = hltests_allocate_device_mem(fd, dram_size, 0, CONTIGUOUS);
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

	dma_down_qid = hltests_get_dma_down_qid(fd, STREAM0);
	dma_up_qid = hltests_get_dma_up_qid(fd, STREAM0);

	vec_len = kv_size(array);

	if (split_cs)
		vec_len = vec_len >> 1;

	packets_size = hltests_get_max_pkt_size(fd, MB_TRUE, EB_FALSE, dma_down_qid) * vec_len;
	packets_size += hltests_get_cq_patch_size(fd, dma_down_qid);

	/* DMA down */
	cb_size[0] = 0;
	cb[0] = hltests_create_cb(fd, packets_size, EXTERNAL, 0);
	assert_non_null(cb[0]);

	if (split_cs) {
		cb_size[1] = 0;
		cb[1] = hltests_create_cb(fd, packets_size, EXTERNAL, 0);
		assert_non_null(cb[1]);
	}

	for (i = 0 ; i < vec_len ; i++) {
		chunk = kv_A(array, i);
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = dma_down_qid;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = chunk.input_device_va;
		pkt_info.dma.dst_addr = (uint64_t) (uintptr_t) chunk.dram_addr;
		pkt_info.dma.size = cfg.dma_size;
		pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_DRAM;
		cb_size[0] = hltests_add_dma_pkt(fd, cb[0], cb_size[0], &pkt_info);
	}

	for (i = vec_len ; (i < vec_len * 2) && split_cs ; i++) {
		chunk = kv_A(array, i);
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = dma_down_qid;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = chunk.input_device_va;
		pkt_info.dma.dst_addr = (uint64_t) (uintptr_t) chunk.dram_addr;
		pkt_info.dma.size = cfg.dma_size;
		pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_DRAM;
		cb_size[1] = hltests_add_dma_pkt(fd, cb[1], cb_size[1], &pkt_info);
	}

	execute_arr[0].cb_ptr = cb[0];
	execute_arr[0].cb_size = cb_size[0];
	execute_arr[0].queue_index = dma_down_qid;

	if (split_cs) {
		execute_arr[1].cb_ptr = cb[1];
		execute_arr[1].cb_size = cb_size[1];
		execute_arr[1].queue_index = dma_down_qid;
	}

	if (monitor_dma) {
		mon_dma.fd = fd;
		mon_dma.poll_interval_sec = 30;
	}

	if (verbose) {
		print_with_ts_and_flush("DMA down...\n");
		clock_gettime(CLOCK_MONOTONIC_RAW, &begin);
	}

	if (is_pldm || hltests_is_simulator(fd)) {
		copy_size_mb = (kv_size(array) * cfg.dma_size) / 1024 / 1024;
		if (is_pldm)
			timeout_us = copy_size_mb * DMA_ENTIRE_DRAM_PLDM_TIMEOUT_USEC_PER_MB;
		else
			timeout_us = copy_size_mb * DMA_ENTIRE_DRAM_SIM_TIMEOUT_USEC_PER_MB;

		if (verbose)
			print_and_flush("timeout: %lu seconds.\n", timeout_us / 1000000);

		rc = hltests_submit_cs_timeout(fd, NULL, 0, execute_arr,
						split_cs ? 2 : 1, 0, timeout_us / 1000000, &seq);
		assert_int_equal(rc, 0);

		if (monitor_dma) {
			mon_dma.qid = dma_down_qid;
			hltests_monitor_dma_start(&mon_dma);
		}

		rc = hltests_wait_for_cs(fd, seq, timeout_us);
	} else {
		rc = hltests_submit_cs(fd, NULL, 0, execute_arr, split_cs ? 2 : 1, 0, &seq);
		assert_int_equal(rc, 0);
		rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	}

	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	if (monitor_dma)
		hltests_monitor_dma_stop(&mon_dma);

	if (verbose) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		print_with_ts_and_flush("DMA down took %u seconds.\n",
			(unsigned int) get_timediff_sec(&begin, &end));
	}

	rc = hltests_destroy_cb(fd, cb[0]);
	assert_int_equal(rc, 0);

	if (split_cs) {
		rc = hltests_destroy_cb(fd, cb[1]);
		assert_int_equal(rc, 0);
	}

	/* DMA up */
	cb_size[0] = 0;
	cb[0] = hltests_create_cb(fd, packets_size, EXTERNAL, 0);
	assert_non_null(cb[0]);

	if (split_cs) {
		cb_size[1] = 0;
		cb[1] = hltests_create_cb(fd, packets_size, EXTERNAL, 0);
		assert_non_null(cb[1]);
	}

	for (i = 0 ; i < vec_len ; i++) {
		chunk = kv_A(array, i);
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = dma_up_qid;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = (uint64_t) (uintptr_t) chunk.dram_addr;
		pkt_info.dma.dst_addr = chunk.output_device_va;
		pkt_info.dma.size = cfg.dma_size;
		pkt_info.dma.dma_dir = DMA_DIR_DRAM_TO_HOST;
		cb_size[0] = hltests_add_dma_pkt(fd, cb[0], cb_size[0], &pkt_info);
	}

	for (i = vec_len ; (i < vec_len * 2) && split_cs ; i++) {
		chunk = kv_A(array, i);
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = dma_up_qid;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.dma.src_addr = (uint64_t) (uintptr_t) chunk.dram_addr;
		pkt_info.dma.dst_addr = chunk.output_device_va;
		pkt_info.dma.size = cfg.dma_size;
		pkt_info.dma.dma_dir = DMA_DIR_DRAM_TO_HOST;
		cb_size[1] = hltests_add_dma_pkt(fd, cb[1], cb_size[1], &pkt_info);
	}

	execute_arr[0].cb_ptr = cb[0];
	execute_arr[0].cb_size = cb_size[0];
	execute_arr[0].queue_index = dma_up_qid;

	if (split_cs) {
		execute_arr[1].cb_ptr = cb[1];
		execute_arr[1].cb_size = cb_size[1];
		execute_arr[1].queue_index = dma_up_qid;
	}

	if (verbose) {
		print_with_ts_and_flush("DMA up...\n");
		clock_gettime(CLOCK_MONOTONIC_RAW, &begin);
	}

	if (is_pldm) {
		copy_size_mb = (kv_size(array) * cfg.dma_size) / 1024 / 1024;
		timeout_us = copy_size_mb * DMA_ENTIRE_DRAM_PLDM_TIMEOUT_USEC_PER_MB;

		if (verbose)
			print_and_flush("timeout: %lu seconds.\n", timeout_us / 1000000);

		rc = hltests_submit_cs_timeout(fd, NULL, 0, execute_arr,
					split_cs ? 2 : 1, 0, timeout_us / 1000000, &seq);
		assert_int_equal(rc, 0);

		if (monitor_dma) {
			mon_dma.qid = dma_up_qid;
			hltests_monitor_dma_start(&mon_dma);
		}
		rc = hltests_wait_for_cs(fd, seq, timeout_us);
	} else {
		rc = hltests_submit_cs(fd, NULL, 0, execute_arr,
					split_cs ? 2 : 1, 0, &seq);
		assert_int_equal(rc, 0);
		rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	}

	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	if (monitor_dma)
		hltests_monitor_dma_stop(&mon_dma);

	if (verbose) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		print_with_ts_and_flush("DMA up took %u seconds.\n",
			(unsigned int) get_timediff_sec(&begin, &end));
	}

	rc = hltests_destroy_cb(fd, cb[0]);
	assert_int_equal(rc, 0);

	if (split_cs) {
		rc = hltests_destroy_cb(fd, cb[1]);
		assert_int_equal(rc, 0);
	}

	if (split_cs)
		vec_len = vec_len * 2;

	/* compare host memories */
	if (verbose) {
		print_and_flush("comparing...\n");
		clock_gettime(CLOCK_MONOTONIC_RAW, &begin);
	}

	for (i = 0 ; i < vec_len ; i++) {
		chunk = kv_A(array, i);
		rc = hltests_mem_compare(chunk.input, chunk.output,
						cfg.dma_size);
		if (rc && verbose)
			print_and_flush("compare failed in chunk %d/%u.\n"
				"chunk.dram_addr: 0x%" PRIX64 "\n"
				"chunk.input_device_va: 0x%" PRIX64 "\n"
				"chunk.output_device_va: 0x%" PRIX64 "\n"
				"chunk.input: %p\nchunk.output: %p\n", i, vec_len-1,
				chunk.dram_addr, chunk.input_device_va,
				chunk.output_device_va, chunk.input, chunk.output);

		assert_int_equal(rc, 0);
	}

	/* cleanup */
	if (verbose) {
		clock_gettime(CLOCK_MONOTONIC_RAW, &end);
		print_and_flush("comparison took %u seconds.\n",
			(unsigned int) get_timediff_sec(&begin, &end));
		clock_gettime(CLOCK_MONOTONIC_RAW, &begin);
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

	rc = hltests_free_device_mem(fd, dram_ptr);
	assert_int_equal(rc, 0);

	kv_destroy(array);

	END_TEST;
}

VOID test_dma_entire_dram_random_256KB(void **state)
{
	if (!hltests_get_parser_run_disabled_tests()) {
		printf("This test needs to be run with -d flag\n");
		skip();
	}

	END_TEST_FUNC(dma_entire_dram_random(state,
					16 * 1024 * 1024, 256 * 1024));
}

VOID test_dma_entire_dram_random_512KB(void **state)
{
	if (!hltests_get_parser_run_disabled_tests()) {
		printf("This test needs to be run with -d flag\n");
		skip();
	}

	END_TEST_FUNC(dma_entire_dram_random(state,
					16 * 1024 * 1024, 512 * 1024));
}

VOID test_dma_entire_dram_random_1MB(void **state)
{
	if (!hltests_get_parser_run_disabled_tests()) {
		printf("This test needs to be run with -d flag\n");
		skip();
	}

	END_TEST_FUNC(dma_entire_dram_random(state,
					16 * 1024 * 1024, 1 * 1024 * 1024));
}

VOID test_dma_entire_dram_random_2MB(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;

	if (hltests_is_pldm(fd) && !hltests_get_parser_run_disabled_tests()) {
		printf("This test needs to be run with -d flag on pldm\n");
		skip();
	}

	/* TODO: enable once SW-92827 is resolved */
	if (!hltests_is_legacy_mode_enabled(fd)) {
		printf("This test is temporarily disabled in non-legacy mode\n");
		skip();
	}

	END_TEST_FUNC(dma_entire_dram_random(state,
					16 * 1024 * 1024, 2 * 1024 * 1024));
}

DMA_TEST_INC_DRAM(test_dma_dram_size_1KB, state, 1 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_2KB, state, 2 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_3KB, state, 3 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_4KB, state, 4 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_5KB, state, 5 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_6KB, state, 6 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_7KB, state, 7 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_8KB, state, 8 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_9KB, state, 9 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_10KB, state, 10 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_11KB, state, 11 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_12KB, state, 12 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_13KB, state, 13 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_14KB, state, 14 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_15KB, state, 15 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_16KB, state, 16 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_20KB, state, 20 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_24KB, state, 24 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_28KB, state, 28 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_32KB, state, 32 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_36KB, state, 36 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_40KB, state, 40 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_44KB, state, 44 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_48KB, state, 48 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_52KB, state, 52 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_56KB, state, 56 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_60KB, state, 60 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_64KB, state, 64 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_96KB, state, 96 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_128KB, state, 128 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_160KB, state, 160 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_192KB, state, 192 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_224KB, state, 224 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_256KB, state, 256 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_288KB, state, 288 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_320KB, state, 320 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_352KB, state, 352 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_384KB, state, 384 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_416KB, state, 416 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_448KB, state, 448 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_480KB, state, 480 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_512KB, state, 512 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_640KB, state, 640 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_768KB, state, 768 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_896KB, state, 896 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_1024KB, state, 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_1152KB, state, 1152 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_1280KB, state, 1280 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_1408KB, state, 1408 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_1536KB, state, 1536 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_1664KB, state, 1664 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_1792KB, state, 1792 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_1920KB, state, 1920 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_2MB, state, 2 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_3MB, state, 3 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_4MB, state, 4 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_5MB, state, 5 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_6MB, state, 6 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_7MB, state, 7 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_8MB, state, 8 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_9MB, state, 9 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_10MB, state, 10 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_11MB, state, 11 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_12MB, state, 12 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_13MB, state, 13 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_14MB, state, 14 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_15MB, state, 15 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_16MB, state, 16 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_20MB, state, 20 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_24MB, state, 24 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_28MB, state, 28 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_32MB, state, 32 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_36MB, state, 36 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_40MB, state, 40 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_44MB, state, 44 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_48MB, state, 48 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_64MB, state, 64 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_128MB, state, 128 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_192MB, state, 192 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM(test_dma_dram_size_256MB, state, 256 * 1024 * 1024, 0)
DMA_TEST_INC_DRAM_FRAG(test_dma_dram_frag_size_64MB, state, 64 * 1024 * 1024)
DMA_TEST_INC_DRAM_FRAG(test_dma_dram_frag_size_128MB, state, 128 * 1024 * 1024)
DMA_TEST_INC_DRAM_FRAG(test_dma_dram_frag_size_192MB, state, 192 * 1024 * 1024)
DMA_TEST_INC_DRAM_FRAG(test_dma_dram_frag_size_256MB, state, 256 * 1024 * 1024)
DMA_TEST_INC_DRAM_FRAG(test_dma_dram_frag_size_512MB, state, 512 * 1024 * 1024)
DMA_TEST_INC_DRAM_FRAG(test_dma_dram_frag_size_1GB, state, 1024 * 1024 * 1024)
DMA_TEST_INC_DRAM_HIGH(test_dma_dram_high_size_64MB, state, 64 * 1024 * 1024)
DMA_TEST_INC_DRAM_HIGH(test_dma_dram_high_size_128MB, state, 128 * 1024 * 1024)
DMA_TEST_INC_DRAM_HIGH(test_dma_dram_high_size_192MB, state, 192 * 1024 * 1024)
DMA_TEST_INC_DRAM_HIGH(test_dma_dram_high_size_256MB, state, 256 * 1024 * 1024)
DMA_TEST_INC_DRAM_HIGH(test_dma_dram_high_size_512MB, state, 512 * 1024 * 1024)
DMA_TEST_INC_DRAM_HIGH(test_dma_dram_high_size_1GB, state, 1024 * 1024 * 1024)

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

	return hltests_run_group_tests("dma_dram", dma_dram_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
