// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#include "hlthunk_tests.h"
#include "ini.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

void test_tdr_deadlock(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[1];
	struct hltests_pkt_info pkt_info;
	void *ptr;
	uint64_t seq = 0;
	uint32_t page_size = sysconf(_SC_PAGESIZE), offset = 0;
	int rc, fd = tests_state->fd;

	assert_in_range(page_size, PAGE_SIZE_4KB, PAGE_SIZE_64KB);

	ptr = hltests_create_cb(fd, page_size, EXTERNAL, 0);
	assert_non_null(ptr);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.fence.dec_val = 1;
	pkt_info.fence.gate_val = 1;
	pkt_info.fence.fence_id = 0;
	offset = hltests_add_fence_pkt(fd, ptr, offset, &pkt_info);

	hltests_submit_and_wait_cs(fd, ptr, offset,
				hltests_get_dma_down_qid(fd, DCORE0, STREAM0),
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_TIMEDOUT);

	/* no need to destroy the CB because the device is in reset */
}

void test_endless_memory_ioctl(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t page_size = sysconf(_SC_PAGESIZE);
	void *src_ptr;
	int rc, fd = tests_state->fd;

	assert_in_range(page_size, PAGE_SIZE_4KB, PAGE_SIZE_64KB);

	/* Don't check return value because we don't want the test to finish
	 * when the driver returns error
	 */

	while (1) {
		src_ptr = hltests_allocate_host_mem(fd, page_size, NOT_HUGE);

		usleep(1000);

		rc = hltests_free_host_mem(fd, src_ptr);

		usleep(1000);
	}
}

void test_print_hw_ip_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	printf("\nDevice information:");
	printf("\n-----------------------");
	printf("\nDevice id        : 0x%x", hw_ip.device_id);
	printf("\nDRAM enabled     : %d", hw_ip.dram_enabled);
	printf("\nDRAM base address: 0x%lx", hw_ip.dram_base_address);
	printf("\nDRAM size        : %lu (0x%lx)", hw_ip.dram_size,
							hw_ip.dram_size);
	printf("\nSRAM base address: 0x%lx", hw_ip.sram_base_address);
	printf("\nSRAM size        : %u (0x%x)", hw_ip.sram_size,
							hw_ip.sram_size);
	printf("\n\n");
}

static void print_engine_name(enum hlthunk_device_name device_id,
					uint32_t engine_id)
{
	if (device_id == HLTHUNK_DEVICE_GOYA) {
		switch (engine_id) {
		case GOYA_ENGINE_ID_DMA_0 ... GOYA_ENGINE_ID_DMA_4:
			printf("  DMA%d\n", engine_id - GOYA_ENGINE_ID_DMA_0);
			break;
		case GOYA_ENGINE_ID_MME_0:
			printf("  MME\n");
			break;
		case GOYA_ENGINE_ID_TPC_0 ... GOYA_ENGINE_ID_TPC_7:
			printf("  TPC%d\n", engine_id - GOYA_ENGINE_ID_TPC_0);
			break;
		default:
			fail_msg("Unexpected engine id %d\n", engine_id);
		}
	} else {
		fail_msg("Unexpected device id %d\n", device_id);
	}
}

void test_print_hw_idle_info(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	enum hlthunk_device_name device_id;
	uint32_t busy_engines_mask, i;
	bool is_idle;
	int rc, fd = tests_state->fd;

	printf("\n");
	printf("Idle status\n");
	printf("-----------\n");

	is_idle = hlthunk_is_device_idle(fd);
	if (is_idle) {
		printf("Device is idle\n");
		goto out;
	}

	rc = hlthunk_get_busy_engines_mask(fd, &busy_engines_mask);
	assert_int_equal(rc, 0);

	device_id = hlthunk_get_device_name_from_fd(fd);

	printf("Busy engine(s):\n");
	for (i = 0 ; i < 32; i++)
		if (busy_engines_mask & (1 << i))
			print_engine_name(device_id, i);
out:
	printf("\n");
}

struct dma_custom_cfg {
	enum hltests_goya_dma_direction dma_dir;
	uint64_t src_addr;
	uint64_t dst_addr;
	uint64_t size;
	uint32_t chunk_size;
	uint32_t value;
	uint32_t read_cnt;
	uint32_t write_cnt;
	uint32_t write_to_read_delay_ms;
	bool sequential;
	bool random;
	bool stop_on_err;
	bool zero_before_write;
};

static int dma_custom_parsing_handler(void *user, const char *section,
					const char *name, const char *value)
{
	struct dma_custom_cfg *dma_cfg = (struct dma_custom_cfg *) user;
	char *tmp;

	if (MATCH("dma_custom_test", "dma_dir")) {
		dma_cfg->dma_dir = atoi(value);
	} else if (MATCH("dma_custom_test", "dst_addr")) {
		dma_cfg->dst_addr = strtoul(value, NULL, 0);
	} else if (MATCH("dma_custom_test", "size")) {
		dma_cfg->size = strtoul(value, NULL, 0);
	} else if (MATCH("dma_custom_test", "chunk_size")) {
		dma_cfg->chunk_size = strtoul(value, NULL, 0);
	} else if (MATCH("dma_custom_test", "sequential")) {
		tmp = strdup(value);
		if (!tmp)
			return 1;

		dma_cfg->sequential = strcmp("true", tmp) ? false : true;
		if (dma_cfg->sequential)
			dma_cfg->random = false;
		free(tmp);
	} else if (MATCH("dma_custom_test", "stop_on_err")) {
		tmp = strdup(value);
		if (!tmp)
			return 1;

		dma_cfg->stop_on_err = strcmp("true", tmp) ? false : true;
		free(tmp);
	} else if (MATCH("dma_custom_test", "value")) {
		dma_cfg->value = strtoul(value, NULL, 0);
		dma_cfg->random = false;
	} else if (MATCH("dma_custom_test", "read_cnt")) {
		dma_cfg->read_cnt = strtoul(value, NULL, 0);
	} else if (MATCH("dma_custom_test", "write_cnt")) {
		dma_cfg->write_cnt = strtoul(value, NULL, 0);
	} else if (MATCH("dma_custom_test", "zero_before_write")) {
		tmp = strdup(value);
		if (!tmp)
			return 1;

		dma_cfg->zero_before_write = strcmp("true", tmp) ? false : true;
		free(tmp);
	} else if (MATCH("dma_custom_test", "write_to_read_delay_ms")) {
		dma_cfg->write_to_read_delay_ms = strtoul(value, NULL, 0);
	} else {
		return 0; /* unknown section/name, error */
	}

	return 1;
}

void test_dma_custom(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct hlthunk_hw_ip_info hw_ip;
	struct dma_custom_cfg cfg;
	void *device_ptr = NULL, *src_ptr, *dst_ptr, *zero_ptr;
	uint64_t device_addr, host_src_addr, host_dst_addr, host_zero_addr = 0;
	uint32_t dma_dir_down, dma_dir_up, read_cnt, write_cnt;
	uint64_t offset = 0;
	bool is_error;
	int i, rc, fd = tests_state->fd;

	if (!config_filename)
		fail_msg("User didn't supply a configuration file name!\n");

	cfg.random = true;
	cfg.read_cnt = 1;
	cfg.write_cnt = 1;
	cfg.stop_on_err = true;
	cfg.zero_before_write = false;
	cfg.write_to_read_delay_ms = 0;

	if (ini_parse(config_filename, dma_custom_parsing_handler, &cfg) < 0)
		fail_msg("Can't load %s\n", config_filename);

	printf("Configuration loaded from %s:\n", config_filename);
	printf("dma_dir = %d, dst_addr = 0x%lx, size = %lu, chunk size = %u\n",
		cfg.dma_dir, cfg.dst_addr, cfg.size, cfg.chunk_size);
	printf(
		"read cnt = %d, write cnt = %d, stop on err = %s, zero before write = %s\n",
		cfg.read_cnt, cfg.write_cnt,
		(cfg.stop_on_err ? "true" : "false"),
		(cfg.zero_before_write ? "true" : "false"));
	printf("write_to_read_delay_ms = %d\n", cfg.write_to_read_delay_ms);

	if (cfg.random) {
		printf("random values\n\n");
	} else if (cfg.sequential) {
		printf("sequential values\n\n");
		if (cfg.chunk_size % 4)
			fail_msg("With sequential values, chunk size must "
				"be divisible by 4\n");
	} else {
		printf("fixed fill value = 0x%x\n\n", cfg.value);
		if (cfg.chunk_size % 4)
			fail_msg("With fixed fill value, chunk size must "
				"be divisible by 4\n");
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	assert_int_equal(hw_ip.dram_enabled, 1);
	assert_int_not_equal(cfg.size, 0);
	assert_in_range(cfg.chunk_size, 1, UINT_MAX);

	dma_dir_down = cfg.dma_dir;
	switch (cfg.dma_dir) {
	case GOYA_DMA_HOST_TO_DRAM:
		dma_dir_up = GOYA_DMA_DRAM_TO_HOST;
		device_ptr = hltests_allocate_device_mem(fd,
						hw_ip.dram_size, CONTIGUOUS);
		assert_non_null(device_ptr);
		device_addr = (uint64_t) (uintptr_t) device_ptr;
		device_addr += (cfg.dst_addr - hw_ip.dram_base_address);
		break;
	case GOYA_DMA_HOST_TO_SRAM:
		dma_dir_up = GOYA_DMA_SRAM_TO_HOST;
		device_addr = cfg.dst_addr;
		break;
	default:
		fail_msg("Test doesn't support DMA direction\n");
		return;
	}

	if (cfg.chunk_size > cfg.size)
		cfg.chunk_size = cfg.size;

	src_ptr = hltests_allocate_host_mem(fd, cfg.chunk_size, NOT_HUGE);
	assert_non_null(src_ptr);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	if (cfg.sequential) {
		for (i = 0 ; i < (cfg.chunk_size / 4) ; i++)
			((uint32_t *) src_ptr)[i] = i;
	} else if (!cfg.random) {
		for (i = 0 ; i < (cfg.chunk_size / 4) ; i++)
			((uint32_t *) src_ptr)[i] = cfg.value;
	}

	if (cfg.zero_before_write) {
		zero_ptr = hltests_allocate_host_mem(fd, cfg.chunk_size,
								NOT_HUGE);
		assert_non_null(src_ptr);
		host_zero_addr = hltests_get_device_va_for_host_ptr(fd,
								zero_ptr);
		memset(zero_ptr, 0, cfg.chunk_size);
	}

	dst_ptr = hltests_allocate_host_mem(fd, cfg.chunk_size, NOT_HUGE);
	assert_non_null(dst_ptr);
	memset(dst_ptr, 0, cfg.chunk_size);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	do {
		if (cfg.zero_before_write)
			hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd,
					DCORE0, STREAM0), EB_FALSE, MB_TRUE,
					host_zero_addr, device_addr + offset,
					cfg.chunk_size, dma_dir_down);

		/* DMA: host->device */
		for (write_cnt = 0 ; write_cnt < cfg.write_cnt ; write_cnt++) {
			if (cfg.random)
				hltests_fill_rand_values(src_ptr,
							cfg.chunk_size);
			hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd,
					DCORE0, STREAM0), EB_FALSE, MB_TRUE,
					host_src_addr, device_addr + offset,
					cfg.chunk_size, dma_dir_down);
		}

		/* DMA: device->host */
		is_error = false;

		if (cfg.write_to_read_delay_ms)
			usleep((uint64_t) cfg.write_to_read_delay_ms * 1000);

		for (read_cnt = 0 ; read_cnt < cfg.read_cnt ; read_cnt++) {
			hltests_dma_transfer(fd,
				hltests_get_dma_up_qid(fd, DCORE0, STREAM0),
				EB_FALSE, MB_TRUE, device_addr + offset,
				host_dst_addr, cfg.chunk_size, dma_dir_up);

			/* Compare host memories */
			rc = hltests_mem_compare_with_stop(src_ptr, dst_ptr,
							cfg.chunk_size,
							cfg.stop_on_err);
			if (rc) {
				printf("Failed comparison, read iteration %d\n",
					read_cnt);
				is_error = true;
			}
		}

		assert_int_equal(is_error, false);

		printf("Finished section 0x%lx - 0x%lx\n", device_addr + offset,
			device_addr + offset + cfg.chunk_size);

		memset(dst_ptr, 0, cfg.chunk_size);

		offset += cfg.chunk_size;

		cfg.size -= cfg.chunk_size;

		if (cfg.chunk_size > cfg.size)
			cfg.chunk_size = cfg.size;

	} while (cfg.size > 0);

	/* Cleanup */
	rc = hltests_free_host_mem(fd, dst_ptr);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, src_ptr);
	assert_int_equal(rc, 0);

	if (device_ptr) {
		rc = hltests_free_device_mem(fd, device_ptr);
		assert_int_equal(rc, 0);
	}
}

static void test_transfer_bigger_than_alloc(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	void *device_ptr, *src_ptr, *ptr;
	struct hltests_pkt_info pkt_info;
	uint64_t device_addr, host_src_addr, seq = 0;
	uint64_t device_alloc_size = 2 * 1024 * 1024; /* 2MB */
	uint64_t host_alloc_size = 8;
	uint64_t transfer_size = 5000;
	uint32_t offset = 0;
	struct hltests_cs_chunk execute_arr[1];
	int rc, fd = tests_state->fd;

	device_ptr = hltests_allocate_device_mem(fd,
				device_alloc_size, CONTIGUOUS);
	assert_non_null(device_ptr);
	device_addr = (uint64_t) (uintptr_t) device_ptr;

	src_ptr = hltests_allocate_host_mem(fd, host_alloc_size, NOT_HUGE);
	assert_non_null(src_ptr);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	ptr = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(ptr);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = host_src_addr;
	pkt_info.dma.dst_addr = device_addr;
	pkt_info.dma.size = transfer_size;
	pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_DRAM;
	offset = hltests_add_dma_pkt(fd, ptr, offset, &pkt_info);

	hltests_submit_and_wait_cs(fd, ptr, offset,
				hltests_get_dma_down_qid(fd, DCORE0, STREAM0),
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_TIMEDOUT);

	/* no need to clean up because the device is in reset */
}

struct map_custom_cfg {
	uint64_t dram_size;
	uint64_t host_size;
	int dram_num_of_alloc;
	int host_num_of_alloc;
};

static int map_custom_parsing_handler(void *user, const char *section,
					const char *name, const char *value)
{
	struct map_custom_cfg *cfg = (struct map_custom_cfg *) user;
	char *tmp;

	if (MATCH("map_custom_test", "dram_size"))
		cfg->dram_size = strtoul(value, NULL, 0);
	else if (MATCH("map_custom_test", "host_size"))
		cfg->host_size = strtoul(value, NULL, 0);
	else if (MATCH("map_custom_test", "dram_num_of_alloc"))
		cfg->dram_num_of_alloc = atoi(value);
	else if (MATCH("map_custom_test", "host_num_of_alloc"))
		cfg->host_num_of_alloc = atoi(value);
	else
		return 0; /* unknown section/name, error */

	return 1;
}

void test_map_custom(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct hlthunk_hw_ip_info hw_ip;
	struct map_custom_cfg cfg;
	void *dram_addr, *host_addr;
	int i, rc, fd = tests_state->fd;

	memset(&cfg, 0, sizeof(struct map_custom_cfg));
	cfg.dram_num_of_alloc = 1;
	cfg.host_num_of_alloc = 1;

	if (!config_filename)
		fail_msg("User didn't supply a configuration file name!\n");

	if (ini_parse(config_filename, map_custom_parsing_handler, &cfg) < 0)
		fail_msg("Can't load %s\n", config_filename);

	printf("Configuration loaded from %s:\n", config_filename);
	printf("dram size = %lu , host size = %lu\n",
			cfg.dram_size, cfg.host_size);
	printf(
		"number of dram allocations = %d, number of host allocations = %d\n",
		cfg.dram_num_of_alloc, cfg.host_num_of_alloc);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (cfg.dram_num_of_alloc)
		assert_int_equal(hw_ip.dram_enabled, 1);

	for (i = 0 ; i < cfg.dram_num_of_alloc ; i++) {
		dram_addr = hltests_allocate_device_mem(fd, cfg.dram_size,
								CONTIGUOUS);
		assert_non_null(dram_addr);
	}

	for (i = 0 ; i < cfg.host_num_of_alloc ; i++) {
		host_addr = hltests_allocate_host_mem(fd, cfg.host_size,
							NOT_HUGE);
		assert_non_null(host_addr);
	}

	printf("Starting to wait...\n");
	while (1)
		sleep(1);
}

void test_loop_map_work_unmap(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_pkt_info pkt_info;
	void *src_ptr, *dram_ptr;
	uint64_t host_src_addr, total_size = 100 * SZ_1M;
	uint32_t cb_size = 0;
	void *cb;
	int i, rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	cb = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_non_null(cb);

	dram_ptr = hltests_allocate_device_mem(fd, total_size, CONTIGUOUS);
	assert_non_null(dram_ptr);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.dst_addr = (uint64_t) (uintptr_t) dram_ptr;
	pkt_info.dma.size = total_size;
	pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_DRAM;

	for (i = 0 ; i < 20000 ; i++) {
		src_ptr = hltests_allocate_host_mem(fd, total_size, HUGE);
		assert_non_null(src_ptr);
		host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

		pkt_info.dma.src_addr = host_src_addr;

		cb_size = hltests_add_dma_pkt(fd, cb, 0, &pkt_info);

		hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, DCORE0, STREAM0),
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);

		rc = hltests_free_host_mem(fd, src_ptr);
		assert_int_equal(rc, 0);

		if (!((i + 1) % 100))
			printf("Finished %d iterations\n", i + 1);
	}

	rc = hltests_free_device_mem(fd, dram_ptr);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);
}

const struct CMUnitTest debug_tests[] = {
	cmocka_unit_test_setup(test_tdr_deadlock,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_endless_memory_ioctl,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_print_hw_ip_info,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_print_hw_idle_info,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_custom,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_transfer_bigger_than_alloc,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_map_custom,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_loop_map_work_unmap,
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"debug [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(debug_tests) / sizeof((debug_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID, debug_tests,
			num_tests);

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("This executable need to be run with -d flag\n");
		return 0;
	}

	return hltests_run_group_tests("debug", debug_tests, num_tests,
					hltests_setup, hltests_teardown);
}
