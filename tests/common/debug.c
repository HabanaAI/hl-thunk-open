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
	assert_ptr_not_equal(ptr, NULL);
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

struct dma_custom_cfg {
	enum hltests_goya_dma_direction dma_dir;
	uint64_t src_addr;
	uint64_t dst_addr;
	uint64_t size;
	uint32_t chunk_size;
	uint32_t value;
	uint32_t read_cnt;
	uint32_t write_cnt;
	bool sequential;
	bool random;
	bool stop_on_err;
};

static int dma_custom_parsing_handler(void *user, const char *section,
					const char *name, const char *value)
{
	struct dma_custom_cfg *cfg = (struct dma_custom_cfg *) user;
	char *tmp;

	if (MATCH("dma_custom_test", "dma_dir")) {
		cfg->dma_dir = atoi(value);
	} else if (MATCH("dma_custom_test", "dst_addr")) {
		cfg->dst_addr = strtoul(value, NULL, 0);
	} else if (MATCH("dma_custom_test", "size")) {
		cfg->size = strtoul(value, NULL, 0);
	} else if (MATCH("dma_custom_test", "chunk_size")) {
		cfg->chunk_size = strtoul(value, NULL, 0);
	} else if (MATCH("dma_custom_test", "sequential")) {
		tmp = strdup(value);
		if (!tmp)
			return 1;

		cfg->sequential = strcmp("true", tmp) ? false : true;
		if (cfg->sequential)
			cfg->random = false;
		free(tmp);
	} else if (MATCH("dma_custom_test", "stop_on_err")) {
		tmp = strdup(value);
		if (!tmp)
			return 1;

		cfg->stop_on_err = strcmp("true", tmp) ? false : true;
		free(tmp);
	} else if (MATCH("dma_custom_test", "value")) {
		cfg->value = strtoul(value, NULL, 0);
		cfg->random = false;
	} else if (MATCH("dma_custom_test", "read_cnt")) {
		cfg->read_cnt = strtoul(value, NULL, 0);
	} else if (MATCH("dma_custom_test", "write_cnt")) {
		cfg->write_cnt = strtoul(value, NULL, 0);
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
	void *device_ptr = NULL, *src_ptr, *dst_ptr;
	uint64_t device_addr, host_src_addr, host_dst_addr, offset = 0;
	uint32_t dma_dir_down, dma_dir_up, read_cnt, write_cnt;
	bool is_huge, is_error;
	int i, rc, fd = tests_state->fd;

	if (!config_filename)
		fail_msg("User didn't supply a configuration file name!\n");

	cfg.random = true;
	cfg.read_cnt = 1;
	cfg.write_cnt = 1;
	cfg.stop_on_err = true;

	if (ini_parse(config_filename, dma_custom_parsing_handler, &cfg) < 0)
		fail_msg("Can't load %s\n", config_filename);

	printf("Configuration loaded from %s:\n", config_filename);
	printf("dma_dir = %d, dst_addr = 0x%lx, size = %lu, chunk size = %u\n",
		cfg.dma_dir, cfg.dst_addr, cfg.size, cfg.chunk_size);
	printf("read cnt = %d, write cnt = %d, stop on err = %s\n",
		cfg.read_cnt, cfg.write_cnt,
		(cfg.stop_on_err ? "true" : "false"));

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
						hw_ip.dram_size, CONTIGOUS);
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

	is_huge = cfg.chunk_size > 32 * 1024;

	src_ptr = hltests_allocate_host_mem(fd, cfg.chunk_size, is_huge);
	assert_non_null(src_ptr);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	if (cfg.sequential) {
		for (i = 0 ; i < (cfg.chunk_size / 4) ; i++)
			((uint32_t *) src_ptr)[i] = i;
	} else if (!cfg.random) {
		for (i = 0 ; i < (cfg.chunk_size / 4) ; i++)
			((uint32_t *) src_ptr)[i] = cfg.value;
	}

	dst_ptr = hltests_allocate_host_mem(fd, cfg.chunk_size, is_huge);
	assert_non_null(dst_ptr);
	memset(dst_ptr, 0, cfg.chunk_size);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	do {
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
				device_alloc_size, CONTIGOUS);
	assert_non_null(device_ptr);
	device_addr = (uint64_t) (uintptr_t) device_ptr;

	src_ptr = hltests_allocate_host_mem(fd, host_alloc_size, NOT_HUGE);
	assert_non_null(src_ptr);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	ptr = hltests_create_cb(fd, getpagesize(), EXTERNAL, 0);
	assert_ptr_not_equal(ptr, NULL);

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

const struct CMUnitTest debug_tests[] = {
	cmocka_unit_test_setup(test_tdr_deadlock,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_endless_memory_ioctl,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_print_hw_ip_info,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_custom,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_transfer_bigger_than_alloc,
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"debug [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID, debug_tests,
			sizeof(debug_tests) / sizeof((debug_tests)[0]));

	if (!hltests_get_parser_run_disabled_tests())
		return 0;

	return cmocka_run_group_tests(debug_tests, hltests_setup,
					hltests_teardown);
}
