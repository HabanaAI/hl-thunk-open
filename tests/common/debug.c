// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "ini.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

VOID test_tdr_deadlock(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_pkt_info pkt_info;
	void *ptr;
	uint32_t offset = 0;
	int fd = tests_state->fd;

	ptr = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(ptr);
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.fence.dec_val = 1;
	pkt_info.fence.gate_val = 1;
	pkt_info.fence.fence_id = 0;
	offset = hltests_add_fence_pkt(fd, ptr, offset, &pkt_info);

	hltests_submit_and_wait_cs(fd, ptr, offset,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_TIMEDOUT);

	/* no need to destroy the CB because the device is in reset */
	END_TEST;
}

VOID test_endless_memory_ioctl(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	void *src_ptr;
	int rc, fd = tests_state->fd;

	/* Don't check return value because we don't want the test to finish
	 * when the driver returns error
	 */

	while (1) {
		src_ptr = hltests_allocate_host_mem(fd, SZ_4K, NOT_HUGE_MAP);

		usleep(1000);

		rc = hltests_free_host_mem(fd, src_ptr);

		usleep(1000);
	}

	END_TEST;
}

struct dma_custom_cfg {
	enum hltests_dma_direction dma_dir;
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
	} else if (MATCH("dma_custom_test", "zero_before_write")) {
		tmp = strdup(value);
		if (!tmp)
			return 1;

		cfg->zero_before_write = strcmp("true", tmp) ? false : true;
		free(tmp);
	} else if (MATCH("dma_custom_test", "write_to_read_delay_ms")) {
		cfg->write_to_read_delay_ms = strtoul(value, NULL, 0);
	} else {
		return 0; /* unknown section/name, error */
	}

	return 1;
}

VOID test_dma_custom(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct hlthunk_hw_ip_info hw_ip;
	struct dma_custom_cfg cfg;
	void *device_ptr = NULL, *src_ptr, *dst_ptr, *zero_ptr = NULL;
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

	assert_int_not_equal(cfg.size, 0);
	assert_in_range(cfg.chunk_size, 1, UINT_MAX);

	dma_dir_down = cfg.dma_dir;
	switch (cfg.dma_dir) {
	case DMA_DIR_HOST_TO_DRAM:
		assert_int_equal(hw_ip.dram_enabled, 1);
		dma_dir_up = DMA_DIR_DRAM_TO_HOST;
		device_ptr = hltests_allocate_device_mem(fd, hw_ip.dram_size, 0, CONTIGUOUS);
		assert_non_null(device_ptr);
		device_addr = (uint64_t) (uintptr_t) device_ptr;
		device_addr += (cfg.dst_addr - hw_ip.dram_base_address);
		break;
	case DMA_DIR_HOST_TO_SRAM:
		dma_dir_up = DMA_DIR_SRAM_TO_HOST;
		device_addr = cfg.dst_addr;
		break;
	default:
		fail_msg("Test doesn't support DMA direction\n");
		EXIT_FROM_TEST;
	}

	if (cfg.chunk_size > cfg.size)
		cfg.chunk_size = cfg.size;

	src_ptr = hltests_allocate_host_mem(fd, cfg.chunk_size, NOT_HUGE_MAP);
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
								NOT_HUGE_MAP);
		assert_non_null(src_ptr);
		host_zero_addr = hltests_get_device_va_for_host_ptr(fd,
								zero_ptr);
		memset(zero_ptr, 0, cfg.chunk_size);
	}

	dst_ptr = hltests_allocate_host_mem(fd, cfg.chunk_size, NOT_HUGE_MAP);
	assert_non_null(dst_ptr);
	memset(dst_ptr, 0, cfg.chunk_size);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	do {
		if (cfg.zero_before_write)
			hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd,
					STREAM0), EB_FALSE, MB_TRUE,
					host_zero_addr, device_addr + offset,
					cfg.chunk_size, dma_dir_down);

		/* DMA: host->device */
		for (write_cnt = 0 ; write_cnt < cfg.write_cnt ; write_cnt++) {
			if (cfg.random)
				hltests_fill_rand_values(src_ptr,
							cfg.chunk_size);
			hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd,
					STREAM0), EB_FALSE, MB_TRUE,
					host_src_addr, device_addr + offset,
					cfg.chunk_size, dma_dir_down);
		}

		/* DMA: device->host */
		is_error = false;

		if (cfg.write_to_read_delay_ms)
			usleep((uint64_t) cfg.write_to_read_delay_ms * 1000);

		for (read_cnt = 0 ; read_cnt < cfg.read_cnt ; read_cnt++) {
			hltests_dma_transfer(fd,
				hltests_get_dma_up_qid(fd, STREAM0),
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

	if (cfg.zero_before_write) {
		rc = hltests_free_host_mem(fd, zero_ptr);
		assert_int_equal(rc, 0);
	}

	if (device_ptr) {
		rc = hltests_free_device_mem(fd, device_ptr);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_transfer_bigger_than_alloc(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	void *device_ptr, *src_ptr;
	uint64_t device_addr, host_src_addr;
	uint64_t device_alloc_size = 2 * 1024 * 1024; /* 2MB */
	uint64_t host_alloc_size = 8;
	uint64_t transfer_size = 5000;
	int fd = tests_state->fd;

	device_ptr = hltests_allocate_device_mem(fd, device_alloc_size, 0, CONTIGUOUS);
	assert_non_null(device_ptr);
	device_addr = (uint64_t) (uintptr_t) device_ptr;

	src_ptr = hltests_allocate_host_mem(fd, host_alloc_size, NOT_HUGE_MAP);
	assert_non_null(src_ptr);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0), EB_FALSE,
			MB_FALSE, host_src_addr, device_addr, transfer_size,
			DMA_DIR_HOST_TO_DRAM);

	/* no need to clean up because the device is in reset */
	END_TEST;
}

struct map_custom_cfg {
	uint64_t dram_size;
	uint64_t host_size;
	int dram_num_of_alloc;
	int host_num_of_alloc;
	bool create_tdr;
};

static int map_custom_parsing_handler(void *user, const char *section,
					const char *name, const char *value)
{
	struct map_custom_cfg *cfg = (struct map_custom_cfg *) user;
	char *tmp;

	if (MATCH("map_custom_test", "dram_size")) {
		cfg->dram_size = strtoul(value, NULL, 0);
	} else if (MATCH("map_custom_test", "host_size")) {
		cfg->host_size = strtoul(value, NULL, 0);
	} else if (MATCH("map_custom_test", "dram_num_of_alloc")) {
		cfg->dram_num_of_alloc = atoi(value);
	} else if (MATCH("map_custom_test", "host_num_of_alloc")) {
		cfg->host_num_of_alloc = atoi(value);
	} else if (MATCH("map_custom_test", "create_tdr")) {
		tmp = strdup(value);
		if (!tmp)
			return 1;

		cfg->create_tdr = strcmp("true", tmp) ? false : true;
		free(tmp);
	} else {
		return 0; /* unknown section/name, error */
	}

	return 1;
}

VOID test_map_custom(void **state)
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
	printf("create tdr = %d\n", cfg.create_tdr);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (cfg.dram_num_of_alloc)
		assert_int_equal(hw_ip.dram_enabled, 1);

	for (i = 0 ; i < cfg.dram_num_of_alloc ; i++) {
		dram_addr = hltests_allocate_device_mem(fd, cfg.dram_size, 0, CONTIGUOUS);
		assert_non_null(dram_addr);
	}

	for (i = 0 ; i < cfg.host_num_of_alloc ; i++) {
		host_addr = hltests_allocate_host_mem(fd, cfg.host_size,
							NOT_HUGE_MAP);
		assert_non_null(host_addr);
	}

	if (!cfg.create_tdr) {
		printf("Starting to wait...\n");
		while (1)
			sleep(1);
	}

	printf("Creating TDR...\n");

	test_tdr_deadlock(state);

	END_TEST;
}

VOID test_loop_map_work_unmap(void **state)
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

	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(cb);

	dram_ptr = hltests_allocate_device_mem(fd, total_size, 0, CONTIGUOUS);
	assert_non_null(dram_ptr);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.dst_addr = (uint64_t) (uintptr_t) dram_ptr;
	pkt_info.dma.size = total_size;
	pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_DRAM;

	for (i = 0 ; i < 20000 ; i++) {
		src_ptr = hltests_allocate_host_mem(fd, total_size, HUGE_MAP);
		assert_non_null(src_ptr);
		host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

		pkt_info.dma.src_addr = host_src_addr;

		cb_size = hltests_add_dma_pkt(fd, cb, 0, &pkt_info);

		hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
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

	END_TEST;
}

static int file_descriptor_sanity_check(int fd)
{
	struct hlthunk_hw_ip_info hw_ip;

	/* INFO IOCTL is an arbitrary IOCTL for a sanity check of the fd */
	memset(&hw_ip, 0, sizeof(hw_ip));
	return hlthunk_get_hw_ip_info(fd, &hw_ip);
}

VOID test_duplicate_file_descriptor(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	enum hlthunk_device_name device_name;
	int rc, fd = tests_state->fd, fd_dup, fd_new;

	device_name = hlthunk_get_device_name_from_fd(fd);
	assert_int_not_equal(device_name, HLTHUNK_DEVICE_INVALID);

	/* Duplicate a file descriptor */
	fd_dup = dup(fd);
	assert_false(fd_dup < 0);
	rc = file_descriptor_sanity_check(fd_dup);
	assert_int_equal(rc, 0);

	/*
	 * Verify that fd is valid after closing the duplicated fd, and that a
	 * new file descriptor cannot be opened.
	 */
	rc = hlthunk_close(fd_dup);
	assert_int_equal(rc, 0);
	rc = file_descriptor_sanity_check(fd);
	assert_int_equal(rc, 0);
	fd_new = hlthunk_open(device_name, NULL);
	assert_true(fd_new < 0);

	/*
	 * Re-duplicate a file descriptor.
	 * Verify that the duplicated fd is still valid after closing fd, and
	 * that a new file descriptor cannot be opened.
	 */
	fd_dup = dup(fd);
	assert_false(fd_dup < 0);
	rc = file_descriptor_sanity_check(fd_dup);
	assert_int_equal(rc, 0);
	rc = hlthunk_close(fd);
	assert_int_equal(rc, 0);
	rc = file_descriptor_sanity_check(fd_dup);
	assert_int_equal(rc, 0);
	fd_new = hlthunk_open(device_name, NULL);
	assert_true(fd_new < 0);

	/*
	 * Close the duplicated fd in addition to fd and verify that a new file
	 * descriptor can be opened.
	 */
	rc = hlthunk_close(fd_dup);
	assert_int_equal(rc, 0);
	fd_new = hlthunk_open(device_name, NULL);
	assert_false(fd_new < 0);
	rc = file_descriptor_sanity_check(fd_new);
	assert_int_equal(rc, 0);

	/*
	 * Update "tests_state->fd" to "fd_new", so the "hltests_teardown"
	 * function won't try to close "fd" which was released during the test.
	 */
	tests_state->fd = fd_new;

	END_TEST;
}

VOID test_page_miss(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	void *device_addr, *src_ptr, *dst_ptr;
	uint64_t host_src_addr, host_dst_addr;
	uint32_t size = 0x100000;
	int rc, fd = tests_state->fd;

	/* Sanity and memory allocation */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	device_addr = (void *) (uintptr_t) hw_ip.sram_base_address;

	src_ptr = malloc(size);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, size);
	host_src_addr = (uint64_t) (uintptr_t) src_ptr;

	dst_ptr = malloc(size);
	assert_non_null(dst_ptr);
	memset(dst_ptr, 0, size);
	host_dst_addr = (uint64_t) (uintptr_t) dst_ptr;

	/* DMA: host->device */
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, host_src_addr,
			(uint64_t) (uintptr_t) device_addr,
			size, DMA_DIR_HOST_TO_SRAM);

	/* DMA: device->host */
	hltests_dma_transfer(fd, hltests_get_dma_up_qid(fd, STREAM0),
				0, 1, (uint64_t) (uintptr_t) device_addr,
				host_dst_addr, size, DMA_DIR_SRAM_TO_HOST);

	/* Compare host memories */
	rc = hltests_mem_compare(src_ptr, dst_ptr, size);
	assert_int_not_equal(rc, 0);

	/* Cleanup */
	free(dst_ptr);
	free(src_ptr);

	END_TEST;
}

struct register_security_cfg {
	uint64_t reg_addr;
	uint32_t value;
	uint32_t qid;
	bool use_wreg;
};

static int register_security_parsing_handler(void *user, const char *section,
					const char *name, const char *value)
{
	struct register_security_cfg *cfg =
					(struct register_security_cfg *) user;
	char *tmp;

	if (MATCH("register_security_cfg", "reg_addr")) {
		cfg->reg_addr = strtoul(value, NULL, 0);
	} else if (MATCH("register_security_cfg", "value")) {
		cfg->value = strtoul(value, NULL, 0);
	} else if (MATCH("register_security_cfg", "qid")) {
		cfg->qid = strtoul(value, NULL, 0);
	} else if (MATCH("register_security_cfg", "use_wreg")) {
		tmp = strdup(value);
		if (!tmp)
			return 1;

		cfg->use_wreg = strcmp("true", tmp) ? false : true;
		free(tmp);
	} else {
		return 0; /* unknown section/name, error */
	}

	return 1;
}

VOID test_register_security(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct hlthunk_hw_ip_info hw_ip;
	struct register_security_cfg cfg;
	struct hltests_pkt_info pkt_info;
	uint32_t cb_size;
	void *cb;
	int rc, fd = tests_state->fd;

	memset(&cfg, 0, sizeof(struct register_security_cfg));

	if (!config_filename)
		fail_msg("User didn't supply a configuration file name!\n");

	if (ini_parse(config_filename, register_security_parsing_handler,
								&cfg) < 0)
		fail_msg("Can't load %s\n", config_filename);

	printf("Configuration loaded from %s:\n", config_filename);
	printf("register address = 0x%lx, value = 0x%x\n",
		cfg.reg_addr, cfg.value);
	printf("use_wreg = %d, qid = %d\n",
		cfg.use_wreg, cfg.qid);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	cb = hltests_create_cb(fd, SZ_4K, EXTERNAL, 0);
	assert_non_null(cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;

	if (cfg.use_wreg) {
		pkt_info.wreg32.reg_addr = (uint16_t) cfg.reg_addr;
		pkt_info.wreg32.value = cfg.value;

		cb_size = hltests_add_wreg32_pkt(fd, cb, 0, &pkt_info);

		END_TEST_FUNC(hltests_submit_and_wait_cs(fd, cb, cb_size,
				cfg.qid, DESTROY_CB_TRUE,
				HL_WAIT_CS_STATUS_COMPLETED));
	} else {
		pkt_info.msg_long.address = cfg.reg_addr;
		pkt_info.msg_long.value = cfg.value;

		cb_size = hltests_add_msg_long_pkt(fd, cb, 0, &pkt_info);

		END_TEST_FUNC(hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED));
	}

	END_TEST;
}

struct scan_with_sm_cfg {
	uint64_t start_addr;
	uint64_t end_addr;
	uint32_t value;
	bool sequential;
	bool random;
};

static int scan_with_sm_parsing_handler(void *user, const char *section,
					const char *name, const char *value)
{
	struct scan_with_sm_cfg *cfg = (struct scan_with_sm_cfg *) user;
	char *tmp;

	if (MATCH("scan_with_sm", "start_addr")) {
		cfg->start_addr = strtoul(value, NULL, 0);
	} else if (MATCH("scan_with_sm", "end_addr")) {
		cfg->end_addr = strtoul(value, NULL, 0);
	} else if (MATCH("scan_with_sm", "sequential")) {
		tmp = strdup(value);
		if (!tmp)
			return 1;

		cfg->sequential = strcmp("true", tmp) ? false : true;
		if (cfg->sequential)
			cfg->random = false;
		free(tmp);
	} else if (MATCH("scan_with_sm", "value")) {
		cfg->value = strtoul(value, NULL, 0);
		cfg->random = false;
	} else {
		return 0; /* unknown section/name, error */
	}

	return 1;
}

VOID test_scan_with_sm(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct hltests_monitor mon_info;
	struct hltests_pkt_info write_to_sob, clear_sob;
	struct hlthunk_hw_ip_info hw_ip;
	uint16_t sob_id, mon_per_dcore;
	int rc, fd = tests_state->fd;
	struct scan_with_sm_cfg cfg;
	uint32_t cb_size, seq_val;
	uint64_t cur_addr, qid;
	void *cb;

	if (!config_filename)
		fail_msg("User didn't supply a configuration file name!\n");

	memset(&cfg, 0, sizeof(struct scan_with_sm_cfg));
	cfg.random = true;

	if (ini_parse(config_filename, scan_with_sm_parsing_handler, &cfg) < 0)
		fail_msg("Can't load %s\n", config_filename);

	printf("Configuration loaded from %s:\n", config_filename);
	printf("start address = 0x%lx, end address = 0x%lx\n", cfg.start_addr, cfg.end_addr);

	if (cfg.random)
		printf("random values\n\n");
	else if (cfg.sequential)
		printf("sequential values\n\n");
	else
		printf("fixed fill value = 0x%x\n\n", cfg.value);

	assert_in_range(cfg.start_addr, 0, cfg.end_addr - 4);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	cb = hltests_create_cb(fd, HL_MAX_CB_SIZE, EXTERNAL, 0);
	assert_non_null(cb);

	sob_id = hltests_get_first_avail_sob(fd);
	mon_per_dcore = hltests_get_monitors_cnt_per_dcore(fd);
	qid = hltests_get_dma_down_qid(fd, STREAM0);

	memset(&clear_sob, 0, sizeof(clear_sob));
	clear_sob.qid = qid;
	clear_sob.eb = EB_TRUE;
	clear_sob.mb = MB_TRUE;
	clear_sob.write_to_sob.sob_id = sob_id;
	clear_sob.write_to_sob.value = 0;
	clear_sob.write_to_sob.mode = SOB_SET;

	memset(&mon_info, 0, sizeof(mon_info));
	mon_info.sob_id = sob_id;
	mon_info.mon_id = hltests_get_first_avail_mon(fd);
	mon_info.sob_val = 1;

	memset(&write_to_sob, 0, sizeof(write_to_sob));
	write_to_sob.qid = qid;
	write_to_sob.eb = EB_TRUE;
	write_to_sob.mb = MB_TRUE;
	write_to_sob.write_to_sob.sob_id = sob_id;
	write_to_sob.write_to_sob.value = 1;
	write_to_sob.write_to_sob.mode = SOB_SET;

	cb_size = 0;
	cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &clear_sob);

	for (cur_addr = cfg.start_addr, seq_val = 0;  cur_addr < cfg.end_addr ; cur_addr += 4) {
		mon_info.mon_address = cur_addr;

		if (cfg.random)
			mon_info.mon_payload = hltests_rand_u32();
		else if (cfg.sequential)
			mon_info.mon_payload = seq_val++;
		else
			mon_info.mon_payload = cfg.value;


		cb_size = hltests_add_monitor(fd, cb, cb_size, &mon_info);

		mon_info.mon_id++;

		if (cur_addr + 4 >= cfg.end_addr || cb_size + 0x100 > HL_MAX_CB_SIZE ||
					mon_info.mon_id == mon_per_dcore) {

			cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &write_to_sob);

			hltests_submit_and_wait_cs(fd, cb, cb_size, qid,
						DESTROY_CB_FALSE, HL_WAIT_CS_STATUS_COMPLETED);
			cb_size = 0;
			mon_info.mon_id = hltests_get_first_avail_mon(fd);
			cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &clear_sob);
		}
	}

	hltests_destroy_cb(fd, cb);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest debug_tests[] = {
	cmocka_unit_test_setup(test_tdr_deadlock,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_endless_memory_ioctl,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dma_custom,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_transfer_bigger_than_alloc,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_map_custom,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_loop_map_work_unmap,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_duplicate_file_descriptor,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_page_miss,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_register_security,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_scan_with_sm,
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"debug [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(debug_tests) / sizeof((debug_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE, debug_tests,
			num_tests);

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("This executable need to be run with -d flag\n");
		return 0;
	}

	return hltests_run_group_tests("debug", debug_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
