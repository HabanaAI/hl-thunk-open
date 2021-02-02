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
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#define is_power_of_2(x) (				\
{							\
	typeof(x) __x = (x);				\
	((__x > 0) && ((__x & (__x  - 1)) == 0));	\
}							\
)

#define PAGE_OFFSET_MASK	0xFFF
#define BLOCKS_NUM		2

enum range_type {HOST_ADDR, DRAM_ADDR};

struct hints_param {
	uint64_t *hints;
	uint32_t num_of_hints;
	uint32_t hint_idx;
	enum range_type type;
	uint32_t size;
} hints_param;

struct hints_addr_cfg {
	struct hints_param hints_block[BLOCKS_NUM]; /* [HOST], [DRAM] */
	uint32_t block_idx;
	uint32_t blocks_count;
};

/**
 * This test checks that a mapping of more than 4GB is successful. This big size
 * enforces the driver to store it in a u64 variable rather than u32 variable.
 * In addition the test performs DMA transfers to verify that the mapping is
 * correct.
 * The DMA size shouldn't be too big to avoid too big command buffers.
 * @param state contains the open file descriptor.
 */
void test_map_bigger_than_4GB(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	void *device_addr, *src_ptr, *dst_ptr;
	uint64_t host_src_addr, host_dst_addr, total_size = (1ull << 30) * 5,
		dma_size = 1 << 26, offset = 0;
	uint32_t dma_dir_down, dma_dir_up;
	int rc, fd = tests_state->fd;

	if (hltests_is_pldm(fd))
		skip();

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	if (!tests_state->mmu) {
		printf("MMU is disabled so skipping test\n");
		skip();
	}

	assert_in_range(dma_size, 1, hw_ip.dram_size);

	device_addr = hltests_allocate_device_mem(fd, dma_size, NOT_CONTIGUOUS);
	assert_non_null(device_addr);

	dma_dir_down = GOYA_DMA_HOST_TO_DRAM;
	dma_dir_up = GOYA_DMA_DRAM_TO_HOST;

	src_ptr = hltests_allocate_host_mem(fd, total_size, NOT_HUGE);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, total_size);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE);
	assert_non_null(dst_ptr);
	memset(dst_ptr, 0, dma_size);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	/* We don't need to transfer the entire size.
	 * Do a sample DMA every 512MB
	 */
	while (offset < total_size) {
		/* DMA: host->device */
		hltests_dma_transfer(fd,
				hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE, (host_src_addr + offset),
				(uint64_t) (uintptr_t) device_addr, dma_size,
				dma_dir_down);

		/* DMA: device->host */
		hltests_dma_transfer(fd,
				hltests_get_dma_up_qid(fd, STREAM0),
				EB_FALSE, MB_TRUE,
				(uint64_t) (uintptr_t) device_addr,
				host_dst_addr, dma_size, dma_dir_up);

		/* Compare host memories */
		rc = hltests_mem_compare(
				(void *) ((uintptr_t) src_ptr + offset),
				dst_ptr, dma_size);
		assert_int_equal(rc, 0);

		offset += (1ull << 29);
	}

	/* Cleanup */
	rc = hltests_free_host_mem(fd, dst_ptr);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, src_ptr);
	assert_int_equal(rc, 0);

	rc = hltests_free_device_mem(fd, device_addr);
	assert_int_equal(rc, 0);
}

/**
 * This test allocates device memory until all the memory was allocated.
 * When the device dram_page_size is a power of 2 the allocated chunks are 0.5GB
 * (because the driver reserves the first 0.5GB and we have multiples of 1GB of
 * memory).
 * When the device dram_page_size is not  a power of 2, the allocated memory
 * chunks will have the same size as the dram_page_size. This may leave some
 * memory residues which will not be used by the test.
 * The test pass if we can allocate the entire memory and fails otherwise
 * @param state contains the open file descriptor.
 * @param contiguous indicates if the allocated device memory should be
 *        contiguous or not.
 */
static void allocate_device_mem_until_full(void **state,
					enum hltests_contiguous contigouos)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	void **device_addr;
	uint64_t total_size, num_of_chunks, i, j;
	uint32_t chunk_size;
	bool error = false;
	int rc, fd = tests_state->fd;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		skip();
	}

	total_size = hw_ip.dram_size;
	if ((hw_ip.dram_page_size == 0) ||
				is_power_of_2(hw_ip.dram_page_size)) {
		chunk_size = hltests_is_simulator(fd) ? SZ_32M : SZ_512M;
		/* handle devices with dram_page_size > 32M */
		chunk_size = chunk_size > hw_ip.dram_page_size ?
					chunk_size : hw_ip.dram_page_size;
	} else {
		chunk_size = hw_ip.dram_page_size;
	}

	num_of_chunks = total_size / chunk_size;
	assert_int_not_equal(num_of_chunks, 0);

	device_addr = hlthunk_malloc(num_of_chunks * sizeof(void *));
	assert_non_null(device_addr);

	for (i = 0 ; i < num_of_chunks ; i++) {
		device_addr[i] = hltests_allocate_device_mem(fd, chunk_size,
								contigouos);
		if (!device_addr[i])
			break;
	}

	if (i < num_of_chunks) {
		printf("Was able to allocate only %luMB out of %luMB\n",
			i * (chunk_size / SZ_1M), total_size / SZ_1M);
		error = true;
	}

	for (j = 0 ; j < i ; j++) {
		rc = hltests_free_device_mem(fd, device_addr[j]);
		assert_int_equal(rc, 0);
	}

	hlthunk_free(device_addr);

	if (error)
		fail();
}

void test_alloc_device_mem_until_full(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;

	if (hltests_is_pldm(tests_state->fd))
		skip();

	allocate_device_mem_until_full(state, NOT_CONTIGUOUS);
}

void test_alloc_device_mem_until_full_contiguous(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;

	if (hltests_is_pldm(tests_state->fd))
		skip();

	allocate_device_mem_until_full(state, CONTIGUOUS);
}

void test_submit_after_unmap(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	void *device_addr, *src_ptr;
	uint64_t host_src_addr, size;
	int rc, fd = tests_state->fd;

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("This test need to be run with -d flag\n");
		skip();
	}

	size = 0x1000;

	/* Sanity and memory allocation */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	device_addr = (void *) (uintptr_t) hw_ip.sram_base_address;

	src_ptr = hltests_allocate_host_mem(fd, size, false);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, size);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	/* Cleanup */
	rc = hltests_free_host_mem(fd, src_ptr);
	assert_int_equal(rc, 0);

	/* DMA: host->device */
	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, host_src_addr,
			(uint64_t) (uintptr_t) device_addr,
			size, GOYA_DMA_HOST_TO_SRAM);

}

void test_submit_and_close(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t seq, host_src_addr, size, cb_size, device_addr;
	struct hltests_cs_chunk execute_arr;
	struct hltests_pkt_info pkt_info;
	void *src_ptr, *cb;
	struct hlthunk_hw_ip_info hw_ip;
	int i, rc, fd = tests_state->fd;
	uint32_t cb_offset = 0;

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("This test need to be run with -d flag\n");
		skip();
	}

	size = 0x1000;

	/* Sanity and memory allocation */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	device_addr = hw_ip.sram_base_address;

	src_ptr = hltests_allocate_host_mem(fd, size, false);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, size);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	cb_size = 0x200000 - 128;

	cb = hltests_create_cb(fd, cb_size, EXTERNAL, 0);
	assert_non_null(cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = host_src_addr;
	pkt_info.dma.dst_addr = device_addr;
	pkt_info.dma.size = size;
	pkt_info.dma.dma_dir = GOYA_DMA_HOST_TO_SRAM;

	for (i = 0 ; i < (cb_size / 24) ; i++)
		cb_offset = hltests_add_dma_pkt(fd, cb, cb_offset, &pkt_info);

	execute_arr.cb_ptr = cb;
	execute_arr.cb_size = cb_offset;
	execute_arr.queue_index = hltests_get_dma_down_qid(fd, STREAM0);

	rc = hltests_submit_cs(fd, NULL, 0, &execute_arr, 1, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);
}

static int test_hint_addresses_parsing_handler(void *user, const char *section,
					const char *name, const char *value)
{
	struct hints_addr_cfg *cfg = (struct hints_addr_cfg *) user;
	uint32_t *hints_idx;

	if (MATCH("hint_addresses_test", "range_type")) {
		if (cfg->blocks_count)
			cfg->block_idx++;

		if (strcmp(value, "host") == 0) {
			cfg->hints_block[cfg->block_idx].type = HOST_ADDR;
		} else if (strcmp(value, "dram") == 0) {
			cfg->hints_block[cfg->block_idx].type = DRAM_ADDR;
		} else {
			printf("Invalid hints block config, fix config file\n");
			return 0;
		}
		cfg->blocks_count++;
		if (cfg->blocks_count > BLOCKS_NUM) {
			printf("bad config file, range blocks must be %u\n",
					BLOCKS_NUM);
			return 0;
		}
	} else if (MATCH("hint_addresses_test", "hints_num")) {
		cfg->hints_block[cfg->block_idx].num_of_hints =
						strtoul(value, NULL, 0);
		cfg->hints_block[cfg->block_idx].hints = malloc(
				cfg->hints_block[cfg->block_idx].num_of_hints *
					sizeof(uint64_t));
		if (!cfg->hints_block[cfg->block_idx].hints) {
			printf("Failed to allocate memory\n");
			return 0;
		}
		memset(cfg->hints_block[cfg->block_idx].hints, 0,
				cfg->hints_block[cfg->block_idx].num_of_hints *
							sizeof(uint64_t));
	}  else if (MATCH("hint_addresses_test", "va_hint")) {
		hints_idx = &cfg->hints_block[cfg->block_idx].hint_idx;
		cfg->hints_block[cfg->block_idx].hints[*hints_idx] =
						strtoul(value, NULL, 0);
		*hints_idx = *hints_idx + 1;
	} else if (MATCH("hint_addresses_test", "size")) {
		cfg->hints_block[cfg->block_idx].size =	strtoul(value, NULL, 0);
	}

	return 1;
}

void hint_addresses_test(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hints_addr_cfg cfg = {0};
	struct hints_param *param;
	uint64_t device_map_addr, device_handle, page_offset;
	const char *config_filename = hltests_get_config_filename();
	void *ptr;
	int i, idx, fd = tests_state->fd, ret;
	bool test_failed = false;

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("hints memory test need to be run with -d flag\n");
		return;
	}

	if (!config_filename)
		fail_msg("User didn't supply a configuration file name!\n");

	cfg.block_idx = 0;
	cfg.blocks_count = 0;

	if (ini_parse(config_filename, test_hint_addresses_parsing_handler,
						&cfg))
		fail_msg("Can't load %s\n", config_filename);

	printf("Configuration loaded from %s:\n", config_filename);

	/* validity checks for config file */
	if (cfg.blocks_count != BLOCKS_NUM)
		fail_msg("Bad config file, see example in hlthunk_tests.ini\n");

	for (i = 0 ; i < BLOCKS_NUM ; i++) {
		param = &cfg.hints_block[i];
		if (param->num_of_hints != param->hint_idx)
			fail_msg
			("Bad config file, see example in hlthunk_tests.ini\n");
	}

	for (i = 0 ; i < BLOCKS_NUM ; i++) {
		param = &cfg.hints_block[i];
		printf("block(%d):\nnum_of_hints: %u, hint_idx: %u, type: %s,"
				" size: 0x%x\n",
				i, param->num_of_hints, param->hint_idx,
				param->type ? "DRAM" : "HOST", param->size);
		for (idx = 0 ; idx < param->num_of_hints ; idx++)
			printf("hint(%u): 0x%lx\n", idx, param->hints[idx]);
	}

	for (i = 0 ; i < BLOCKS_NUM ; i++) {
		param = &cfg.hints_block[i];
		if (param->type == HOST_ADDR) {
			for (idx = 0 ; idx < param->num_of_hints ; idx++) {
				ptr = malloc(param->size);
				assert_non_null(ptr);

				page_offset = (uintptr_t)ptr & PAGE_OFFSET_MASK;

				device_map_addr = hlthunk_host_memory_map(fd,
						ptr, param->hints[idx],
						param->size);
				if (device_map_addr !=
					((param->hints[idx] & ~PAGE_OFFSET_MASK)
							+ page_offset)) {
					printf("host hint %lx was ignored, "
							"mapped addr 0x%lx\n",
							param->hints[idx],
							device_map_addr);
					test_failed = true;
				}

				ret = hlthunk_memory_unmap(fd, device_map_addr);
				assert_int_equal(ret, 0);

				free(ptr);
			}
		} else {
			for (idx = 0 ; idx < param->num_of_hints ; idx++) {
				device_handle = hlthunk_device_memory_alloc(fd,
					param->size, NOT_CONTIGUOUS, false);
				assert_non_null(device_handle);

				device_map_addr = hlthunk_device_memory_map(fd,
						device_handle,
						param->hints[idx]);
				if (device_map_addr != param->hints[idx]) {
					printf("device hint %lx was ignored, "
							"mapped addr 0x%lx\n",
							param->hints[idx],
							device_map_addr);
					test_failed = true;
				}

				ret = hlthunk_memory_unmap(fd, device_map_addr);
				assert_int_equal(ret, 0);

				ret = hlthunk_device_memory_free(fd,
						device_handle);
				assert_int_equal(ret, 0);
			}
		}
	}

	for (i = 0 ; i < BLOCKS_NUM ; i++)
		free(cfg.hints_block[i].hints);

	if (test_failed)
		fail_msg("hints test failed\n");
}

const struct CMUnitTest memory_tests[] = {
	cmocka_unit_test_setup(test_map_bigger_than_4GB,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_alloc_device_mem_until_full,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_alloc_device_mem_until_full_contiguous,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_submit_after_unmap,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_submit_and_close,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(hint_addresses_test,
					hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"memory [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(memory_tests) / sizeof((memory_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE,
			memory_tests, num_tests);

	return hltests_run_group_tests("memory", memory_tests, num_tests,
					hltests_setup, hltests_teardown);
}
