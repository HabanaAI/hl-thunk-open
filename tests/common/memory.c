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

#define is_power_of_2(x) (				\
{							\
	typeof(x) __x = (x);				\
	((__x > 0) && ((__x & (__x  - 1)) == 0));	\
}							\
)

#define PAGE_OFFSET_MASK	0xFFF
#define BLOCKS_NUM		2

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
VOID test_map_bigger_than_4GB(void **state)
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

	if (hltests_is_simulator(fd) && dma_size > hw_ip.dram_size) {
		printf(
			"SIM's DRAM (%lu[B]) is smaller than required allocation (%lu[B]) so skipping test\n",
			hw_ip.dram_size, dma_size);
		skip();
	}

	assert_in_range(dma_size, 1, hw_ip.dram_size);

	device_addr = hltests_allocate_device_mem(fd, dma_size, 0, NOT_CONTIGUOUS);
	assert_non_null(device_addr);

	dma_dir_down = DMA_DIR_HOST_TO_DRAM;
	dma_dir_up = DMA_DIR_DRAM_TO_HOST;

	src_ptr = hltests_allocate_host_mem(fd, total_size, NOT_HUGE_MAP);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, total_size);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, dma_size, NOT_HUGE_MAP);
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

	END_TEST;
}

VOID test_alloc_device_mem_until_full(void **state)
{
	END_TEST_FUNC(hltests_allocate_device_mem_until_full(state, 0, NOT_CONTIGUOUS, false));
}

VOID test_alloc_device_mem_until_full_contiguous(void **state)
{
	END_TEST_FUNC(hltests_allocate_device_mem_until_full(state, 0, CONTIGUOUS, false));
}

VOID test_alloc_device_mem_mixed_until_full(void **state)
{
	/* note that with mixed allocations page_size is don't care */
	END_TEST_FUNC(hltests_allocate_device_mem_until_full(state, 0, NOT_CONTIGUOUS, true));
}

VOID test_submit_after_unmap(void **state)
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

	if (!hw_ip.sram_size)
		skip();

	device_addr = (void *) (uintptr_t) hw_ip.sram_base_address;

	src_ptr = hltests_allocate_host_mem(fd, size, false);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, size);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	/* Cleanup */
	rc = hltests_free_host_mem(fd, src_ptr);
	assert_int_equal(rc, 0);

	/* DMA: host->device */
	END_TEST_FUNC(hltests_dma_transfer(fd,
			hltests_get_dma_down_qid(fd, STREAM0),
			EB_FALSE, MB_TRUE, host_src_addr,
			(uint64_t) (uintptr_t) device_addr,
			size, DMA_DIR_HOST_TO_SRAM));
}

VOID test_submit_and_close(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t seq, host_src_addr, size, cb_size, device_addr;
	struct hltests_cs_chunk execute_arr;
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info hw_ip;
	int i, rc, fd = tests_state->fd;
	uint32_t cb_offset = 0, dma_qid;
	void *src_ptr, *cb;

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("This test need to be run with -d flag\n");
		skip();
	}

	size = 0x1000;

	/* Sanity and memory allocation */
	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.sram_size)
		skip();

	device_addr = hw_ip.sram_base_address;

	src_ptr = hltests_allocate_host_mem(fd, size, false);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, size);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	cb_size = 0x200000 - 128;

	cb = hltests_create_cb(fd, cb_size, EXTERNAL, 0);
	assert_non_null(cb);

	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.src_addr = host_src_addr;
	pkt_info.dma.dst_addr = device_addr;
	pkt_info.dma.size = size;
	pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_SRAM;

	for (i = 0 ; i < (cb_size / 24) ; i++)
		cb_offset = hltests_add_dma_pkt(fd, cb, cb_offset, &pkt_info);

	execute_arr.cb_ptr = cb;
	execute_arr.cb_size = cb_offset;
	execute_arr.queue_index = dma_qid;

	rc = hltests_submit_cs(fd, NULL, 0, &execute_arr, 1, 0, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	END_TEST;
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

VOID test_hint_addresses(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	uint64_t device_map_addr, device_handle, page_offset;
	int i, idx, fd = tests_state->fd, ret;
	struct hints_addr_cfg cfg;
	struct hints_param *param;
	bool test_failed = false;
	void *ptr;

	memset((void *) &cfg, 0, sizeof(struct hints_addr_cfg));

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("hints memory test need to be run with -d flag\n");
		skip();
	}

	if (!config_filename)
		fail_msg("User didn't supply a configuration file name!\n");

	cfg.block_idx = 0;
	cfg.blocks_count = 0;

	if (ini_parse(config_filename, test_hint_addresses_parsing_handler,
						&cfg)) {
		printf("Can't load %s\n", config_filename);
		fail();
	}

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
					param->size, 0, NOT_CONTIGUOUS, false);
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

	END_TEST;
}

VOID test_dmmu_hint_address(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t dram_base_address, dram_page_size;
	struct hlthunk_hw_ip_info hw_ip;
	int rc, fd = tests_state->fd;

	if (!tests_state->mmu) {
		printf("Test can't run in case MMU is disabled, skipping "
		       "test\n");
		skip();
	}

	if (hltests_is_gaudi(fd)) {
		printf("Test can't run on Gaudi, skipping test\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	if (!hw_ip.dram_enabled) {
		printf("DRAM is disabled, skipping test\n");
		skip();
	}

	/* The dram_base_address is used for the hint address */
	dram_base_address = hw_ip.dram_base_address;
	dram_page_size = hw_ip.dram_page_size;

	/* Test with a non page aligned hint address */
	rc = hltests_mmu_hint_address(fd, dram_page_size, dram_base_address,
				      DRAM_ADDR, false);
	assert_int_equal(rc, 0);

	/* Test with a page aligned hint address */
	rc = hltests_mmu_hint_address(fd, dram_page_size, dram_base_address,
				      DRAM_ADDR, true);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_pmmu_hint_address(void **state, bool is_huge)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t page_size, device_map_addr, buf_size = SZ_16K;
	int rc, fd = tests_state->fd;
	void *host_ptr;

	if (!tests_state->mmu) {
		printf("Test can't run in case MMU is disabled, skipping "
		       "test\n");
		skip();
	}

	page_size = is_huge ? SZ_2M : SZ_4K;

	/* Allocate and map an host buffer just to get the relevant address
	 * range - is used for the hint address.
	 */
	host_ptr = hltests_allocate_host_mem(fd, buf_size, is_huge);
	assert_non_null(host_ptr);
	device_map_addr = hltests_get_device_va_for_host_ptr(fd, host_ptr);
	rc = hltests_free_host_mem(fd, host_ptr);
	assert_int_equal(rc, 0);

	/* Test with a non page aligned hint address */
	rc = hltests_mmu_hint_address(fd, page_size, device_map_addr, HOST_ADDR,
				      false);
	assert_int_equal(rc, 0);

	/* Test with a page aligned hint address */
	rc = hltests_mmu_hint_address(fd, page_size, device_map_addr, HOST_ADDR,
				      true);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_pmmu_hint_address_regular_page(void **state)
{
	END_TEST_FUNC(test_pmmu_hint_address(state, false));
}

VOID test_pmmu_hint_address_huge_page(void **state)
{
	END_TEST_FUNC(test_pmmu_hint_address(state, true));
}

/*
 * This test is relevant for asics with pmmu memcache, i.e. greco and gaudi2.
 * This test does the following:
 * 1. Allocate and release 3 contigious pages P1, P2, P3 - this ensures we have
 *    at least 2 of them in the same cache line, P1 and P2 or P2 and P3.
 * 2. Since we just did unmap, we also know the cache is currently empty.
 * 3. Allocate P1 and P3 using hints.
 * 4. Call dma on P1 and P3. This ensures P1 and P3 enter the cache.
 * 5. Now allocate P2. Validate that we can dma on P2.
 *
 * The potential problem this test checks is the corner case when P2, due to
 * being in the same cacheline as P1, stays in cache as invalid page, after
 * the user actually mapped it.
 */
VOID test_pdma_cache_lines_inconsistency(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk cs[1];
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info hw_ip;
	uint64_t host_va, dram_va, p1_va, p2_va, p3_va, seq;
	uint32_t host_page_size = 0x1000, cb_size, dma_qid,
		p1_off = 0, p2_off = host_page_size, p3_off = host_page_size * 2;
	void *host_ptr, *p1, *p2, *p3, *cb, *dram_ptr = NULL;
	int rc, fd = tests_state->fd;

	if (hltests_is_gaudi(fd) || hltests_is_goya(fd)) {
		printf("This test requires either gaudi2 or greco, skipping\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	/* Prepare device memory */
	if (hw_ip.dram_enabled) {
		dram_ptr = hltests_allocate_device_mem(fd, host_page_size, 0, CONTIGUOUS);
		assert_non_null(dram_ptr);
		dram_va = (uint64_t)(uintptr_t)dram_ptr;
	} else {
		if (!hw_ip.sram_size)
			skip();

		dram_va = hw_ip.sram_base_address;
	}

	/* Prepare command buffers, must be first */
	cb = hltests_create_cb(fd, host_page_size, EXTERNAL, 0);
	assert_non_null(cb);
	cb_size = 0;

	/*
	 * Allocate and map at least 3 pages. Then unmap immediately.
	 * This way we ensure we have enough contigious free virtual memory
	 * to respect hints.
	 * Throughout the code, we ensure that neigther p1 nor p2 nor p3 are
	 * 2MB aligned ON HOST.
	 * The problem with 2MB aligned pages for our scenario is that in this
	 * specific case, it may happen that the hint will be ignored on such
	 * page. This is due to another limitation in kernel, which will
	 * try to force 2MB alignment on device for such pages. While the hints
	 * we use may be not 2MB aligned, which will cause the driver to ignore
	 * them.
	 * To do this, for p1, p2 and p3 we always allocate 2 pages, but only
	 * use one of them, the one which is not 2MB aligned.
	 */
	host_ptr = mmap(NULL, 3 * host_page_size, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	assert_int_not_equal(host_ptr, MAP_FAILED);
	host_va = hlthunk_host_memory_map(fd, host_ptr, 0, 3 * host_page_size);
	assert_int_not_equal(host_va, 0);
	rc = hlthunk_memory_unmap(fd, host_va);
	assert_int_equal(rc, 0);
	munmap(host_ptr, 3 * host_page_size);

	/* Allocate and map P1 and P3 */
	p1 = mmap(NULL, 2 * host_page_size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	assert_int_not_equal(p1, MAP_FAILED);
	p1_va = hlthunk_host_memory_map_flags(fd,
		((uint64_t)p1 % SZ_2M) ? p1 : (char *)p1 + host_page_size,
		host_va + p1_off, host_page_size, HL_MEM_FORCE_HINT);
	assert_int_equal(p1_va, host_va + p1_off);

	p3 = mmap(NULL, 2 * host_page_size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	assert_int_not_equal(p3, MAP_FAILED);
	p3_va = hlthunk_host_memory_map_flags(fd,
		((uint64_t)p3 % SZ_2M) ? p3 : (char *)p3 + host_page_size,
		host_va + p3_off, host_page_size, HL_MEM_FORCE_HINT);
	assert_int_equal(p3_va, host_va + p3_off);

	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	/* DMA on P1 */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = p1_va;
	pkt_info.dma.dst_addr = dram_va;
	pkt_info.dma.size = host_page_size;
	pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_DRAM;
	cb_size = hltests_add_dma_pkt(fd, cb, cb_size, &pkt_info);

	cs[0].cb_ptr = cb;
	cs[0].cb_size = cb_size;
	cs[0].queue_index = dma_qid;

	rc = hltests_submit_cs(fd, NULL, 0, cs, 1, 0, &seq);
	assert_int_equal(rc, 0);
	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* DMA on P3 */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = p3_va;
	pkt_info.dma.dst_addr = dram_va;
	pkt_info.dma.size = host_page_size;
	pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_DRAM;
	cb_size = hltests_add_dma_pkt(fd, cb, cb_size, &pkt_info);

	cs[0].cb_ptr = cb;
	cs[0].cb_size = cb_size;
	cs[0].queue_index = dma_qid;

	rc = hltests_submit_cs(fd, NULL, 0, cs, 1, 0, &seq);
	assert_int_equal(rc, 0);
	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Allocate and map P2 */
	p2 = mmap(NULL, 2 * host_page_size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	assert_int_not_equal(p2, MAP_FAILED);
	p2_va = hlthunk_host_memory_map_flags(fd,
		((uint64_t)p2 % SZ_2M) ? p2 : (char *)p2 + host_page_size,
		host_va + p2_off, host_page_size, HL_MEM_FORCE_HINT);
	assert_int_equal(p2_va, host_va + p2_off);

	/* DMA on P2 */
	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = dma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.src_addr = p2_va;
	pkt_info.dma.dst_addr = dram_va;
	pkt_info.dma.size = host_page_size;
	pkt_info.dma.dma_dir = DMA_DIR_HOST_TO_DRAM;
	cb_size = hltests_add_dma_pkt(fd, cb, cb_size, &pkt_info);

	cs[0].cb_ptr = cb;
	cs[0].cb_size = cb_size;
	cs[0].queue_index = dma_qid;

	rc = hltests_submit_cs(fd, NULL, 0, cs, 1, 0, &seq);
	assert_int_equal(rc, 0);
	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* Cleanup */
	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);
	if (hw_ip.dram_enabled) {
		rc = hltests_free_device_mem(fd, dram_ptr);
		assert_int_equal(rc, 0);
	}
	rc = hlthunk_memory_unmap(fd, p1_va);
	assert_int_equal(rc, 0);
	rc = hlthunk_memory_unmap(fd, p2_va);
	assert_int_equal(rc, 0);
	rc = hlthunk_memory_unmap(fd, p3_va);
	assert_int_equal(rc, 0);
	munmap(p1, host_page_size);
	munmap(p2, host_page_size);
	munmap(p3, host_page_size);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest memory_tests[] = {
	cmocka_unit_test_setup(test_map_bigger_than_4GB,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_alloc_device_mem_until_full,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_alloc_device_mem_until_full_contiguous,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_alloc_device_mem_mixed_until_full,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_submit_after_unmap,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_submit_and_close,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_hint_addresses,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dmmu_hint_address,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_pmmu_hint_address_regular_page,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_pmmu_hint_address_huge_page,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_pdma_cache_lines_inconsistency,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"memory [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(memory_tests) / sizeof((memory_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE,
			memory_tests, num_tests);

	return hltests_run_group_tests("memory", memory_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
