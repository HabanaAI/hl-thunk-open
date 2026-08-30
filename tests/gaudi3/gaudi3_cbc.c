// SPDX-License-Identifier: MIT

/*
 * Copyright 2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "gaudi3/gaudi3.h"
#include "gaudi3/asic_reg/gaudi3_regs.h"

#include <stdio.h>
#include <unistd.h>

#define CBC_CACHE_LINE_SIZE		SZ_128
#define CBC_INVALIDATION_STATUS_DONE	0x2

enum gaudi3_cbc_range {
	CBC_RANGE_0,
	CBC_RANGE_1,
	CBC_RANGE_2,
	CBC_RANGE_3,
	CBC_ALL_RANGES
};

enum gaudi3_cbc_registers_set {
	CBC_REGISTERS_SET_0,
	CBC_REGISTERS_SET_1,
	CBC_REGISTERS_SET_2,
	CBC_REGISTERS_SET_3,
	CBC_REGISTERS_SET_4
};

static struct gaudi3_cbc_range_regs_offsets {
	uint64_t range_en;
	uint64_t range_min_lo;
	uint64_t range_min_hi;
	uint64_t range_max_lo;
	uint64_t range_max_hi;
} gaudi3_cbc_range_regs_offsets_array[NUM_OF_CBC_RANGES] = {
	[CBC_RANGE_0] = {
		mmCBC_USER_CBC_RANGE_EN_0,
		mmCBC_USER_CBC_RANGE_MIN_LO_0,
		mmCBC_USER_CBC_RANGE_MIN_HI_0,
		mmCBC_USER_CBC_RANGE_MAX_LO_0,
		mmCBC_USER_CBC_RANGE_MAX_HI_0
	},
	[CBC_RANGE_1] = {
		mmCBC_USER_CBC_RANGE_EN_1,
		mmCBC_USER_CBC_RANGE_MIN_LO_1,
		mmCBC_USER_CBC_RANGE_MIN_HI_1,
		mmCBC_USER_CBC_RANGE_MAX_LO_1,
		mmCBC_USER_CBC_RANGE_MAX_HI_1
	},
	[CBC_RANGE_2] = {
		mmCBC_USER_CBC_RANGE_EN_2,
		mmCBC_USER_CBC_RANGE_MIN_LO_2,
		mmCBC_USER_CBC_RANGE_MIN_HI_2,
		mmCBC_USER_CBC_RANGE_MAX_LO_2,
		mmCBC_USER_CBC_RANGE_MAX_HI_2
	},
	[CBC_RANGE_3] = {
		mmCBC_USER_CBC_RANGE_EN_3,
		mmCBC_USER_CBC_RANGE_MIN_LO_3,
		mmCBC_USER_CBC_RANGE_MIN_HI_3,
		mmCBC_USER_CBC_RANGE_MAX_LO_3,
		mmCBC_USER_CBC_RANGE_MAX_HI_3
	}
};

static struct gaudi3_cbc_invalidation_regs_offsets {
	uint64_t invalid_en;
	uint64_t invalid_ctrl;
	uint64_t invalid_status;
	uint64_t lbw_addr;
	uint64_t lbw_data;
} gaudi3_cbc_invalidation_regs_offsets_array[NUM_OF_CBC_INVALIDATION_REGS_SETS] = {
	[CBC_REGISTERS_SET_0] = {
		mmCBC_USER_INVALID_EN_0,
		mmCBC_USER_INVALID_CTRL_0,
		mmCBC_USER_INVALID_STATUS_0,
		mmCBC_USER_LBW_ADDR_0,
		mmCBC_USER_LBW_DATA_0
	},
	[CBC_REGISTERS_SET_1] = {
		mmCBC_USER_INVALID_EN_1,
		mmCBC_USER_INVALID_CTRL_1,
		mmCBC_USER_INVALID_STATUS_1,
		mmCBC_USER_LBW_ADDR_1,
		mmCBC_USER_LBW_DATA_1
	},
	[CBC_REGISTERS_SET_2] = {
		mmCBC_USER_INVALID_EN_2,
		mmCBC_USER_INVALID_CTRL_2,
		mmCBC_USER_INVALID_STATUS_2,
		mmCBC_USER_LBW_ADDR_2,
		mmCBC_USER_LBW_DATA_2
	},
	[CBC_REGISTERS_SET_3] = {
		mmCBC_USER_INVALID_EN_3,
		mmCBC_USER_INVALID_CTRL_3,
		mmCBC_USER_INVALID_STATUS_3,
		mmCBC_USER_LBW_ADDR_3,
		mmCBC_USER_LBW_DATA_3
	},
	[CBC_REGISTERS_SET_4] = {
		mmCBC_USER_INVALID_EN_4,
		mmCBC_USER_INVALID_CTRL_4,
		mmCBC_USER_INVALID_STATUS_4,
		mmCBC_USER_LBW_ADDR_4,
		mmCBC_USER_LBW_DATA_4
	}
};

static VOID test_cbc_prepare_sm_for_completion(int fd, uint16_t interrupt_id, uint16_t sob,
						uint32_t sob_val, uint32_t mon_payload,
						struct hltests_cb *cq_cb)
{
	struct hltests_cq_config cq_config;
	struct hltests_monitor mon_info;
	uint32_t cb_size, dma_qid;
	uint64_t cq_device_va;
	uint16_t mon, cq_id;
	void *cb;
	int rc;

	mon = hltests_get_first_avail_mon(fd);
	cq_id = hltests_get_first_avail_cq(fd);

	hltests_clear_sobs(fd, 1);

	cb = hltests_create_cb(fd, 0x1000, CB_TYPE_USER, 0);
	assert_non_null(cb);
	cb_size = 0;
	dma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	/* Prepare buffer for CQ */
	memset(cq_cb, 0, sizeof(*cq_cb));
	cq_cb->cb_size = sizeof(uint32_t);
	rc = hlthunk_request_mapped_command_buffer(fd, cq_cb->cb_size, &cq_cb->cb_handle);
	assert_int_equal(rc, 0);
	cq_cb->ptr = hltests_mmap(fd, cq_cb->cb_size, (off_t)cq_cb->cb_handle);
	assert_ptr_not_equal(cq_cb->ptr, MAP_FAILED);
	rc = hlthunk_get_mapped_cb_device_va_by_handle(fd, cq_cb->cb_handle, &cq_device_va);
	assert_int_equal(rc, 0);
	*(uint32_t *) cq_cb->ptr = 0;

	/* Configure CQ */
	memset(&cq_config, 0, sizeof(cq_config));
	cq_config.fd = fd;
	cq_config.qid = dma_qid;
	cq_config.cq_address = cq_device_va;
	cq_config.cq_size_log2 = 2;
	cq_config.cq_id = cq_id;
	cq_config.interrupt_id = interrupt_id;
	cq_config.inc_mode = 0;
	cb_size = hltests_add_cq_config_pkt(fd, cb, cb_size, &cq_config);

	/* Configure monitor */
	memset(&mon_info, 0, sizeof(mon_info));
	mon_info.qid = dma_qid;
	mon_info.sob_id = sob;
	mon_info.mon_id = mon;
	mon_info.sob_val = sob_val;
	mon_info.mon_payload = mon_payload;
	mon_info.cq_enable = 1;
	mon_info.cq_id = u8_safe(cq_id);
	mon_info.mon_mode = SOB_EQUAL;
	cb_size = hltests_add_monitor(fd, cb, cb_size, &mon_info);

	hltests_submit_and_wait_cs(fd, cb, cb_size, dma_qid, DESTROY_CB_TRUE,
					HL_WAIT_CS_STATUS_COMPLETED);

	END_TEST;
}

static VOID test_cbc_release_cq_cb(int fd, struct hltests_cb *cq_cb)
{
	int rc;

	rc = hltests_munmap(fd, cq_cb->ptr, cq_cb->cb_size);
	assert_int_equal(rc, 0);
	rc = hlthunk_destroy_command_buffer(fd, cq_cb->cb_handle);
	assert_int_equal(rc, 0);

	END_TEST;
}

static VOID test_cbc_invalidate_range(int fd, enum gaudi3_cbc_range range,
					uint8_t *cbc_user_start_addr,
					enum gaudi3_cbc_registers_set registers_set)
{
	struct gaudi3_cbc_invalidation_regs_offsets *regs_offsets;
	uint32_t ctrl, lbw_addr, lbw_data, target_value, status;
	uint16_t interrupt_id, sob;
	struct hltests_cb cq_cb;
	void *cbc_user_addr;
	uint64_t sob_addr;
	int rc;

	interrupt_id = hltests_get_first_avail_interrupt(fd);
	sob = hltests_get_first_avail_sob(fd);
	lbw_data = 0x1;
	target_value = 0x1;
	test_cbc_prepare_sm_for_completion(fd, interrupt_id, sob, lbw_data, target_value, &cq_cb);

	regs_offsets = &gaudi3_cbc_invalidation_regs_offsets_array[registers_set];

	/* CBC_USER.INVALID_CTRL */
	cbc_user_addr = cbc_user_start_addr + regs_offsets->invalid_ctrl;
	ctrl = (range == CBC_ALL_RANGES) ?
			FIELD_PREP((uint32_t)CBC_USER_INVALID_CTRL_ALL_M, 0x1) :
			FIELD_PREP((uint32_t)CBC_USER_INVALID_CTRL_RANGE_M, range);
	rc = hltests_write_lbw_reg(fd, cbc_user_addr, ctrl);
	assert_int_equal(rc, 0);

	/* CBC_USER.LBW_ADDR */
	cbc_user_addr = cbc_user_start_addr + regs_offsets->lbw_addr;
	sob_addr = hltests_get_sob_base_addr(fd) + sob * sizeof(uint32_t);
	lbw_addr = lower_32_bits(sob_addr - LBW_BASE);
	rc = hltests_write_lbw_reg(fd, cbc_user_addr, lbw_addr);
	assert_int_equal(rc, 0);

	/* CBC_USER.LBW_DATA */
	cbc_user_addr = cbc_user_start_addr + regs_offsets->lbw_data;
	rc = hltests_write_lbw_reg(fd, cbc_user_addr, lbw_data);
	assert_int_equal(rc, 0);

	/* CBC_USER.INVALID_EN */
	cbc_user_addr = cbc_user_start_addr + regs_offsets->invalid_en;
	rc = hltests_write_lbw_reg(fd, cbc_user_addr, 0x1);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_interrupt_by_handle(fd, cq_cb.cb_handle, 0, target_value,
							interrupt_id, WAIT_FOR_CS_DEFAULT_TIMEOUT);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	/* CBC_USER.INVALID_STATUS */
	cbc_user_addr = cbc_user_start_addr + regs_offsets->invalid_status;
	rc = hltests_read_lbw_reg(fd, cbc_user_addr, &status);
	assert_int_equal(rc, 0);
	assert_int_equal(status, CBC_INVALIDATION_STATUS_DONE);

	test_cbc_release_cq_cb(fd, &cq_cb);

	END_TEST;
}

static VOID test_cbc_disable_range(int fd, enum gaudi3_cbc_range range,
					uint8_t *cbc_user_start_addr)
{
	struct gaudi3_cbc_range_regs_offsets *regs_offsets;
	void *cbc_user_addr;
	uint32_t range_mask;
	int i, rc;

	range_mask = (uint32_t)((range == CBC_ALL_RANGES) ? GENMASK(NUM_OF_CBC_RANGES - 1, 0) :
							    BIT(range));

	for (i = 0 ; i < NUM_OF_CBC_RANGES ; i++) {
		if (!(range_mask & BIT(i)))
			continue;

		regs_offsets = &gaudi3_cbc_range_regs_offsets_array[i];

		/* CBC_USER.CBC_RANGE_EN */
		cbc_user_addr = cbc_user_start_addr + regs_offsets->range_en;
		rc = hltests_write_lbw_reg(fd, cbc_user_addr, 0x0);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

static VOID test_cbc_configure_range(int fd, enum gaudi3_cbc_range range, uint64_t range_addr_min,
					uint64_t range_addr_max, uint8_t *cbc_user_start_addr)
{
	struct gaudi3_cbc_range_regs_offsets *regs_offsets;
	void *cbc_user_addr;
	uint32_t range_mask;
	int i, rc;

	range_mask = (uint32_t)((range == CBC_ALL_RANGES) ? GENMASK(NUM_OF_CBC_RANGES - 1, 0) :
							    BIT(range));

	for (i = CBC_RANGE_0 ; i < NUM_OF_CBC_RANGES ; i++) {
		if (!(range_mask & BIT(i)))
			continue;

		regs_offsets = &gaudi3_cbc_range_regs_offsets_array[i];

		/* CBC_USER.RANGE_MIN_LO */
		cbc_user_addr = cbc_user_start_addr + regs_offsets->range_min_lo;
		rc = hltests_write_lbw_reg(fd, cbc_user_addr, lower_32_bits(range_addr_min));
		assert_int_equal(rc, 0);

		/* CBC_USER.RANGE_MIN_HI */
		cbc_user_addr = cbc_user_start_addr + regs_offsets->range_min_hi;
		rc = hltests_write_lbw_reg(fd, cbc_user_addr, upper_32_bits(range_addr_min));
		assert_int_equal(rc, 0);

		/* CBC_USER.RANGE_MAX_LO */
		cbc_user_addr = cbc_user_start_addr + regs_offsets->range_max_lo;
		rc = hltests_write_lbw_reg(fd, cbc_user_addr, lower_32_bits(range_addr_max));
		assert_int_equal(rc, 0);

		/* CBC_USER.RANGE_MAX_HI */
		cbc_user_addr = cbc_user_start_addr + regs_offsets->range_max_hi;
		rc = hltests_write_lbw_reg(fd, cbc_user_addr, upper_32_bits(range_addr_max));
		assert_int_equal(rc, 0);

		/* CBC_USER.CBC_RANGE_EN */
		cbc_user_addr = cbc_user_start_addr + regs_offsets->range_en;
		rc = hltests_write_lbw_reg(fd, cbc_user_addr, 0x1);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_cbc_dma_down_transfer(int fd, uint32_t dma_down_qid, uint64_t src_addr, uint64_t dst_addr,
				uint32_t size, enum hltests_dma_direction dma_dir)
{
	uint32_t dma_size;
	int rc;

	/* Non-128B transactions skip the CBC, but the DMA engine can generate larger transactions.
	 * To make sure the CBC isn't skipped, split the transaction into several 128B transactions.
	 */

	assert_int_not_equal(size, 0);
	dma_size = CBC_CACHE_LINE_SIZE;
	assert_int_equal(size % dma_size, 0);

	while (size) {
		rc = hltests_dma_transfer(fd, dma_down_qid, EB_FALSE, MB_FALSE, src_addr, dst_addr,
					dma_size, dma_dir);
		assert_int_equal(rc, 0);

		src_addr += dma_size;
		dst_addr += dma_size;
		size -= dma_size;
	}

	END_TEST;
}

static VOID _test_cbc_single_range(void **state, enum gaudi3_cbc_range range,
					enum gaudi3_cbc_registers_set registers_set)
{
	uint32_t cbc_user_block_size, size, align, dma_down_qid, dma_up_qid;
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t device_addr = 0x0, host_src_device_va, host_dst_device_va;
	void *dram_ptr = NULL, *src_ptr, *orig_mem_ptr, *dst_ptr;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int rc, fd = tests_state->fd;
	uint8_t *cbc_user_host_addr;

	/* Test description:
	 * - Configure a CBC range.
	 * - DMA host->device using a VA from the CBC range. The host memory will be cached in CBC.
	 * - Modify the content of the host memory.
	 * - DMA host->device using the same VA. The previously cached memory in CBC will be used.
	 * - DMA device->host. Memory should be identical to the initial content of the host memory.
	 * - Invalidate the CBC range.
	 * - DMA host->device using the same VA. The host memory will be accessed again.
	 * - DMA device->host. Memory should be identical to the latter content of the host memory.
	 */

	size = align = CBC_CACHE_LINE_SIZE;

	if (hw_ip->dram_enabled) {
		dram_ptr = hltests_allocate_device_mem(fd, size, 0, NOT_CONTIGUOUS);
		assert_non_null(dram_ptr);
		device_addr = (uint64_t) (uintptr_t) dram_ptr;
	} else if (hw_ip->sram_size) {
		device_addr = hw_ip->sram_base_address;
	} else {
		printf("No device memory is available, skipping\n");
		skip();
	}

	cbc_user_host_addr = hltests_map_hw_block(fd, mmD0_PMMU_CBC_USER_BASE,
							&cbc_user_block_size);
	assert_non_null(cbc_user_host_addr);

	/* Disable and invalidate all CBC ranges before actual test */
	test_cbc_disable_range(fd, CBC_ALL_RANGES, cbc_user_host_addr);
	test_cbc_invalidate_range(fd, CBC_ALL_RANGES, cbc_user_host_addr, CBC_REGISTERS_SET_0);

	/* Allocate and map host memory buffers */
	src_ptr = hltests_allocate_host_mem_aligned(fd, size, NOT_HUGE_MAP, align);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, size);
	host_src_device_va = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, size, NOT_HUGE_MAP);
	assert_non_null(dst_ptr);
	memset(dst_ptr, 0, size);
	host_dst_device_va = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	orig_mem_ptr = hlthunk_malloc(size);
	assert_non_null(orig_mem_ptr);
	memcpy(orig_mem_ptr, src_ptr, size);

	/* Configure a CBC range */
	test_cbc_configure_range(fd, range, host_src_device_va, host_src_device_va + size - 1,
					cbc_user_host_addr);

	dma_down_qid = hltests_get_dma_down_qid(fd, STREAM0);
	dma_up_qid = hltests_get_dma_up_qid(fd, STREAM0);

	/* DMA host->device. Host memory will be cached in CBC. */
	test_cbc_dma_down_transfer(fd, dma_down_qid, host_src_device_va, device_addr, size,
					DMA_DIR_HOST_TO_DRAM);

	/* Modify the content of the host memory */
	hltests_fill_rand_values(src_ptr, size);

	/* DMA host->device. The previously cached memory in CBC will be used. */
	test_cbc_dma_down_transfer(fd, dma_down_qid, host_src_device_va, device_addr, size,
					DMA_DIR_HOST_TO_DRAM);

	/* DMA device->host and compare host memories */
	rc = hltests_dma_transfer(fd, dma_up_qid, EB_FALSE, MB_FALSE, device_addr,
					host_dst_device_va, size, DMA_DIR_DRAM_TO_HOST);
	assert_int_equal(rc, 0);

	rc = hltests_mem_compare(orig_mem_ptr, dst_ptr, size);
	assert_int_equal(rc, 0);

	/* Invalidate the CBC range */
	test_cbc_invalidate_range(fd, range, cbc_user_host_addr, registers_set);

	/* DMA host->device. The host memory will be accessed again. */
	test_cbc_dma_down_transfer(fd, dma_down_qid, host_src_device_va, device_addr, size,
					DMA_DIR_HOST_TO_DRAM);

	/* DMA device->host and compare host memories */
	rc = hltests_dma_transfer(fd, dma_up_qid, EB_FALSE, MB_FALSE, device_addr,
					host_dst_device_va, size, DMA_DIR_DRAM_TO_HOST);
	assert_int_equal(rc, 0);

	rc = hltests_mem_compare(src_ptr, dst_ptr, size);
	assert_int_equal(rc, 0);

	/* Cleanup */
	hlthunk_free(orig_mem_ptr);

	rc = hltests_free_host_mem(fd, dst_ptr);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, src_ptr);
	assert_int_equal(rc, 0);

	rc = hltests_unmap_hw_block(fd, cbc_user_host_addr, cbc_user_block_size);
	assert_int_equal(rc, 0);

	if (hw_ip->dram_enabled) {
		rc = hltests_free_device_mem(fd, dram_ptr);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_cbc_single_range(void **state)
{
	if (hltests_get_parser_mini_suite())
		skip();

	CALL_HELPER_FUNC(_test_cbc_single_range(state, CBC_RANGE_0, CBC_REGISTERS_SET_4));
	CALL_HELPER_FUNC(_test_cbc_single_range(state, CBC_RANGE_1, CBC_REGISTERS_SET_3));
	CALL_HELPER_FUNC(_test_cbc_single_range(state, CBC_RANGE_2, CBC_REGISTERS_SET_2));
	CALL_HELPER_FUNC(_test_cbc_single_range(state, CBC_RANGE_3, CBC_REGISTERS_SET_1));

	END_TEST;
}

static VOID _test_cbc_multiple_ranges(void **state, enum gaudi3_cbc_range range0,
					enum gaudi3_cbc_range range1,
					enum gaudi3_cbc_registers_set registers_set)
{
	uint32_t cbc_user_block_size, total_size, range_size, align, dma_down_qid, dma_up_qid;
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t device_addr = 0x0, host_src_device_va, host_dst_device_va;
	void *dram_ptr = NULL, *src_ptr, *orig_mem_ptr, *dst_ptr;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int rc, fd = tests_state->fd;
	uint8_t *cbc_user_host_addr;

	/* Test description:
	 * - Configure 2 CBC ranges.
	 * - DMA host->device using VAs from the CBC ranges. The host memory will be cached in CBC.
	 * - Modify the content of the host memory.
	 * - Invalidate the first CBC range.
	 * - DMA host->device using the same VAs.
	 * - DMA device->host.
	 *   First range - memory should be identical to the latter content of the host memory.
	 *   Second range - memory should be identical to the initial content of the host memory.
	 */

	assert_int_not_equal(range0, range1);

	range_size = align = CBC_CACHE_LINE_SIZE;
	total_size = 2 * range_size;

	if (hw_ip->dram_enabled) {
		dram_ptr = hltests_allocate_device_mem(fd, total_size, 0, NOT_CONTIGUOUS);
		assert_non_null(dram_ptr);
		device_addr = (uint64_t) (uintptr_t) dram_ptr;

	} else if (hw_ip->sram_size) {
		device_addr = hw_ip->sram_base_address;
	} else {
		printf("No device memory is available, skipping\n");
		skip();
	}

	cbc_user_host_addr = hltests_map_hw_block(fd, mmD0_PMMU_CBC_USER_BASE,
							&cbc_user_block_size);
	assert_non_null(cbc_user_host_addr);

	/* Disable and invalidate all CBC ranges before actual test */
	test_cbc_disable_range(fd, CBC_ALL_RANGES, cbc_user_host_addr);
	test_cbc_invalidate_range(fd, CBC_ALL_RANGES, cbc_user_host_addr, CBC_REGISTERS_SET_0);

	/* Allocate and map host memory buffers */
	src_ptr = hltests_allocate_host_mem_aligned(fd, total_size, NOT_HUGE_MAP, align);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, total_size);
	host_src_device_va = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, total_size, NOT_HUGE_MAP);
	assert_non_null(dst_ptr);
	memset(dst_ptr, 0, total_size);
	host_dst_device_va = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	orig_mem_ptr = hlthunk_malloc(total_size);
	assert_non_null(orig_mem_ptr);
	memcpy(orig_mem_ptr, src_ptr, total_size);

	/* Configure CBC ranges */
	test_cbc_configure_range(fd, range0, host_src_device_va,
					host_src_device_va + range_size - 1, cbc_user_host_addr);
	test_cbc_configure_range(fd, range1, host_src_device_va + range_size,
					host_src_device_va + total_size - 1, cbc_user_host_addr);

	dma_down_qid = hltests_get_dma_down_qid(fd, STREAM0);
	dma_up_qid = hltests_get_dma_up_qid(fd, STREAM0);

	/* DMA host->device. Host memory will be cached in CBC. */
	test_cbc_dma_down_transfer(fd, dma_down_qid, host_src_device_va, device_addr, total_size,
					DMA_DIR_HOST_TO_DRAM);

	/* Modify the content of the host memory */
	hltests_fill_rand_values(src_ptr, total_size);

	/* Invalidate the first CBC range */
	test_cbc_invalidate_range(fd, range0, cbc_user_host_addr, registers_set);

	/* DMA host->device using the same VAs */
	test_cbc_dma_down_transfer(fd, dma_down_qid, host_src_device_va, device_addr, total_size,
					DMA_DIR_HOST_TO_DRAM);

	/* DMA device->host and compare host memories.
	 * First range - memory should be identical to the latter content of the host memory.
	 * Second range - memory should be identical to the initial content of the host memory.
	 */
	rc = hltests_dma_transfer(fd, dma_up_qid, EB_FALSE, MB_FALSE, device_addr,
					host_dst_device_va, total_size, DMA_DIR_DRAM_TO_HOST);
	assert_int_equal(rc, 0);

	rc = hltests_mem_compare(src_ptr, dst_ptr, range_size);
	assert_int_equal(rc, 0);
	rc = hltests_mem_compare((uint8_t *) orig_mem_ptr + range_size,
					(uint8_t *) dst_ptr + range_size, range_size);
	assert_int_equal(rc, 0);

	/* Cleanup */
	hlthunk_free(orig_mem_ptr);

	rc = hltests_free_host_mem(fd, dst_ptr);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, src_ptr);
	assert_int_equal(rc, 0);

	rc = hltests_unmap_hw_block(fd, cbc_user_host_addr, cbc_user_block_size);
	assert_int_equal(rc, 0);

	if (hw_ip->dram_enabled) {
		rc = hltests_free_device_mem(fd, dram_ptr);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_cbc_multiple_ranges(void **state)
{
	if (hltests_get_parser_mini_suite())
		skip();

	CALL_HELPER_FUNC(_test_cbc_multiple_ranges(state, CBC_RANGE_0, CBC_RANGE_1,
				CBC_REGISTERS_SET_1));
	CALL_HELPER_FUNC(_test_cbc_multiple_ranges(state, CBC_RANGE_1, CBC_RANGE_2,
				CBC_REGISTERS_SET_2));
	CALL_HELPER_FUNC(_test_cbc_multiple_ranges(state, CBC_RANGE_2, CBC_RANGE_3,
				CBC_REGISTERS_SET_3));
	CALL_HELPER_FUNC(_test_cbc_multiple_ranges(state, CBC_RANGE_3, CBC_RANGE_0,
				CBC_REGISTERS_SET_4));

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest gaudi3_cbc_tests[] = {
	cmocka_unit_test_setup(test_cbc_single_range, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cbc_multiple_ranges, hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"gaudi3_cbc [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	size_t num_tests = ARRAY_SIZE(gaudi3_cbc_tests);

	hltests_parser(argc, argv, usage,
		       HLTEST_DEVICE_MASK_GAUDI3_ALL, gaudi3_cbc_tests, (int)num_tests);

	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK | CAP_ARC_FW_LOAD_PDMA_MASK);

	return hltests_run_group_tests("gaudi3_cbc", gaudi3_cbc_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
