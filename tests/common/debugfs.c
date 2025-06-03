// SPDX-License-Identifier: MIT

/*
 * Copyright 2021 HabanaLabs, Ltd.
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

#define SAMPLES 6

enum memory_region {
	MEM_REGION_DRAM,
	MEM_REGION_SRAM,
	MEM_REGION_FW_MEM,
	MEM_REGION_NUMBER,
};

static uint64_t sample_arr(int i, uint64_t n_long)
{
	switch (i) {
	case 0:
		return 0;
	case 1:
		return n_long / 4;
	case 2:
		return n_long / 2 - 1;
	case 3:
		return n_long / 2;
	case 4:
		return n_long / 2 + n_long / 4;
	case 5:
		return n_long - 1;
	default:
		fail_msg("index %d outside the range (0-%d)\n", i, SAMPLES - 1);
	}
	return 0;
}

static uint64_t val_arr(int i)
{
	switch (i) {
	case 0:
		return 0xdeadbadd;
	case 1:
		return 0x87654321;
	case 2:
		return 0xabcdef01;
	case 3:
		return 0xdebeaba1;
	case 4:
		return 0xdaf1a223;
	case 5:
		return 0xcabafaba;
	default:
		fail_msg("index %d outside the range (0-%d)\n", i, SAMPLES - 1);
	}
	return 0;
}

static int verify_host_mem(size_t n_long, void *host_mem, bool is_64)
{
	uint64_t sample, val;
	int i;

	for (i = 0; i < SAMPLES; i++) {
		sample = sample_arr(i, n_long);
		val = val_arr(i);
		if (is_64) {
			assert_int_equal(((uint64_t *) host_mem)[sample], val);
		} else {
			assert_int_equal(((uint32_t *) host_mem)[sample],
						(uint32_t) val);
		}
	}
	return 0;
}

static void write_to_mem_debugfs(struct hltests_state *tests_state,
	uint64_t virt_addr, size_t n_long, bool is_64)
{
	uint64_t sample, val;
	int i;

	for (i = 0; i < SAMPLES; i++) {
		sample = sample_arr(i, n_long);
		val = val_arr(i);
		if (is_64)
			WRITE64(virt_addr + sample * sizeof(uint64_t), val);
		else
			WRITE32(virt_addr + sample * sizeof(uint32_t), val);
	}
}

static int comp_virt_addr_with_host_ptr(struct hltests_state *tests_state,
		uint64_t virt_addr, void *ptr, size_t n_long, bool is_64)
{
	uint64_t sample, *mem64 = ptr;
	uint32_t *mem32 = ptr;
	int i;

	for (i = 0; i < SAMPLES; i++) {
		sample = sample_arr(i, n_long);
		if (is_64) {
			assert_int_equal(READ64(virt_addr + sample * sizeof(uint64_t)),
				mem64[sample]);
		} else {
			assert_int_equal(READ32(virt_addr + sample * sizeof(uint32_t)),
				mem32[sample]);
		}
	}
	return 0;
}

static int iommu_present(void **state, bool *present)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	char pci_bus_id[64], iommu_path[128];
	int rc;

	rc = hlthunk_get_pci_bus_id_from_fd(tests_state->fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc) {
		printf("No PCI device was found\n");
		return -ENODEV;
	}

	snprintf(iommu_path, 128, "/sys/bus/pci/devices/%s/iommu", pci_bus_id);
	if (access(iommu_path, F_OK) == 0)
		*present = true;
	else
		*present = false;
	return 0;
}

VOID test_read_write_host_debugfs(void **state, uint64_t size, bool is_64)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	void *host_ptr;
	uint64_t host_virt_addr;
	size_t n_long;
	bool has_iommu = false, is_huge = !!((size > SZ_32K) && (size < SZ_1G));
	int rc, fd = tests_state->fd;

	rc = iommu_present(state, &has_iommu);
	assert_int_equal(rc, 0);

	if (has_iommu) {
		printf("pci iommu exist therefore access host is not supported - skip\n");
		skip();
	}

	/*
	 * n_long describes the mem size by the units we sample
	 * (either 4 or 8 bytes)
	 */
	if (is_64)
		n_long = size / sizeof(uint64_t);
	else
		n_long = size / sizeof(uint32_t);

	host_ptr = hltests_allocate_host_mem(fd, size, is_huge);
	assert_non_null(host_ptr);
	host_virt_addr = hltests_get_device_va_for_host_ptr(fd, host_ptr);

	/* test1: fill host ptr with values and compare with host va addr */
	hltests_fill_rand_values(host_ptr, size);
	rc = comp_virt_addr_with_host_ptr(tests_state, host_virt_addr,
		host_ptr, n_long, is_64);
	assert_int_equal(rc, 0);

	/* test2: write values to host va and compare the host ptr with the values */
	memset(host_ptr, 0, size);
	write_to_mem_debugfs(tests_state, host_virt_addr, n_long, is_64);
	rc = verify_host_mem(n_long, host_ptr, is_64);
	assert_int_equal(rc, 0);

	/* Cleanup */
	rc = hltests_free_host_mem(fd, host_ptr);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_read_write_device_debugfs(void **state, enum memory_region mem_region,
				    uint64_t access_size, uint64_t alloc_size, bool is_64,
				    uint64_t offset, enum hltests_contiguous is_contiguous)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	void *device_addr, *src_ptr, *dst_ptr;
	uint64_t host_src_addr, host_dst_addr;
	uint32_t dma_dir_down, dma_dir_up;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int rc, fd = tests_state->fd;
	size_t n_long;
	bool is_huge;

	assert_in_range(mem_region, MEM_REGION_DRAM, MEM_REGION_NUMBER - 1);
	assert_in_range(access_size, 1, alloc_size);
	assert_in_range(offset + access_size, 1, hltests_get_total_avail_device_mem(fd));

	if (mem_region == MEM_REGION_FW_MEM) {
		if (hltests_is_gaudi3(fd)) {
			if (hltests_is_simulator(fd)) {
				printf("FW MEM is not supported on simulator - skip\n");
				skip();
			}
			printf("no access to fw mem since we run with preboot - skip\n");
			skip();
		} else {
			printf("FW MEM is not supported on this ASIC - skip\n");
			skip();
		}
	}

	is_huge = !!((alloc_size > SZ_32K) && (alloc_size < SZ_1G));

	/*
	 * n_long describes the mem size by the units we sample
	 * (either 4 or 8 bytes)
	 */
	if (is_64)
		n_long = access_size / sizeof(uint64_t);
	else
		n_long = access_size / sizeof(uint32_t);

	/* Sanity and memory allocation */
	switch (mem_region) {
	case MEM_REGION_DRAM:
		if (!hw_ip->dram_enabled) {
			printf("dram is disabled - skip\n");
			skip();
		}
		assert_in_range(alloc_size, sizeof(uint64_t), hw_ip->dram_size);

		device_addr = hltests_allocate_device_mem(fd, alloc_size, 0, is_contiguous);
		assert_non_null(device_addr);

		dma_dir_down = DMA_DIR_HOST_TO_DRAM;
		dma_dir_up = DMA_DIR_DRAM_TO_HOST;
		break;
	case MEM_REGION_SRAM:
		if (alloc_size > hw_ip->sram_size) {
			printf("size %#lx is bigger than sram size %#x - skip\n",
					alloc_size, hw_ip->sram_size);
			skip();
		}
		device_addr = (void *) (uintptr_t) hw_ip->sram_base_address;

		dma_dir_down = DMA_DIR_HOST_TO_SRAM;
		dma_dir_up = DMA_DIR_SRAM_TO_HOST;
		break;
	case MEM_REGION_FW_MEM:
	default:
		device_addr = (void *) (uintptr_t) hltests_get_fw_mem_addr(fd, alloc_size);
		assert_non_null(device_addr);

		dma_dir_down = DMA_DIR_HOST_TO_SRAM;
		dma_dir_up = DMA_DIR_SRAM_TO_HOST;
		break;
	}

	src_ptr = hltests_allocate_host_mem(fd, access_size, is_huge);
	assert_non_null(src_ptr);
	hltests_fill_rand_values(src_ptr, access_size);
	host_src_addr = hltests_get_device_va_for_host_ptr(fd, src_ptr);

	dst_ptr = hltests_allocate_host_mem(fd, access_size, is_huge);
	assert_non_null(dst_ptr);
	memset(dst_ptr, 0, access_size);
	host_dst_addr = hltests_get_device_va_for_host_ptr(fd, dst_ptr);

	/* DMA: host->device */
	rc = hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
		EB_FALSE, MB_FALSE, host_src_addr,
		(uint64_t) (uintptr_t) device_addr + offset,
		access_size, dma_dir_down);
	assert_int_equal(rc, 0);

	/* read from device mem and compare to host mem */
	rc = comp_virt_addr_with_host_ptr(tests_state, (uint64_t) device_addr + offset,
		src_ptr, n_long, is_64);
	assert_int_equal(rc, 0);

	/* write to device mem through debugfs */
	write_to_mem_debugfs(tests_state, (uint64_t) device_addr + offset, n_long, is_64);

	/* DMA: device->host */
	rc = hltests_dma_transfer(fd, hltests_get_dma_up_qid(fd, STREAM0),
		EB_FALSE, MB_FALSE, (uint64_t) (uintptr_t) device_addr + offset,
		host_dst_addr, access_size, dma_dir_up);
	assert_int_equal(rc, 0);

	/* compare host mem with the values we wrote to device */
	rc = verify_host_mem(n_long, dst_ptr, is_64);
	assert_int_equal(rc, 0);

	/* Cleanup */
	rc = hltests_free_host_mem(fd, dst_ptr);
	assert_int_equal(rc, 0);
	rc = hltests_free_host_mem(fd, src_ptr);
	assert_int_equal(rc, 0);

	if (mem_region == MEM_REGION_DRAM) {
		rc = hltests_free_device_mem(fd, device_addr);
		assert_int_equal(rc, 0);
	}

	END_TEST;
}

VOID test_read_write_dram_full_range_debugfs(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *)*state;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int fd = tests_state->fd;
	uint64_t dram_size = 0;

	if (!hltests_is_gaudi3(fd) || hltests_is_simulator(fd)) {
		printf("test supported only for gaudi3 asic");
		skip();
	}

	dram_size = hltests_get_total_avail_device_mem(fd);
	assert_in_range(dram_size, SZ_256M, hw_ip->dram_size);

	test_read_write_device_debugfs(state, MEM_REGION_DRAM, SZ_1K,
					dram_size, true, 0, CONTIGUOUS);

	test_read_write_device_debugfs(state, MEM_REGION_DRAM, SZ_1K,
					dram_size, true, dram_size - SZ_256M, CONTIGUOUS);

	test_read_write_device_debugfs(state, MEM_REGION_DRAM, SZ_32M,
					dram_size, true, dram_size - SZ_32M, CONTIGUOUS);

	END_TEST;
}

VOID test_dmmu_debugfs(struct hltests_state *tests_state, uint64_t hint_addr)
{
	uint64_t size, device_handle, device_va, host_va, sample, n_long;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int i, rc, fd = tests_state->fd;
	void *host_mem;

	if (hltests_is_gaudi(fd)) {
		printf("Test is not supported on Gaudi\n");
		skip();
	}

	if (!hw_ip->dram_enabled) {
		printf("dram is disabled - skip\n");
		skip();
	}

	size = 2 * hw_ip->device_mem_alloc_default_page_size;
	n_long = size / sizeof(uint64_t);

	host_mem = hltests_allocate_host_mem(fd, size, NOT_HUGE_MAP);
	assert_non_null(host_mem);
	host_va = hltests_get_device_va_for_host_ptr(fd, host_mem);
	hltests_fill_rand_values(host_mem, size);

	device_handle = hlthunk_device_memory_alloc(fd, size, 0, NOT_CONTIGUOUS, false);
	assert_int_not_equal(device_handle, 0);
	device_va = hlthunk_device_memory_map(fd, device_handle, hint_addr);
	assert_int_not_equal(device_handle, 0);

	rc = hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
			EB_FALSE, MB_FALSE, host_va, device_va,
			size, DMA_DIR_HOST_TO_DRAM);
	assert_int_equal(rc, 0);

	for (i = 0; i < SAMPLES; i++) {
		uint64_t *hmem = host_mem;

		sample = sample_arr(i, n_long);
		assert_int_equal(READ64(device_va + sample * sizeof(uint64_t)),
			hmem[sample]);
	}

	hlthunk_memory_unmap(fd, device_va);
	hlthunk_device_memory_free(fd, device_handle);
	hltests_free_host_mem(fd, host_mem);

	END_TEST;
}

VOID test_debugfs_dmmu_low_addresses(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;

	END_TEST_FUNC(test_dmmu_debugfs(tests_state, 0));
}

VOID test_debugfs_dmmu_high_addresses(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(fd)->asic_funcs;

	END_TEST_FUNC(test_dmmu_debugfs(tests_state, asic->get_dram_va_reserved_addr_start()));
}

VOID test_debugfs_read_write_host(void **state)
{
	END_TEST_FUNC(test_read_write_host_debugfs(state, SZ_1K, false));
}

VOID test_debugfs_read_write_host64(void **state)
{
	END_TEST_FUNC(test_read_write_host_debugfs(state, SZ_1K, true));
}

VOID test_debugfs_read_write_sram(void **state)
{
	END_TEST_FUNC(test_read_write_device_debugfs(state, MEM_REGION_SRAM, SZ_1K, SZ_1K, false, 0,
						     NOT_CONTIGUOUS));
}

VOID test_debugfs_read_write_dram(void **state)
{
	END_TEST_FUNC(test_read_write_device_debugfs(state, MEM_REGION_DRAM, SZ_1K, SZ_1K, false, 0,
						     NOT_CONTIGUOUS));
}

VOID test_debugfs_read_write_dram_full_range(void **state)
{
	END_TEST_FUNC(test_read_write_dram_full_range_debugfs(state));
}

VOID test_debugfs_read_write_fw_mem(void **state)
{
	END_TEST_FUNC(test_read_write_device_debugfs(state, MEM_REGION_FW_MEM, SZ_1K, SZ_1K, false,
						     0, NOT_CONTIGUOUS));
}

VOID test_debugfs_read_write_sram64(void **state)
{
	END_TEST_FUNC(test_read_write_device_debugfs(state, MEM_REGION_SRAM, SZ_1K, SZ_1K, true, 0,
						     NOT_CONTIGUOUS));
}

VOID test_debugfs_read_write_dram64(void **state)
{
	END_TEST_FUNC(test_read_write_device_debugfs(state, MEM_REGION_DRAM, SZ_1K, SZ_1K, true, 0,
						     NOT_CONTIGUOUS));
}

VOID test_debugfs_read_write_fw_mem64(void **state)
{
	END_TEST_FUNC(test_read_write_device_debugfs(state, MEM_REGION_FW_MEM, SZ_1K, SZ_1K, true,
						     0, NOT_CONTIGUOUS));
}
#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest debug_tests[] = {
		cmocka_unit_test_setup(test_debugfs_dmmu_low_addresses,
			hltests_ensure_device_operational),
		cmocka_unit_test_setup(test_debugfs_dmmu_high_addresses,
			hltests_ensure_device_operational),
		cmocka_unit_test_setup(test_debugfs_read_write_host,
			hltests_ensure_device_operational),
		cmocka_unit_test_setup(test_debugfs_read_write_host64,
			hltests_ensure_device_operational),
		cmocka_unit_test_setup(test_debugfs_read_write_sram,
			hltests_ensure_device_operational),
		cmocka_unit_test_setup(test_debugfs_read_write_dram,
			hltests_ensure_device_operational),
		cmocka_unit_test_setup(test_debugfs_read_write_fw_mem,
			hltests_ensure_device_operational),
		cmocka_unit_test_setup(test_debugfs_read_write_sram64,
			hltests_ensure_device_operational),
		cmocka_unit_test_setup(test_debugfs_read_write_dram64,
			hltests_ensure_device_operational),
		cmocka_unit_test_setup(test_debugfs_read_write_fw_mem64,
			hltests_ensure_device_operational),
		cmocka_unit_test_setup(test_debugfs_read_write_dram_full_range,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"debug [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = ARRAY_SIZE(debug_tests);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE, debug_tests, num_tests);

	if (!can_open_debugfs(true))
		return 0;

	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK | CAP_ARC_FW_LOAD_PDMA_MASK);
	return hltests_run_group_tests("debugfs", debug_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
