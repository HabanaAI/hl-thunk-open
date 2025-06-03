// SPDX-License-Identifier: MIT

/*
 * Copyright 2021 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "kvec.h"
#include "specs/common/importer_drv.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>

static int test_dmabuf_ibv_reg_dmabuf_mr(int imp_fd, uint64_t offset, uint64_t length,
						uint64_t iova, uint32_t dmabuf_fd,
						uint32_t access_flags, uint64_t *mr_handle)
{
	union hl_importer_reg_dmabuf_mr_args args;
	int rc;

	if (!mr_handle)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	args.in.offset = offset;
	args.in.length = length;
	args.in.iova = iova;
	args.in.fd = dmabuf_fd;
	args.in.access_flags = access_flags;

	rc = ioctl(imp_fd, HL_IMPORTER_IOCTL_REG_DMABUF_MR, &args);
	if (rc)
		return rc;

	*mr_handle = args.out.mr_handle;

	return 0;
}

static int test_dmabuf_ibv_dereg_mr(int imp_fd, uint64_t mr_handle)
{
	struct hl_importer_dereg_mr_args args;

	memset(&args, 0, sizeof(args));
	args.mr_handle = mr_handle;

	return ioctl(imp_fd, HL_IMPORTER_IOCTL_DEREG_MR, &args);
}

static int test_dmabuf_ibv_write_to_mr(int imp_fd, uint64_t mr_handle, void *userptr,
					uint32_t offset, uint32_t size)
{
	struct hl_importer_write_to_mr_args args;

	memset(&args, 0, sizeof(args));
	args.mr_handle = mr_handle;
	args.userptr = (uint64_t) (uintptr_t) userptr;
	args.size = size;
	args.offset = offset;

	return ioctl(imp_fd, HL_IMPORTER_IOCTL_WRITE_TO_MR, &args);
}

static int test_dmabuf_ibv_read_from_mr(int imp_fd, uint64_t mr_handle, void *userptr,
					uint32_t offset, uint32_t size)
{
	struct hl_importer_read_from_mr_args args;

	memset(&args, 0, sizeof(args));
	args.mr_handle = mr_handle;
	args.userptr = (uint64_t) (uintptr_t) userptr;
	args.size = size;
	args.offset = offset;

	return ioctl(imp_fd, HL_IMPORTER_IOCTL_READ_FROM_MR, &args);
}

static bool test_dmabuf_check_prerequisites(struct hltests_state *tests_state)
{
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	int fd = tests_state->fd, imp_fd = tests_state->imp_fd;

	if (hltests_is_pldm(fd)) {
		printf("Skipping test on PLDM\n");
		return false;
	}

	if (hltests_is_simulator(fd)) {
		printf("Skipping test on simulator\n");
		return false;
	}

	if (imp_fd < 0) {
		printf("Skipping test because importer device is missing\n");
		return false;
	}

	if (!hw_ip->dram_enabled) {
		printf("DRAM is disabled so skipping test\n");
		return false;
	}

	return true;
}

struct test_dmabuf_params {
	pthread_barrier_t *barrier;
	void *device_addr;
	uint32_t iterations;
	uint64_t export_offset;
	uint64_t export_size;
	uint32_t access_size;
	int fd;
	int imp_fd;
	bool verify_memory;
	bool random_offset;
};

static void *dmabuf_thread_start(void *args)
{
	struct test_dmabuf_params *params = (struct test_dmabuf_params *) args;
	uint64_t host_src_device_va, host_dst_device_va, mr_handle = 0,
			export_offset = params->export_offset, export_size = params->export_size,
			alloc_size = export_offset + export_size, export_addr;
	int rc, fd = params->fd, imp_fd = params->imp_fd, dmabuf_fd, i;
	uint32_t access_offset = 0, access_size = params->access_size;
	void *device_addr, *host_src, *host_dst;

	/* Allocate host/device memories */

	host_src = hltests_allocate_host_mem(fd, access_size, NOT_HUGE_MAP);
	if (!host_src)
		return NULL;
	host_src_device_va = hltests_get_device_va_for_host_ptr(fd, host_src);

	host_dst = hltests_allocate_host_mem(fd, access_size, NOT_HUGE_MAP);
	if (!host_dst)
		return NULL;
	host_dst_device_va = hltests_get_device_va_for_host_ptr(fd, host_dst);

	if (!params->device_addr) {
		device_addr = hltests_allocate_device_mem(fd, alloc_size, 0, NOT_CONTIGUOUS);
		if (!device_addr)
			return NULL;
	} else {
		device_addr = params->device_addr;
	}

	/* Export DMA-BUF and register MR */

	dmabuf_fd = hltests_device_memory_export_dmabuf_fd(fd, device_addr, export_size,
								export_offset);
	if (dmabuf_fd < 0)
		return NULL;

	export_addr = (uint64_t) (uintptr_t) device_addr + export_offset;

	rc = test_dmabuf_ibv_reg_dmabuf_mr(imp_fd, 0, export_size, 0, dmabuf_fd, 0, &mr_handle);
	if (rc)
		return NULL;

	/*
	 * PTHREAD_BARRIER_SERIAL_THREAD is returned to one unspecified thread
	 * and zero is returned to each of the remaining threads.
	 */
	rc = pthread_barrier_wait(params->barrier);
	if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD)
		return NULL;

	for (i = 0 ; i < params->iterations ; i++) {
		if (params->random_offset)
			access_offset = hltests_rand_u32() % (export_size - access_size);

		/* Write to MR */

		hltests_fill_rand_values(host_src, access_size);
		rc = test_dmabuf_ibv_write_to_mr(imp_fd, mr_handle, host_src, access_offset,
							access_size);
		if (rc)
			return NULL;

		if (params->verify_memory) {
			memset(host_dst, 0, access_size);
			rc = hltests_dma_transfer(fd, hltests_get_dma_up_qid(fd, STREAM0),
								EB_FALSE, MB_FALSE,
								export_addr + access_offset,
								host_dst_device_va, access_size,
								DMA_DIR_DRAM_TO_HOST);
			if (rc) {
				printf("%s dma transfer to host failed, rc = %d\n", __func__, rc);
				return NULL;
			}

			rc = hltests_mem_compare(host_src, host_dst, access_size);
			if (rc)
				return NULL;
		}

		/* Read from MR */

		if (params->verify_memory) {
			hltests_fill_rand_values(host_src, access_size);
			rc = hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
								EB_FALSE, MB_FALSE,
								host_src_device_va,
								export_addr + access_offset,
								access_size, DMA_DIR_HOST_TO_DRAM);
			if (rc) {
				printf("%s dma transfer to dram failed, rc = %d\n", __func__, rc);
				return NULL;
			}
		}

		memset(host_dst, 0, access_size);
		rc = test_dmabuf_ibv_read_from_mr(imp_fd, mr_handle, host_dst, access_offset,
							access_size);
		if (rc)
			return NULL;

		if (params->verify_memory) {
			rc = hltests_mem_compare(host_src, host_dst, access_size);
			if (rc)
				return NULL;
		}
	}

	/* Cleanup */

	rc = test_dmabuf_ibv_dereg_mr(imp_fd, mr_handle);
	if (rc)
		return NULL;

	rc = close(dmabuf_fd);
	if (rc)
		return NULL;

	if (!params->device_addr) {
		rc = hltests_free_device_mem(fd, device_addr);
		if (rc)
			return NULL;
	}

	rc = hltests_free_host_mem(fd, host_dst);
	if (rc)
		return NULL;

	rc = hltests_free_host_mem(fd, host_src);
	if (rc)
		return NULL;

	return args;
}

static VOID test_dmabuf_multiple_threads(void **state, uint32_t num_of_threads, uint32_t iterations,
				uint64_t export_offset, uint64_t export_size, uint32_t access_size,
				bool shared_device_memory, bool random_offset)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t alloc_size = export_offset + export_size;
	struct test_dmabuf_params *thread_params;
	void *device_addr = NULL, *retval;
	int rc, i, fd = tests_state->fd;
	pthread_barrier_t barrier;
	pthread_t *thread_id;

	if (!test_dmabuf_check_prerequisites(tests_state))
		skip();

	assert_in_range(access_size, 1, export_size);

	thread_params = hlthunk_malloc(num_of_threads * sizeof(*thread_params));
	assert_non_null(thread_params);

	thread_id = hlthunk_malloc(num_of_threads * sizeof(*thread_id));
	assert_non_null(thread_id);

	rc = pthread_barrier_init(&barrier, NULL, num_of_threads);
	assert_int_equal(rc, 0);

	if (shared_device_memory) {
		device_addr = hltests_allocate_device_mem(fd, alloc_size, 0, NOT_CONTIGUOUS);
		assert_non_null(device_addr);
	}

	/* Create and execute threads */
	for (i = 0 ; i < num_of_threads ; i++) {
		thread_params[i].barrier = &barrier;
		thread_params[i].device_addr = device_addr;
		thread_params[i].iterations = iterations;
		thread_params[i].export_offset = export_offset;
		thread_params[i].export_size = export_size;
		thread_params[i].access_size = access_size;
		thread_params[i].fd = fd;
		thread_params[i].imp_fd = tests_state->imp_fd;
		thread_params[i].verify_memory = !shared_device_memory;
		thread_params[i].random_offset = random_offset;

		rc = pthread_create(&thread_id[i], NULL, dmabuf_thread_start,
					&thread_params[i]);
		assert_int_equal(rc, 0);
	}

	/* Wait for the termination of the threads */
	for (i = 0 ; i < num_of_threads ; i++) {
		rc = pthread_join(thread_id[i], &retval);
		assert_int_equal(rc, 0);
		assert_non_null(retval);
	}

	/* Cleanup */
	if (shared_device_memory) {
		rc = hltests_free_device_mem(fd, device_addr);
		assert_int_equal(rc, 0);
	}
	pthread_barrier_destroy(&barrier);
	hlthunk_free(thread_id);
	hlthunk_free(thread_params);

	END_TEST;
}

VOID test_dmabuf_basic(void **state)
{
	END_TEST_FUNC(test_dmabuf_multiple_threads(state, 1, 1, 0, SZ_32M, SZ_4K, false, false));
}

VOID test_dmabuf_multiple_threads_non_shared_memory(void **state)
{
	END_TEST_FUNC(test_dmabuf_multiple_threads(state, 15, 10, 0, SZ_32M, SZ_4K, false, true));
}

VOID test_dmabuf_multiple_threads_shared_memory(void **state)
{
	END_TEST_FUNC(test_dmabuf_multiple_threads(state, 30, 20, 0, SZ_32M, SZ_4K, true, true));
}

VOID test_dmabuf_non_zero_offset(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;
	uint64_t page_size;

	if (hltests_is_gaudi(fd)) {
		printf("exporting dma-buf with offset is not allowed for Gaudi, skipping\n");
		skip();
	}

	/*
	 * Assumptions:
	 * - The dma_max_seg_size of the importer driver is 64KB.
	 * - The HMMU page size for Gaudi2 is 768MB.
	 * - The default HMMU page size for non-Gaudi2 is 32MB.
	 */

	page_size = hltests_is_gaudi2(fd) ? (SZ_512M + SZ_256M) /* 768M */ : SZ_32M;

	/* exported size < dma_max_seg_size */
	CALL_HELPER_FUNC(test_dmabuf_multiple_threads(state, 1, 1, SZ_8K, SZ_32K, SZ_4K,
							false, false));

	/* exported size = dma_max_seg_size */
	CALL_HELPER_FUNC(test_dmabuf_multiple_threads(state, 1, 1, SZ_16K, SZ_64K, SZ_4K,
							false, false));

	/* exported size > dma_max_seg_size */
	CALL_HELPER_FUNC(test_dmabuf_multiple_threads(state, 1, 1, SZ_32K, SZ_128K, SZ_4K,
							false, true));

	/*
	 * - exported size > dma_max_seg_size
	 * - dma_max_seg_size is reached when the end of a page is reached
	 */
	CALL_HELPER_FUNC(test_dmabuf_multiple_threads(state, 1, 1, page_size - SZ_64K, SZ_128K,
							SZ_4K, false, true));

	/*
	 * - exported size > dma_max_seg_size
	 * - exported memory is spanned on 2 pages
	 */
	CALL_HELPER_FUNC(test_dmabuf_multiple_threads(state, 1, 1, page_size - SZ_4K, SZ_8K, SZ_4K,
							false, true));

	/*
	 * - exported size > dma_max_seg_size
	 * - exported memory is spanned on 2 pages
	 * - exported memory starts on the 2nd out of 3 pages
	 */
	CALL_HELPER_FUNC(test_dmabuf_multiple_threads(state, 1, 1, (2 * page_size) - SZ_4K, SZ_8K,
							SZ_4K, false, true));

	END_TEST;
}

VOID test_dmabuf_entire_dram(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t dram_size, export_offset, export_size;
	int fd = tests_state->fd;

	if (hltests_is_gaudi(fd)) {
		printf("exporting dma-buf with offset is not allowed for Gaudi, skipping\n");
		skip();
	}

	dram_size = hltests_get_total_avail_device_mem(fd);
	export_offset = 0xA000000;
	assert_true(dram_size > export_offset);
	export_size = dram_size - export_offset;

	END_TEST_FUNC(test_dmabuf_multiple_threads(state, 1, 100, export_offset, export_size, SZ_4K,
							false, true));
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest dma_buf_tests[] = {
	cmocka_unit_test_setup(test_dmabuf_basic, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dmabuf_multiple_threads_non_shared_memory,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dmabuf_multiple_threads_shared_memory,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dmabuf_non_zero_offset,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dmabuf_entire_dram,
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"dma_buf [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(dma_buf_tests) / sizeof((dma_buf_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_GAUDI_FAMILY,
			dma_buf_tests, num_tests);
	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK |
				CAP_ARC_FW_LOAD_PDMA_MASK);
	return hltests_run_group_tests("dma_buf", dma_buf_tests, num_tests,
					hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
