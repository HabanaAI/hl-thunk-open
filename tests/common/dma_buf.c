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
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>

static int ibv_reg_dmabuf_mr(int imp_fd, uint64_t offset, uint64_t length,
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

static int ibv_dereg_mr(int imp_fd, uint64_t mr_handle)
{
	struct hl_importer_dereg_mr_args args;

	memset(&args, 0, sizeof(args));
	args.mr_handle = mr_handle;

	return ioctl(imp_fd, HL_IMPORTER_IOCTL_DEREG_MR, &args);
}

static int ibv_write_to_mr(int imp_fd, uint64_t mr_handle, void *userptr,
				uint32_t size)
{
	struct hl_importer_write_to_mr_args args;

	memset(&args, 0, sizeof(args));
	args.mr_handle = mr_handle;
	args.userptr = (uint64_t) (uintptr_t) userptr;
	args.size = size;

	return ioctl(imp_fd, HL_IMPORTER_IOCTL_WRITE_TO_MR, &args);
}

static int ibv_read_from_mr(int imp_fd, uint64_t mr_handle, void *userptr,
				uint32_t size)
{
	struct hl_importer_read_from_mr_args args;

	memset(&args, 0, sizeof(args));
	args.mr_handle = mr_handle;
	args.userptr = (uint64_t) (uintptr_t) userptr;
	args.size = size;

	return ioctl(imp_fd, HL_IMPORTER_IOCTL_READ_FROM_MR, &args);
}

static void test_dmabuf_check_prerequisites(int fd, int imp_fd)
{
	if (hltests_is_pldm(fd)) {
		printf("Skipping test on PLDM\n");
		skip();
	}

	if (hltests_is_simulator(fd)) {
		printf("Skipping test on simulator\n");
		skip();
	}

	if (imp_fd < 0) {
		printf("Skipping test because importer device is missing\n");
		skip();
	}
}

struct test_dmabuf_params {
	pthread_barrier_t *barrier;
	void *device_addr;
	uint32_t iterations;
	uint32_t alloc_size;
	uint32_t access_size;
	int fd;
	int imp_fd;
	bool verify_memory;
};

static void *dmabuf_thread_start(void *args)
{
	struct test_dmabuf_params *params = (struct test_dmabuf_params *) args;
	uint64_t host_src_device_va, host_dst_device_va, mr_handle = 0,
			access_size = params->access_size,
			alloc_size = params->alloc_size;
	void *device_addr, *host_src, *host_dst;
	int rc, fd = params->fd, imp_fd = params->imp_fd, dmabuf_fd, i;

	/* Allocate host/device memories */

	host_src = hltests_allocate_host_mem(fd, alloc_size, NOT_HUGE);
	assert_non_null(host_src);
	host_src_device_va = hltests_get_device_va_for_host_ptr(fd, host_src);

	host_dst = hltests_allocate_host_mem(fd, alloc_size, NOT_HUGE);
	assert_non_null(host_dst);
	host_dst_device_va = hltests_get_device_va_for_host_ptr(fd, host_dst);

	if (!params->device_addr) {
		device_addr = hltests_allocate_device_mem(fd, alloc_size,
								NOT_CONTIGUOUS);
		assert_non_null(device_addr);
	} else {
		device_addr = params->device_addr;
	}

	/* Export DMA-BUF and register MR */

	dmabuf_fd = hltests_device_memory_export_dmabuf_fd(fd, device_addr,
								alloc_size);
	assert_in_range(fd, 0, INT_MAX);

	rc = ibv_reg_dmabuf_mr(imp_fd, 0, alloc_size, 0, dmabuf_fd, 0,
				&mr_handle);
	assert_int_equal(rc, 0);

	/*
	 * PTHREAD_BARRIER_SERIAL_THREAD is returned to one unspecified thread
	 * and zero is returned to each of the remaining threads.
	 */
	rc = pthread_barrier_wait(params->barrier);
	if (rc && rc != PTHREAD_BARRIER_SERIAL_THREAD)
		return NULL;

	for (i = 0 ; i < params->iterations ; i++) {
		/* Write to MR */

		if (params->verify_memory) {
			hltests_fill_rand_values(host_src, access_size);
			memset(host_dst, 0, access_size);
		}

		rc = ibv_write_to_mr(imp_fd, mr_handle, host_src, access_size);
		assert_int_equal(rc, 0);

		if (params->verify_memory) {
			hltests_dma_transfer(fd,
					hltests_get_dma_up_qid(fd, STREAM0),
					EB_FALSE, MB_FALSE,
					(uint64_t) (uintptr_t) device_addr,
					host_dst_device_va, access_size,
					GOYA_DMA_DRAM_TO_HOST);

			rc = hltests_mem_compare(host_src, host_dst,
							access_size);
			assert_int_equal(rc, 0);
		}

		/* Read from MR */

		if (params->verify_memory) {
			hltests_fill_rand_values(host_src, access_size);
			memset(host_dst, 0, access_size);

			hltests_dma_transfer(fd,
					hltests_get_dma_down_qid(fd, STREAM0),
					EB_FALSE, MB_FALSE, host_src_device_va,
					(uint64_t) (uintptr_t) device_addr,
					access_size, GOYA_DMA_HOST_TO_DRAM);
		}

		rc = ibv_read_from_mr(imp_fd, mr_handle, host_dst, access_size);
		assert_int_equal(rc, 0);

		if (params->verify_memory) {
			rc = hltests_mem_compare(host_src, host_dst,
							access_size);
			assert_int_equal(rc, 0);
		}
	}

	/* Cleanup */

	rc = ibv_dereg_mr(imp_fd, mr_handle);
	assert_int_equal(rc, 0);

	rc = close(dmabuf_fd);
	assert_int_equal(rc, 0);

	if (!params->device_addr) {
		rc = hltests_free_device_mem(fd, device_addr);
		assert_int_equal(rc, 0);
	}

	rc = hltests_free_host_mem(fd, host_dst);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, host_src);
	assert_int_equal(rc, 0);

	return args;
}

void _test_dmabuf_multiple_threads(int fd, int imp_fd, uint32_t num_of_threads,
				uint32_t iterations, uint64_t alloc_size,
				uint64_t access_size, bool shared_device_memory)
{
	struct test_dmabuf_params *thread_params;
	pthread_t *thread_id;
	pthread_barrier_t barrier;
	void *device_addr = NULL, *retval;
	int rc, i;

	test_dmabuf_check_prerequisites(fd, imp_fd);

	assert_in_range(access_size, 1, alloc_size);

	thread_params = hlthunk_malloc(num_of_threads * sizeof(*thread_params));
	assert_non_null(thread_params);

	thread_id = hlthunk_malloc(num_of_threads * sizeof(*thread_id));
	assert_non_null(thread_id);

	rc = pthread_barrier_init(&barrier, NULL, num_of_threads);
	assert_int_equal(rc, 0);

	if (shared_device_memory) {
		device_addr = hltests_allocate_device_mem(fd, alloc_size,
								NOT_CONTIGUOUS);
		assert_non_null(device_addr);
	}

	/* Create and execute threads */
	for (i = 0 ; i < num_of_threads ; i++) {
		thread_params[i].barrier = &barrier;
		thread_params[i].device_addr = device_addr;
		thread_params[i].iterations = iterations;
		thread_params[i].alloc_size = alloc_size;
		thread_params[i].access_size = access_size;
		thread_params[i].fd = fd;
		thread_params[i].imp_fd = imp_fd;
		thread_params[i].verify_memory = !shared_device_memory;

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
}

void test_dmabuf_basic(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;

	_test_dmabuf_multiple_threads(tests_state->fd, tests_state->imp_fd,
					1, 1, SZ_32M, SZ_4K, false);
}

void test_dmabuf_multiple_threads_non_shared_memory(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;

	_test_dmabuf_multiple_threads(tests_state->fd, tests_state->imp_fd,
					15, 10, SZ_32M, SZ_4K, false);
}

void test_dmabuf_multiple_threads_shared_memory(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;

	_test_dmabuf_multiple_threads(tests_state->fd, tests_state->imp_fd,
					30, 20, SZ_32M, SZ_4K, true);
}

const struct CMUnitTest dma_buf_tests[] = {
	cmocka_unit_test_setup(test_dmabuf_basic,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dmabuf_multiple_threads_non_shared_memory,
			hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_dmabuf_multiple_threads_shared_memory,
			hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"dma_buf [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(dma_buf_tests) / sizeof((dma_buf_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE,
			dma_buf_tests, num_tests);

	return hltests_run_group_tests("dma_buf", dma_buf_tests, num_tests,
					hltests_setup, hltests_teardown);
}
