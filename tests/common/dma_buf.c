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

void test_dmabuf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t mr_handle = 0, host_src_device_va, host_dst_device_va;
	void *device_addr, *host_src, *host_dst;
	int imp_fd = tests_state->imp_fd;
	struct hlthunk_hw_ip_info hw_ip;
	int fd = tests_state->fd;
	uint32_t alloc_size = SZ_32M, access_size = SZ_4K;
	int rc, dmabuf_fd;

	if (hltests_is_pldm(tests_state->fd))
		skip();

	if (imp_fd < 0) {
		printf("Skipping test because importer device is missing\n");
		skip();
	}

	assert_true(access_size <= alloc_size);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	host_src = hltests_allocate_host_mem(fd, alloc_size, NOT_HUGE);
	assert_non_null(host_src);
	host_src_device_va = hltests_get_device_va_for_host_ptr(fd, host_src);

	host_dst = hltests_allocate_host_mem(fd, alloc_size, NOT_HUGE);
	assert_non_null(host_dst);
	host_dst_device_va = hltests_get_device_va_for_host_ptr(fd, host_dst);

	device_addr = hltests_allocate_device_mem(fd, alloc_size,
							NOT_CONTIGUOUS);
	assert_non_null(device_addr);

	dmabuf_fd = hltests_device_memory_export_dmabuf_fd(fd, device_addr,
								alloc_size);
	assert_in_range(fd, 0, INT_MAX);

	rc = ibv_reg_dmabuf_mr(imp_fd, 0, alloc_size, 0, dmabuf_fd, 0,
				&mr_handle);
	assert_int_equal(rc, 0);

	/* Write to MR */

	hltests_fill_rand_values(host_src, access_size);
	memset(host_dst, 0, access_size);

	rc = ibv_write_to_mr(imp_fd, mr_handle, host_src, access_size);
	assert_int_equal(rc, 0);

	hltests_dma_transfer(fd, hltests_get_dma_up_qid(fd, STREAM0),
				EB_FALSE, MB_FALSE,
				(uint64_t) (uintptr_t) device_addr,
				host_dst_device_va, access_size,
				GOYA_DMA_DRAM_TO_HOST);

	rc = hltests_mem_compare(host_src, host_dst, access_size);
	assert_int_equal(rc, 0);

	/* Read from MR */

	hltests_fill_rand_values(host_src, access_size);
	memset(host_dst, 0, access_size);

	hltests_dma_transfer(fd, hltests_get_dma_down_qid(fd, STREAM0),
				EB_FALSE, MB_FALSE, host_src_device_va,
				(uint64_t) (uintptr_t) device_addr, access_size,
				GOYA_DMA_HOST_TO_DRAM);

	rc = ibv_read_from_mr(imp_fd, mr_handle, host_dst, access_size);
	assert_int_equal(rc, 0);

	rc = hltests_mem_compare(host_src, host_dst, access_size);
	assert_int_equal(rc, 0);

	rc = ibv_dereg_mr(imp_fd, mr_handle);
	assert_int_equal(rc, 0);

	rc = close(dmabuf_fd);
	assert_int_equal(rc, 0);

	rc = hltests_free_device_mem(fd, device_addr);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, host_dst);
	assert_int_equal(rc, 0);

	rc = hltests_free_host_mem(fd, host_src);
	assert_int_equal(rc, 0);
}

const struct CMUnitTest dma_buf_tests[] = {
	cmocka_unit_test_setup(test_dmabuf,
			hltests_ensure_device_operational),
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
