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

void test_dmabuf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	void *device_addr;
	int imp_fd = tests_state->imp_fd;
	struct hlthunk_hw_ip_info hw_ip;
	int fd = tests_state->fd;
	uint64_t mr_handle = 0;
	uint32_t size = 0x1000;
	int rc, dmabuf_fd;

	if (hltests_is_pldm(tests_state->fd))
		skip();

	if (imp_fd < 0) {
		printf("Skipping test because importer device is missing\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	device_addr = hltests_allocate_device_mem(fd, size, NOT_CONTIGUOUS);
	assert_non_null(device_addr);

	dmabuf_fd = hltests_device_memory_export_dmabuf_fd(fd, device_addr,
								size);
	assert_in_range(fd, 0, INT_MAX);

	rc = ibv_reg_dmabuf_mr(imp_fd, 0, size, 0, dmabuf_fd, 0, &mr_handle);
	assert_int_equal(rc, 0);

	rc = ibv_dereg_mr(imp_fd, mr_handle);
	assert_int_equal(rc, 0);

	rc = close(dmabuf_fd);
	assert_int_equal(rc, 0);

	rc = hltests_free_device_mem(fd, device_addr);
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
