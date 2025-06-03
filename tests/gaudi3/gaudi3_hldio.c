// SPDX-License-Identifier: MIT

/*
 * Copyright 2024 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#define _GNU_SOURCE
#include "hlthunk_tests.h"
#include "ini.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

/*
 * Important read before running the test:
 *
 * mount some NVME SSD to NVME_DRIVE_ROOT.
 * if the SSD is not in the correct format use this cmd to format it then mount it:
 * e.g: sudo mkfs.ext4 /dev/nvme6n1
 * Create a file inside that disk called testfile.txt and add some text to it.
 * At the end of this test you should see your text printed out.
 * In addition make sure "supports_nvme" is set to true in the device properties.
 */
#define NVME_DRIVE_ROOT "/mnt/nvme/"
#define TEST_FILE NVME_DRIVE_ROOT "/testfile.txt"

VOID test_hldio_read(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *)*state;
	uint64_t len_read, io_len = 4096 * 2, host_va;
	int fd = tests_state->fd, input_fd, rc;
	struct hlthunk_hw_ip_info hw_ip;
	struct hl_dio_args dio_args;
	struct hl_debug_args args;
	void *host_mem, *dev_mem;

	input_fd = open(TEST_FILE, O_DIRECT | O_RDWR);
	if (input_fd < 0) {
		printf("Error opening input file: %m (%d)\n", errno);
		fail();
	}

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	dev_mem = hltests_allocate_device_mem(fd, hw_ip.dram_page_size, 0, NOT_CONTIGUOUS);
	assert_non_null(dev_mem);

	host_mem = hltests_allocate_host_mem(fd, io_len, NOT_HUGE_MAP);
	assert_non_null(host_mem);
	host_va = hltests_get_device_va_for_host_ptr(fd, host_mem);

	dio_args = (struct hl_dio_args)
	{
		.op = HL_DIO_CMD_SSD2HL,
		.ssd2hl.fd = input_fd,
		.ssd2hl.device_va = (uint64_t)dev_mem,
		.ssd2hl.len_bytes = io_len,
		.ssd2hl.off_bytes = 0,
	};

	memset(&args, 0, sizeof(args));
	args.input_ptr = (uint64_t)(uintptr_t)&dio_args;
	args.input_size = sizeof(dio_args);
	args.output_ptr = (uint64_t)(uintptr_t)&len_read;
	args.output_size = sizeof(len_read);
	args.op = HL_DEBUG_OP_DIO;

	rc = hlthunk_debug(fd, &args);
	assert_int_equal(rc, 0);

	assert_in_range(len_read, 0, len_read);

	close(input_fd);

	rc = hltests_dma_transfer(fd, hltests_get_dma_up_qid(fd, STREAM0),
				  EB_FALSE, MB_FALSE, (uint64_t)dev_mem,
				  host_va, io_len, DMA_DIR_DRAM_TO_HOST);
	assert_int_equal(rc, 0);

	fwrite(host_mem, len_read, 1, stdout);

	hltests_free_host_mem(fd, host_mem);
	hltests_free_device_mem(fd, dev_mem);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest hldio_tests[] = {
	cmocka_unit_test_setup(test_hldio_read,
			       hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"hldio [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = ARRAY_SIZE(hldio_tests);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_GAUDI3, hldio_tests,
		       num_tests);

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("direct IO tests should run with --disabled option\n");
		return 0;
	}

	return hltests_run_group_tests("hldio", hldio_tests, num_tests,
				       hltests_setup, hltests_teardown);
}

#endif /* HLTESTS_LIB_MODE */
