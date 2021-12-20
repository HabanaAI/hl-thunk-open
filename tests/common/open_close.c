// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#include "hlthunk_tests.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

void test_open_by_busid(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();

	if (!pciaddr) {
		printf("Test is skipped because pci address wasn't given\n");
		skip();
	}

	if (hltests_setup(state)) {
		printf("Failed to open device with pci address %s\n", pciaddr);
		return;
	}

	hltests_teardown(state);
}

void test_open_twice(void **state)
{
	int fd, fd2;

	fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, NULL);
	assert_in_range(fd, 0, INT_MAX);

	fd2 = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, NULL);
	assert_int_equal(fd2, -1);

	hlthunk_close(fd);
}

void test_open_close_without_ioctl(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();
	int fd;

	fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, pciaddr);
	assert_in_range(fd, 0, INT_MAX);

	hlthunk_close(fd);
}

void test_close_without_releasing_debug(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();
	struct hl_debug_args debug;
	uint32_t status;
	int fd, rc;

	fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, pciaddr);
	assert_in_range(fd, 0, INT_MAX);

	memset(&debug, 0, sizeof(struct hl_debug_args));
	debug.op = HL_DEBUG_OP_SET_MODE;
	debug.enable = 1;

	rc = hlthunk_debug(fd, &debug);
	assert_int_equal(rc, 0);

	rc = hlthunk_close(fd);
	assert_int_equal(rc, 0);

	fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, pciaddr);
	assert_in_range(fd, 0, INT_MAX);

	memset(&debug, 0, sizeof(struct hl_debug_args));
	debug.op = HL_DEBUG_OP_SET_MODE;
	debug.enable = 1;

	rc = hlthunk_debug(fd, &debug);
	assert_int_equal(rc, 0);

	rc = hlthunk_close(fd);
	assert_int_equal(rc, 0);
}

const struct CMUnitTest open_close_tests[] = {
	cmocka_unit_test(test_open_by_busid),
	cmocka_unit_test(test_open_twice),
	cmocka_unit_test(test_open_close_without_ioctl),
	cmocka_unit_test(test_close_without_releasing_debug)
};

static const char *const usage[] = {
	"open_close [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(open_close_tests) /
			sizeof((open_close_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE,
			open_close_tests, num_tests);

	return hltests_run_group_tests("open_close", open_close_tests,
					num_tests, NULL, NULL);
}
