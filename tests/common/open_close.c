// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

VOID test_open_by_busid(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();

	if (!pciaddr) {
		printf("Test is skipped because pci address wasn't given\n");
		skip();
	}

	if (hltests_setup(state)) {
		printf("Failed to open device with pci address %s\n", pciaddr);
		fail();
	}

	hltests_teardown(state);

	END_TEST;
}

VOID test_open_twice(void **state)
{
	int fd, fd2, rc;
	char pci_bus_id[16];
	const char *pciaddr = hltests_get_parser_pciaddr();

	fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, pciaddr);
	assert_in_range(fd, 0, INT_MAX);

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	assert_int_equal(rc, 0);

	fd2 = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, pci_bus_id);
	assert_int_equal(fd2, -EBUSY);

	hlthunk_close(fd);

	END_TEST;
}

VOID test_open_by_module_id(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();
	int fd;

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("Test is skipped because it is disabled by default\n");
		skip();
	}

	if (pciaddr) {
		printf("Test is skipped because pci address was given\n");
		skip();
	}

	fd = hlthunk_open_by_module_id(0);
	assert_in_range(fd, 0, INT_MAX);

	hlthunk_close(fd);

	END_TEST;
}

VOID test_open_close_without_ioctl(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();
	int fd;

	fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, pciaddr);
	assert_in_range(fd, 0, INT_MAX);

	hlthunk_close(fd);

	END_TEST;
}

VOID test_close_without_releasing_debug(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();
	struct hl_debug_args debug;
	char pci_bus_id[16];
	int fd, rc;

	fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, pciaddr);
	assert_in_range(fd, 0, INT_MAX);

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	assert_int_equal(rc, 0);

	memset(&debug, 0, sizeof(struct hl_debug_args));
	debug.op = HL_DEBUG_OP_SET_MODE;
	debug.enable = 1;

	rc = hlthunk_debug(fd, &debug);
	assert_int_equal(rc, 0);

	rc = hlthunk_close(fd);
	assert_int_equal(rc, 0);

	fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, pci_bus_id);
	assert_in_range(fd, 0, INT_MAX);

	memset(&debug, 0, sizeof(struct hl_debug_args));
	debug.op = HL_DEBUG_OP_SET_MODE;
	debug.enable = 1;

	rc = hlthunk_debug(fd, &debug);
	assert_int_equal(rc, 0);

	rc = hlthunk_close(fd);
	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_open_and_print_pci_bdf(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();
	char pci_bus_id[16];
	int rc, fd;

	fd = hlthunk_open(HLTHUNK_DEVICE_DONT_CARE, pciaddr);
	assert_in_range(fd, 0, INT_MAX);

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, 16);
	assert_int_equal(rc, 0);

	printf("PCI BDF: %s\n", pci_bus_id);

	hlthunk_close(fd);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest open_close_tests[] = {
	cmocka_unit_test(test_open_by_busid),
	cmocka_unit_test(test_open_by_module_id),
	cmocka_unit_test(test_open_twice),
	cmocka_unit_test(test_open_close_without_ioctl),
	cmocka_unit_test(test_close_without_releasing_debug),
	cmocka_unit_test(test_open_and_print_pci_bdf)
};

static const char *const usage[] = {
	"open_close [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(open_close_tests) /
			sizeof((open_close_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_DONT_CARE,
			open_close_tests, num_tests);

	return hltests_run_group_tests("open_close", open_close_tests,
					num_tests, NULL, NULL);
}

#endif /* HLTESTS_LIB_MODE */
