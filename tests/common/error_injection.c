// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#include "hlthunk_tests.h"
#include "hlthunk_err_inject.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>


void test_error_injection_endless_command(void **state)
{
	fail();
}

void test_error_injection_non_fatal_event(void **state)
{
	fail();
}

void test_error_injection_fatal_event(void **state)
{
	fail();
}

void test_error_injection_heartbeat(void **state)
{
	fail();
}

void test_error_injection_thermal_event(void **state)
{
	fail();
}

const struct CMUnitTest ei_tests[] = {
	cmocka_unit_test_setup(test_error_injection_endless_command,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_error_injection_non_fatal_event,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_error_injection_fatal_event,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_error_injection_heartbeat,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_error_injection_thermal_event,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"error_injection [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(ei_tests) / sizeof((ei_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE, ei_tests,
			num_tests);

	if (!hltests_get_parser_run_disabled_tests()) {
		printf("This executable need to be run with -d flag\n");
		return 0;
	}

	return hltests_run_group_tests("error_injection", ei_tests, num_tests,
					hltests_setup, hltests_teardown);
}
