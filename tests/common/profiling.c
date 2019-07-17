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
#include <unistd.h>

void test_debug_mode(void **state)
{
	struct hltests_state *tests_state =
			(struct hltests_state *) *state;
	struct hl_debug_args debug;
	int rc, fd = tests_state->fd;

	memset(&debug, 0, sizeof(struct hl_debug_args));
	debug.op = HL_DEBUG_OP_SET_MODE;
	debug.enable = 1;

	rc = hlthunk_debug(fd, &debug);
	assert_int_equal(rc, 0);

	memset(&debug, 0, sizeof(struct hl_debug_args));
	debug.op = HL_DEBUG_OP_SET_MODE;
	debug.enable = 0;

	rc = hlthunk_debug(fd, &debug);
	assert_int_equal(rc, 0);
}

const struct CMUnitTest profiling_tests[] = {
	cmocka_unit_test_setup(test_debug_mode,
			hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"profiling [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(profiling_tests) / sizeof((profiling_tests)[0]);

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_DONT_CARE,
			profiling_tests, num_tests);

	return hltests_run_group_tests("profiling", profiling_tests,
				num_tests, hltests_setup, hltests_teardown);
}
