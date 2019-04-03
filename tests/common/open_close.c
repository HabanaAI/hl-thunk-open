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

void test_open_by_busid(void **state)
{
	const char *pciaddr = hltests_get_parser_pciaddr();

	if (!pciaddr) {
		printf("Test is skipped because pci address wasn't given\n");
		return;
	}

	if (hltests_setup(state)) {
		printf("Failed to open device with pci address %s\n", pciaddr);
		return;
	}

	hltests_teardown(state);
}

const struct CMUnitTest open_close_tests[] = {
	cmocka_unit_test(test_open_by_busid),
};

static const char *const usage[] = {
	"open_close [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID,
		open_close_tests,
		sizeof(open_close_tests) / sizeof((open_close_tests)[0]));

	return cmocka_run_group_tests(open_close_tests, NULL, NULL);
}
