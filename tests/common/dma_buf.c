// SPDX-License-Identifier: MIT

/*
 * Copyright 2021 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "kvec.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

void test_dmabuf(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	int rc;

	if (hltests_is_pldm(tests_state->fd))
		skip();

	if (tests_state->imp_fd < 0) {
		printf("Skipping test because importer device is missing\n");
		skip();
	}

	rc = hlthunk_get_hw_ip_info(tests_state->fd, &hw_ip);
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
