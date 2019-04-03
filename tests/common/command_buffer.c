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

static void cb_create_mmap_unmap_destroy(void **state, uint32_t size,
					bool unmap, bool destroy)
{
	struct hltests_state *tests_state =
					(struct hltests_state *) *state;
	uint64_t cb_handle;
	void *ptr;
	int rc;

	rc = hlthunk_request_command_buffer(tests_state->fd, size, &cb_handle);
	assert_int_equal(rc, 0);

	ptr = hltests_cb_mmap(tests_state->fd, size, cb_handle);
	assert_ptr_not_equal(ptr, MAP_FAILED);

	if (unmap) {
		rc = hltests_cb_munmap(ptr, size);
		assert_int_equal(rc, 0);
	}

	if (destroy) {
		rc = hlthunk_destroy_command_buffer(tests_state->fd, cb_handle);
		assert_int_equal(rc, 0);
	}
}

void test_cb_mmap(void **state)
{
	cb_create_mmap_unmap_destroy(state, 0x100000, true, true);
}

void test_cb_unaligned_size(void **state)
{
	cb_create_mmap_unmap_destroy(state, 5000, true, true);
}

void test_cb_small_unaligned_odd_size(void **state)
{
	cb_create_mmap_unmap_destroy(state, 77, true, true);
}

void test_cb_unaligned_odd_size(void **state)
{
	cb_create_mmap_unmap_destroy(state, 92517, true, true);
}

void test_cb_skip_unmap(void **state)
{
	cb_create_mmap_unmap_destroy(state, 92517, false, true);
}

void test_cb_skip_unmap_and_destroy(void **state)
{
	cb_create_mmap_unmap_destroy(state, 92517, false, false);
}

const struct CMUnitTest cb_tests[] = {
	cmocka_unit_test_setup(test_cb_mmap,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cb_unaligned_size,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cb_small_unaligned_odd_size,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cb_unaligned_odd_size,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cb_skip_unmap,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_cb_skip_unmap_and_destroy,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"command_buffer [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID, cb_tests,
			sizeof(cb_tests) / sizeof((cb_tests)[0]));

	return cmocka_run_group_tests(cb_tests, hltests_setup,
					hltests_teardown);
}
