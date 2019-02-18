/*
 * Copyright (c) 2019 HabanaLabs Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
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

void test_cb_mmap(void **state)
{
	struct hlthunk_tests_state *tests_state =
					(struct hlthunk_tests_state *) *state;
	uint32_t size = 0x100000;
	uint64_t handle;
	void *ptr;
	int rc;

	rc = hlthunk_request_command_buffer(tests_state->fd, size, &handle);
	assert_int_equal(rc, 0);

	ptr = hlthunk_tests_mmap(tests_state->fd, size, handle);
	assert_ptr_not_equal(ptr, MAP_FAILED);

	rc = hlthunk_tests_munmap(ptr, size);
	assert_int_equal(rc, 0);
}

int cb_tests_setup(void **state)
{
	struct hlthunk_tests_state *tests_state;
	int rc;

	tests_state = hlthunk_malloc(sizeof(struct hlthunk_tests_state));
	if (!tests_state)
		return -ENOMEM;

	rc = hlthunk_tests_init();
	if (rc) {
		printf("Failed to init tests library %d\n", rc);
		goto free_state;
	}

	tests_state->fd = hlthunk_tests_open(NULL);
	if (tests_state->fd < 0) {
		printf("Failed to open device %d\n", tests_state->fd);
		rc = tests_state->fd;
		goto fini_tests;
	}

	*state = tests_state;

	return 0;

fini_tests:
	hlthunk_tests_fini();
free_state:
	hlthunk_free(tests_state);
	return rc;
}

int cb_tests_teardown(void **state)
{
	struct hlthunk_tests_state *tests_state =
					(struct hlthunk_tests_state *) *state;

	if (!tests_state)
		return -EINVAL;

	if (hlthunk_tests_close(tests_state->fd))
		printf("Problem in closing FD, ignoring...\n");

	hlthunk_tests_fini();

	hlthunk_free(*state);

	return 0;
}

const struct CMUnitTest cb_tests[] = {
	cmocka_unit_test(test_cb_mmap),
};

int main(void)
{
	return cmocka_run_group_tests(cb_tests, cb_tests_setup,
					cb_tests_teardown);
}
