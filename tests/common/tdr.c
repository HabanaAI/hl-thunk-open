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
#include <unistd.h>

void test_tdr_deadlock(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[1];
	void *ptr;
	uint64_t seq = 0;
	uint32_t page_size = sysconf(_SC_PAGESIZE), offset = 0;
	int rc, fd = tests_state->fd;

	ptr = hltests_create_cb(fd, page_size, true, 0);
	assert_ptr_not_equal(ptr, NULL);

	offset = hltests_add_fence_pkt(fd, ptr, offset, false, false, 1, 1, 0);

	execute_arr[0].cb_ptr = ptr;
	execute_arr[0].cb_size = offset;
	execute_arr[0].queue_index = hltests_get_dma_down_qid(fd, 0, 0);

	rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 1, false, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs_until_not_busy(fd, seq);
	assert_int_not_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_destroy_cb(fd, ptr);
	assert_int_equal(rc, 0);
}

const struct CMUnitTest tdr_tests[] = {
	cmocka_unit_test_setup(test_tdr_deadlock,
				hl_tests_ensure_device_operational),
};

static const char *const usage[] = {
    "tdr [options]",
    NULL,
};

int main(int argc, const char **argv)
{
	char *run_disabled_tests;

	run_disabled_tests = getenv("HLTHUNK_DISABLED_TESTS");
	if (!run_disabled_tests || strcmp(run_disabled_tests, "1"))
		return 0;

	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID, tdr_tests,
			sizeof(tdr_tests) / sizeof((tdr_tests)[0]));

	return cmocka_run_group_tests(tdr_tests, hltests_setup,
					hltests_teardown);
}
