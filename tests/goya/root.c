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
#include "goya/goya.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

void test_debugfs_sram_read_write(void **state)
{
	struct hltests_state *tests_state =
					(struct hltests_state *) *state;
	uint32_t val;

	hltests_debugfs_write(tests_state->fd, SRAM_BASE_ADDR + 0x200000,
					0x99775533);
	hltests_debugfs_write(tests_state->fd, SRAM_BASE_ADDR + 0x200000,
					0x12345678);
	val = hltests_debugfs_read(tests_state->fd,
					SRAM_BASE_ADDR + 0x200000);

	assert_int_equal(0x12345678, val);
}

const struct CMUnitTest root_tests[] = {
	cmocka_unit_test(test_debugfs_sram_read_write),
};

int main(void)
{
	char *test_names_to_run;
	int rc;

	if (access("/sys/kernel/debug", R_OK))
		return 0;

	test_names_to_run = getenv("HLTHUNK_TESTS_NAMES");
	if (test_names_to_run)
		cmocka_set_test_filter(test_names_to_run);

	rc = cmocka_run_group_tests(root_tests, hltests_root_setup,
					hltests_root_teardown);

	return rc;
}
