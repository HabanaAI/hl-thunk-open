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

void test_cs_nop(void **state)
{
	struct hltests_state *tests_state =
			(struct hltests_state *) *state;
	uint32_t offset = 0;
	void *ptr;
	int fd = tests_state->fd;

	ptr = hltests_create_cb(fd, getpagesize(), true, 0);
	assert_ptr_not_equal(ptr, NULL);

	offset = hltests_add_nop_pkt(fd, ptr, offset, false, false);

	hltests_submit_and_wait_cs(fd, ptr, offset,
				hltests_get_dma_down_qid(fd, 0, 0), true);
}

void test_cs_msg_long(void **state)
{
	struct hltests_state *tests_state =
			(struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint32_t offset = 0;
	void *ptr;
	int rc, fd = tests_state->fd;

	ptr = hltests_create_cb(fd, getpagesize(), true, 0);
	assert_ptr_not_equal(ptr, NULL);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	offset = hltests_add_msg_long_pkt(fd, ptr, offset, false, true,
					hw_ip.sram_base_address + 0x1000,
					0xbaba0ded);

	hltests_submit_and_wait_cs(fd, ptr, offset,
				hltests_get_dma_down_qid(fd, 0, 0), true);
}

#define NUM_OF_MSGS	2000

void test_cs_msg_long_2000(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	uint32_t offset = 0;
	void *ptr;
	int rc, fd = tests_state->fd, i;

	/* Largest packet is 24 bytes, so 32 is a good number */
	ptr = hltests_create_cb(fd, NUM_OF_MSGS * 32, true, 0);
	assert_ptr_not_equal(ptr, NULL);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	for (i = 0 ; i < NUM_OF_MSGS ; i++)
		offset = hltests_add_msg_long_pkt(fd, ptr, offset, false, true,
				hw_ip.sram_base_address + 0x1000 + i * 4,
				0x0ded0000 + i);

	hltests_submit_and_wait_cs(fd, ptr, offset,
				hltests_get_dma_down_qid(fd, 0, 0), true);
}

const struct CMUnitTest cs_tests[] = {
	cmocka_unit_test_setup(test_cs_nop, hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_msg_long,
					hl_tests_ensure_device_operational),
	cmocka_unit_test_setup(test_cs_msg_long_2000,
					hl_tests_ensure_device_operational),
};

static const char *const usage[] = {
    "command_submission [options]",
    NULL,
};

int main(int argc, const char **argv)
{
	hltests_parser(argc, argv, usage, HLTHUNK_DEVICE_INVALID, cs_tests,
			sizeof(cs_tests) / sizeof((cs_tests)[0]));

	return cmocka_run_group_tests(cs_tests, hltests_setup,
					hltests_teardown);
}
