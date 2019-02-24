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
	struct hltests_cs_chunk execute_arr[1];
	uint32_t offset = 0;
	uint64_t seq;
	void *ptr;
	int rc;

	ptr = hltests_create_cb(tests_state->fd, getpagesize(), true, 0);
	assert_ptr_not_equal(ptr, NULL);

	offset = hltests_add_nop_pkt(tests_state->fd, ptr, offset, false,
						false);

	execute_arr[0].cb_ptr = ptr;
	execute_arr[0].cb_size = offset;
	execute_arr[0].queue_index =
			hltests_get_dma_down_qid(tests_state->fd, 0);

	rc = hltests_submit_cs(tests_state->fd, NULL, 0, execute_arr, 1,
					false, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs(tests_state->fd, seq,
					WAIT_FOR_CS_DEFAULT_TIMEOUT);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(tests_state->fd, ptr);
	assert_int_equal(rc, 0);
}

void test_cs_msg_long(void **state)
{
	struct hltests_state *tests_state =
			(struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_cs_chunk execute_arr[1];
	uint32_t offset = 0;
	uint64_t seq;
	void *ptr;
	int rc;

	ptr = hltests_create_cb(tests_state->fd, getpagesize(), true, 0);
	assert_ptr_not_equal(ptr, NULL);

	rc = hlthunk_get_hw_ip_info(tests_state->fd, &hw_ip);
	assert_int_equal(rc, 0);

	offset = hltests_add_msg_long_pkt(tests_state->fd, ptr, offset,
					false, true,
					hw_ip.sram_base_address + 0x1000,
					0xbaba0ded);

	execute_arr[0].cb_ptr = ptr;
	execute_arr[0].cb_size = offset;
	execute_arr[0].queue_index =
			hltests_get_dma_down_qid(tests_state->fd, 0);

	rc = hltests_submit_cs(tests_state->fd, NULL, 0, execute_arr, 1,
					false, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs(tests_state->fd, seq,
					WAIT_FOR_CS_DEFAULT_TIMEOUT);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(tests_state->fd, ptr);
	assert_int_equal(rc, 0);
}

#define NUM_OF_MSGS	2000

void test_cs_msg_long_2000(void **state)
{
	struct hltests_state *tests_state =
			(struct hltests_state *) *state;
	struct hlthunk_hw_ip_info hw_ip;
	struct hltests_cs_chunk execute_arr[1];
	uint32_t offset = 0;
	uint64_t seq;
	void *ptr;
	int rc, i;

	/* Largest packet is 24 bytes, so 32 is a good number */
	ptr = hltests_create_cb(tests_state->fd, NUM_OF_MSGS * 32, true,
					0);
	assert_ptr_not_equal(ptr, NULL);

	rc = hlthunk_get_hw_ip_info(tests_state->fd, &hw_ip);
	assert_int_equal(rc, 0);

	for (i = 0 ; i < NUM_OF_MSGS ; i++)
		offset = hltests_add_msg_long_pkt(tests_state->fd, ptr,
				offset, false, true,
				hw_ip.sram_base_address + 0x1000 + i * 4,
				0x0ded0000 + i);

	execute_arr[0].cb_ptr = ptr;
	execute_arr[0].cb_size = offset;
	execute_arr[0].queue_index =
			hltests_get_dma_down_qid(tests_state->fd, 0);

	rc = hltests_submit_cs(tests_state->fd, NULL, 0, execute_arr, 1,
					false, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs(tests_state->fd, seq,
					WAIT_FOR_CS_DEFAULT_TIMEOUT);
	assert_int_equal(rc, 0);

	rc = hltests_destroy_cb(tests_state->fd, ptr);
	assert_int_equal(rc, 0);
}

const struct CMUnitTest cs_tests[] = {
	cmocka_unit_test(test_cs_nop),
	cmocka_unit_test(test_cs_msg_long),
	cmocka_unit_test(test_cs_msg_long_2000),
};

int main(void)
{
	char *test_names_to_run;
	int rc;

	test_names_to_run = getenv("HLTHUNK_TESTS_NAMES");
	if (test_names_to_run)
		cmocka_set_test_filter(test_names_to_run);

	rc = cmocka_run_group_tests(cs_tests, hltests_setup,
					hltests_teardown);

	return rc;
}
