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
#include "specs/goya/goya_packets.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include <limits.h>
#include <cmocka.h>
#include <stdio.h>
#include <errno.h>

void test_cs_nop(void **state)
{
	struct hlthunk_tests_state *tests_state =
			(struct hlthunk_tests_state *) *state;
	struct hlthunk_tests_cs_chunk execute_arr[1];
	struct packet_nop packet = {};
	uint32_t size, offset = 0;
	uint64_t seq;
	void *ptr;
	int rc;

	size = sizeof(packet);
	ptr = hlthunk_tests_create_cb(tests_state->fd, size, true);
	assert_ptr_not_equal(ptr, NULL);

	packet.opcode = PACKET_NOP;
	offset = hlthunk_tests_add_packet_to_cb(ptr, offset, &packet,
			sizeof(packet));

	execute_arr[0].cb_ptr = ptr;
	execute_arr[0].cb_size = size;
	execute_arr[0].queue_index = GOYA_QUEUE_ID_DMA_1;
	rc = hlthunk_tests_submit_cs(tests_state->fd, NULL, 0, execute_arr, 1,
			false, &seq);
	assert_int_equal(rc, 0);

	rc = hlthunk_tests_wait_for_cs(tests_state->fd, seq,
			HLTHUNK_TESTS_WAIT_FOR_CS_DEFAULT_TIMEOUT);
	assert_int_equal(rc, 0);

	rc = hlthunk_tests_destroy_cb(tests_state->fd, ptr);
	assert_int_equal(rc, 0);
}

const struct CMUnitTest cs_tests[] = {
	cmocka_unit_test(test_cs_nop),
};

int main(void)
{
	return cmocka_run_group_tests(cs_tests, hlthunk_tests_setup,
			hlthunk_tests_teardown);
}
