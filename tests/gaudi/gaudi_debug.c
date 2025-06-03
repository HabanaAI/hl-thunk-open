// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_tests.h"
#include "gaudi_nic.h"

#include <stdarg.h>
#include <setjmp.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>

static VOID __test_conn_alloc_destroy(int fd, uint32_t port)
{
	uint32_t i, nr_conn_ids, conn_id;
	int rc;

	/* Verify that max number of connections can be allocated */
	nr_conn_ids = NIC_MAX_CONN_ID - NIC_MIN_CONN_ID + 1;
	for (i = 0 ; i < nr_conn_ids ; i++) {
		rc = hlthunk_alloc_conn(fd, port, &conn_id);
		assert_int_equal(rc, 0);
		assert_in_range(conn_id, NIC_MIN_CONN_ID, NIC_MAX_CONN_ID);
	}

	/* Verify that allocation of more than max connections fails */
	rc = hlthunk_alloc_conn(fd, port, &conn_id);
	assert_int_not_equal(rc, 0);

	/* Verify that destruction of an invalid connection ID fails */
	rc = hlthunk_destroy_conn(fd, port, NIC_MIN_CONN_ID - 1);
	assert_int_not_equal(rc, 0);
	rc = hlthunk_destroy_conn(fd, port, NIC_MAX_CONN_ID + 1);
	assert_int_not_equal(rc, 0);

	/* Verify that max number of connections can be destroyed */
	for (conn_id = NIC_MAX_CONN_ID ; conn_id >= NIC_MIN_CONN_ID ; conn_id--) {
		rc = hlthunk_destroy_conn(fd, port, conn_id);
		assert_int_equal(rc, 0);
	}

	/* Verify that destruction of a non-allocated connection fails */
	rc = hlthunk_destroy_conn(fd, port, NIC_MIN_CONN_ID);
	assert_int_not_equal(rc, 0);

	END_TEST;
}

VOID test_conn_alloc_destroy(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint32_t port, conn_id;
	int rc, fd = tests_state->fd;

	if (!tests_state->nic_ports_mask) {
		printf("Test is skipped because all NIC ports are disabled\n");
		skip();
	}

	for (port = 0 ; port < NIC_NUMBER_OF_PORTS ; port++) {
		if (!(tests_state->nic_ports_mask & BIT_ULL(port)))
			continue;
		__test_conn_alloc_destroy(fd, port);
	}

	/* Verify that connection allocation for an invalid port fails */
	rc = hlthunk_alloc_conn(fd, NIC_NUMBER_OF_PORTS, &conn_id);
	assert_int_not_equal(rc, 0);

	END_TEST;
}

static VOID __test_conn_set_context(int fd, uint32_t port)
{
	struct hlthunk_requester_conn_ctx req_ctx;
	struct hlthunk_responder_conn_ctx res_ctx;
	uint32_t conn_id;
	int rc;

	/* '0x5' and '0xa' are arbitrary values */
	memset(&req_ctx, 0x5, sizeof(req_ctx));
	memset(&res_ctx, 0xa, sizeof(res_ctx));

	/* Can't use destination QP 0 as it is ethernet */
	req_ctx.dst_conn_id = 1;
	res_ctx.dst_conn_id = 1;

	/* Verify that contexts cannot be set before connection is allocated */
	rc = hlthunk_set_responder_conn_ctx(fd, port, NIC_MIN_CONN_ID, &res_ctx);
	assert_int_not_equal(rc, 0);

	rc = hlthunk_set_requester_conn_ctx(fd, port, NIC_MIN_CONN_ID, &req_ctx, NULL);
	assert_int_not_equal(rc, 0);

	rc = hlthunk_alloc_conn(fd, port, &conn_id);
	assert_int_equal(rc, 0);
	assert_in_range(conn_id, NIC_MIN_CONN_ID, NIC_MAX_CONN_ID);

	/* TODO: Add the test below after SW-61009 is merged into the  driver
	 * Verify that contexts cannot be set in the opposite order
	 * rc = hlthunk_set_requester_conn_ctx(fd, port, conn_id, &req_ctx);
	 * assert_int_not_equal(rc, 0);
	 */

	/* Verify that contexts can be set */
	rc = hlthunk_set_responder_conn_ctx(fd, port, conn_id, &res_ctx);
	assert_int_equal(rc, 0);
	rc = hlthunk_set_requester_conn_ctx(fd, port, conn_id, &req_ctx, NULL);
	assert_int_equal(rc, 0);

	/* Verify that contexts can be modified */
	memset(&req_ctx, 0xa, sizeof(req_ctx));
	rc = hlthunk_set_requester_conn_ctx(fd, port, conn_id, &req_ctx, NULL);
	assert_int_equal(rc, 0);
	memset(&res_ctx, 0x5, sizeof(res_ctx));
	rc = hlthunk_set_responder_conn_ctx(fd, port, conn_id, &res_ctx);
	assert_int_equal(rc, 0);

	rc = hlthunk_destroy_conn(fd, port, conn_id);
	assert_int_equal(rc, 0);

	/* Verify that contexts cannot be set after connection is destroyed */
	rc = hlthunk_set_responder_conn_ctx(fd, port, conn_id, &res_ctx);
	assert_int_not_equal(rc, 0);
	rc = hlthunk_set_requester_conn_ctx(fd, port, conn_id, &req_ctx, NULL);
	assert_int_not_equal(rc, 0);

	END_TEST;
}

VOID test_conn_set_context(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd, port;

	if (!tests_state->nic_ports_mask) {
		printf("Test is skipped because all NIC ports are disabled\n");
		skip();
	}

	for (port = 0 ; port < NIC_NUMBER_OF_PORTS ; port++) {
		if (!(tests_state->nic_ports_mask & BIT_ULL(port)))
			continue;
		__test_conn_set_context(fd, port);
	}

	END_TEST;
}

VOID test_sm_overflow(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_pkt_info pkt_info;
	int i, fd = tests_state->fd;
	uint64_t sob_address;
	uint32_t cb_size = 0;
	uint16_t sob_id;
	void *cb;

	sob_id = 23;
	sob_address = CFG_BASE + mmSYNC_MNGR_E_S_SYNC_MNGR_OBJS_SOB_OBJ_0;
	sob_address += sob_id * 4;

	cb = hltests_create_cb(fd, 0x1000, EXTERNAL, 0);
	assert_non_null(cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.msg_long.address = sob_address;
	pkt_info.msg_long.value = 0x7ffe;
	cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	pkt_info.mb = MB_FALSE;
	pkt_info.msg_long.value = BIT(31) | 1;

	for (i = 0 ; i < 10 ; i++)
		cb_size = hltests_add_msg_long_pkt(fd, cb, cb_size, &pkt_info);

	END_TEST_FUNC(hltests_submit_and_wait_cs(fd, cb, cb_size,
				hltests_get_dma_down_qid(fd, STREAM0),
				DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED));
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest gaudi_debug_tests[] = {
	cmocka_unit_test_setup(test_conn_alloc_destroy,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_conn_set_context,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_sm_overflow,
				hltests_ensure_device_operational)
};

static const char *const usage[] = {
	"gaudi_debug [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(gaudi_debug_tests) /
			sizeof((gaudi_debug_tests)[0]);

	hltests_parser(argc, argv, usage, HLTEST_DEVICE_MASK_GAUDI_ALL,
			gaudi_debug_tests, num_tests);

	if (!hltests_get_parser_run_disabled_tests())
		return 0;

	return hltests_run_group_tests("gaudi_debug", gaudi_debug_tests,
			num_tests, hltests_nic_setup, hltests_nic_teardown);
}

#endif /* HLTESTS_LIB_MODE */
