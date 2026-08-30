// SPDX-License-Identifier: MIT

/*
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_nic_tests.h"
#include "ini.h"

#include <stdarg.h>
#include <setjmp.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define QP_ALLOC_RETRIES	5
#define NUM_ETH_QPS		1
#define QP_DESTROY_TIMEOUT_SEC	5


struct wq_mapped_buf {
	void *send_wq_buf;
	void *recv_wq_buf;
};

struct conn_thread_params {
	uint64_t nic_ports_mask;
	uint32_t id;
	int fd;
	struct hltests_nic_gen_test_cfg cfg;
	/* generic pointer */
	void *data;
};

static int nic_gen_test_parser(void *user, const char *section, const char *name, const char *value)
{
	struct hltests_nic_gen_test_cfg *cfg = (struct hltests_nic_gen_test_cfg *)user;

	if (MATCH("gentst", "wq_loc")) {
		if (!strcmp(value, "host"))
			cfg->wq_loc = WQ_LOC_HOST;
		else {
			printf("gentst supports only WQ location on Host\n");
			return 0;
		}
	} else if (MATCH("gentst", "dst_conn_id")) {
		cfg->dst_conn_id = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("gentst", "num_wqs_shift")) {
		cfg->num_wqs_shift = strtoul(value, NULL, 0);
	} else if (MATCH("gentst", "num_wqes_shift")) {
		cfg->num_wqes_shift = strtoul(value, NULL, 0);
	} else if (MATCH("gentst", "num_iterations")) {
		cfg->num_iterations = (uint32_t)strtoul(value, NULL, 0);
	} else {
		return 0;
	}

	return 1;
}

static void set_wq_param(struct hlthunk_nic_wq_arr_set_in *wq_arr_set_in,
				struct hltests_nic_gen_test_wq *test_wq_param,
				uint64_t addr, uint32_t type)
{
	memset(wq_arr_set_in, 0, sizeof(*wq_arr_set_in));
	wq_arr_set_in->port = test_wq_param->port;
	wq_arr_set_in->addr = addr;
	wq_arr_set_in->num_of_wqs = test_wq_param->num_wqs;
	wq_arr_set_in->num_of_wq_entries = test_wq_param->num_wq_entries;
	wq_arr_set_in->type = type;
	wq_arr_set_in->mem_id = test_wq_param->mem_id;
}

static uint64_t get_wq_size(struct hltests_nic_gen_test_wq *test_wq_param,
				enum hl_nic_mem_type type)
{
	uint64_t wq_size;
	uint8_t wqe_size;

	if (type == HL_NIC_USER_WQ_SEND)
		wqe_size = hltests_nic_get_swqe_size(test_wq_param->fd);
	else
		wqe_size = hltests_nic_get_rwqe_size(test_wq_param->fd);

	wq_size = (uint64_t) test_wq_param->num_wqs * test_wq_param->num_wq_entries * wqe_size;

	return wq_size;
}

static void *setup_wq(struct hltests_nic_gen_test_wq *test_wq_param, enum hl_nic_mem_type type)
{
	struct hlthunk_nic_wq_arr_set_out wq_arr_set_out;
	struct hlthunk_nic_wq_arr_set_in wq_arr_set_in;
	uint64_t wq_size, dev_va = 0;
	void *raw_buf = NULL;
	int rc;

	wq_size = get_wq_size(test_wq_param, type);

	set_wq_param(&wq_arr_set_in, test_wq_param, dev_va, type);
	rc = hlthunk_nic_wq_arr_set(test_wq_param->fd, &wq_arr_set_in, &wq_arr_set_out);
	if (rc) {
		printf("Failed setting wq arr for WQ port: %d\n", test_wq_param->port);
		return NULL;
	}

	if (test_wq_param->mem_id == HL_NIC_MEM_HOST)
		/*
		 * Case of new WQ/QP API where hlthunk_nic_wq_arr_set does not return a
		 * handle so there is no mmap-ed buffer. Cannot return NULL since that
		 * indicates failure.
		 */
		return (void *) -1;

	return raw_buf;
}

static void *setup_recv_wq(struct hltests_nic_gen_test_wq *test_wq_param)
{
	return setup_wq(test_wq_param, HL_NIC_USER_WQ_RECV);
}

static void *setup_send_wq(struct hltests_nic_gen_test_wq *test_wq_param)
{
	return setup_wq(test_wq_param, HL_NIC_USER_WQ_SEND);
}

static int teardown_wq(struct hltests_nic_gen_test_wq *test_wq_param, void *raw_buf,
			enum hl_nic_mem_type type)
{
	uint64_t wq_size;

	wq_size = get_wq_size(test_wq_param, type);

	if (hlthunk_nic_wq_arr_unset(test_wq_param->fd, test_wq_param->port, type)) {
		printf("wq arr unset for WQ Send failed, port: %d", test_wq_param->port);
		return -1;
	}

	return 0;
}

static int teardown_recv_wq(struct hltests_nic_gen_test_wq *test_wq_param, void *raw_buf)
{
	return teardown_wq(test_wq_param, raw_buf, HL_NIC_USER_WQ_RECV);
}

static int teardown_send_wq(struct hltests_nic_gen_test_wq *test_wq_param, void *raw_buf)
{
	return teardown_wq(test_wq_param, raw_buf, HL_NIC_USER_WQ_SEND);
}

static void set_test_wq_param(int fd, uint32_t port, struct hltests_nic_gen_test_cfg *cfg,
				struct hltests_nic_gen_test_wq *test_wq_param)
{
	test_wq_param->fd = fd;
	test_wq_param->mem_id = (cfg->wq_loc == WQ_LOC_DEVICE) ? HL_NIC_MEM_DEVICE :
				HL_NIC_MEM_HOST;
	test_wq_param->num_wqs = (uint64_t) 1 << cfg->num_wqs_shift;
	test_wq_param->num_wq_entries = (uint64_t) 1 << cfg->num_wqes_shift;
	test_wq_param->port = port;
}

static void *wq_thread_start(void *args)
{
	struct conn_thread_params *params = (struct conn_thread_params *) args;
	struct hltests_nic_gen_test_wq test_wq_param;
	uint32_t i, port = params->id;
	int rc, fd = params->fd;
	void *buf_raw[2];

	if (!(params->nic_ports_mask & BIT_ULL(port)))
		return args;

	set_test_wq_param(fd, port, &params->cfg, &test_wq_param);

	for (i = 0 ; i < params->cfg.num_iterations ; i++) {
		buf_raw[0] = setup_send_wq(&test_wq_param);
		if (!buf_raw[0])
			return NULL;

		buf_raw[1] = setup_recv_wq(&test_wq_param);
		if (!buf_raw[1])
			return NULL;

		rc = teardown_send_wq(&test_wq_param, buf_raw[0]);
		if (rc != 0)
			return NULL;

		rc = teardown_recv_wq(&test_wq_param, buf_raw[1]);
		if (rc != 0)
			return NULL;
	}

	return args;
}

/* task to release WQs, to be done after connection threads have finished */
static int post_conn_thr_start(void *args)
{
	struct conn_thread_params *params = (struct conn_thread_params *) args;
	struct hltests_nic_gen_test_wq test_wq_param;
	struct wq_mapped_buf *wq_buf;
	uint32_t port, max_ports;
	int rc, fd = params->fd;

	max_ports = hltests_nic_get_max_num_of_ports(fd);
	wq_buf = (struct wq_mapped_buf *) params->data;
	assert_non_null(wq_buf);

	for (port = 0 ; port < max_ports ; port++) {
		if (!(params->nic_ports_mask & BIT_ULL(port)))
			continue;

		set_test_wq_param(fd, port, &params->cfg, &test_wq_param);

		rc = teardown_send_wq(&test_wq_param, wq_buf[port].send_wq_buf);
		assert_int_equal(rc, 0);

		rc = teardown_recv_wq(&test_wq_param, wq_buf[port].recv_wq_buf);
		assert_int_equal(rc, 0);
	}

	hlthunk_free(wq_buf);

	return 0;
}

/* task to allocate WQs, to be done before connection threads are started */
static int pre_conn_thr_start(void *args)
{
	struct conn_thread_params *params = (struct conn_thread_params *) args;
	struct hltests_nic_gen_test_wq test_wq_param;
	struct wq_mapped_buf *wq_buf;
	uint32_t port, max_ports;
	int fd = params->fd;

	max_ports = hltests_nic_get_max_num_of_ports(fd);
	wq_buf = hlthunk_malloc(max_ports * sizeof(*wq_buf));
	assert_non_null(wq_buf);

	params->data = (void *) wq_buf;

	for (port = 0 ; port < max_ports ; port++) {
		if (!(params->nic_ports_mask & BIT_ULL(port)))
			continue;

		set_test_wq_param(fd, port, &params->cfg, &test_wq_param);

		wq_buf[port].send_wq_buf = setup_send_wq(&test_wq_param);
		assert_non_null(wq_buf[port].send_wq_buf);

		wq_buf[port].recv_wq_buf = setup_recv_wq(&test_wq_param);
		assert_non_null(wq_buf[port].recv_wq_buf);
	}

	return 0;
}

static void *conn_thread_start(void *args)
{
	struct conn_thread_params *params = (struct conn_thread_params *) args;
	struct hlthunk_requester_conn_ctx req_ctx;
	struct hlthunk_responder_conn_ctx res_ctx;
	struct hlthunk_requester_conn_ctx_out req_out_params;

	uint32_t i, port, conn_id, swq_size, rwq_size, max_ports;
	int r, rc, fd = params->fd;
	void *swq_buf = NULL, *rwq_buf = NULL;

	memset(&req_ctx, 0, sizeof(req_ctx));
	memset(&res_ctx, 0, sizeof(res_ctx));

	max_ports = hltests_nic_get_max_num_of_ports(fd);

	req_ctx.dst_conn_id = params->cfg.dst_conn_id;
	req_ctx.wq_size = (uint32_t) 1 << params->cfg.num_wqes_shift;
	req_ctx.priority = 1;

	res_ctx.dst_conn_id = params->cfg.dst_conn_id;
	req_ctx.timer_granularity = NIC_QP_TIMER_GRAN;

	for (i = 0 ; i < params->cfg.num_iterations ; i++) {
		for (port = 0 ; port < max_ports ; port++) {
			if (!(params->nic_ports_mask & BIT_ULL(port)))
				continue;

			for (r = 0 ; r < QP_ALLOC_RETRIES ; r++) {
				rc = hlthunk_alloc_conn(fd, port, &conn_id);
				if (rc != -ENOSPC && rc != -EBUSY)
					break;

				/* we may be facing a graceful QP release by the driver
				 * so lets wait for it to release a QP and retry
				 */
				sleep(2);
			}

			if (rc) {
				printf("Failed allocating connection for port %d\n", port);
				return NULL;
			}

			rc = hlthunk_set_responder_conn_ctx(fd, port, conn_id, &res_ctx);
			if (rc) {
				printf("Failed setting responder for port %d, conn id %d\n",
									port, conn_id);
				return NULL;
			}

			rc = hlthunk_set_requester_conn_ctx(fd, port, conn_id, &req_ctx,
				&req_out_params);
			if (rc) {
				printf("Failed setting requester for port %d, conn id %d\n",
									port, conn_id);
				return NULL;
			}

			/* if memory allocated by LKD, then need to mmap it */
			swq_size = ((uint64_t) 1 << params->cfg.num_wqes_shift) *
					hltests_nic_get_swqe_size(fd);
			swq_buf = hltests_mmap(fd, swq_size, (off_t)req_out_params.swq_mem_handle);
			if (swq_buf == MAP_FAILED) {
				printf("mmap failed, port: %d", port);
				return NULL;
			}

			rc = hltests_munmap(fd, swq_buf, swq_size);
			if (rc) {
				printf("munmap failed, port: %d", port);
				return NULL;
			}

			rwq_size = ((uint64_t) 1 << params->cfg.num_wqes_shift) *
					hltests_nic_get_rwqe_size(fd);
			rwq_buf = hltests_mmap(fd, rwq_size, (off_t)req_out_params.rwq_mem_handle);
			if (rwq_buf == MAP_FAILED) {
				printf("mmap failed, port: %d", port);
				return NULL;
			}

			rc = hltests_munmap(fd, rwq_buf, rwq_size);
			if (rc) {
				printf("munmap failed, port: %d", port);
				return NULL;
			}

			rc = hlthunk_destroy_conn(fd, port, conn_id);
			if (rc) {
				printf("Failed destroying connection for port %d, conn id %d\n",
									port, conn_id);
				return NULL;
			}
		}
	}

	return args;
}

VOID test_threads(void **state, uint32_t num_of_threads, void *(*func)(void *),
			int (*pre_task)(void *), int (*post_task)(void *))
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	const char *config_filename = hltests_get_config_filename();
	struct hltests_nic_gen_test_cfg cfg;
	struct conn_thread_params *thread_params;
	pthread_t *thread_id;
	void *retval;
	uint32_t i;
	int rc, fd = tests_state->fd;

	uint64_t port_mask = hltests_nic_get_port_mask(fd);

	if (!(tests_state->nic_ports_mask & port_mask)) {
		printf("Test is skipped because all NIC ports are disabled\n");
		skip();
	}

	/* clear config prior of filling it */
	memset(&cfg, 0, sizeof(cfg));
	cfg.num_threads = num_of_threads;
	cfg.is_pldm = hltests_is_pldm(fd);

	if (config_filename) {
		if (ini_parse(config_filename, nic_gen_test_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);
	} else {
		printf("no cfg file was provided. Taking defaults\n");
		rc = hltests_nic_get_default_cfg(fd, &cfg, HLTESTS_NIC_GEN_TEST);
		assert_int_equal(rc, 0);
	}

	thread_id = (pthread_t *) hlthunk_malloc(num_of_threads * sizeof(*thread_id));
	assert_non_null(thread_id);

	thread_params = (struct conn_thread_params *)
			hlthunk_malloc(num_of_threads * sizeof(*thread_params));
	assert_non_null(thread_params);

	for (i = 0 ; i < num_of_threads ; i++) {
		thread_params[i].fd = fd;
		thread_params[i].id = i;
		thread_params[i].nic_ports_mask =
				tests_state->nic_ports_mask;
		memcpy(&thread_params[i].cfg, &cfg, sizeof(cfg));
	}

	if (pre_task)
		pre_task(&thread_params[0]);

	/* Create and execute threads */
	for (i = 0 ; i < num_of_threads ; i++) {
		rc = pthread_create(&thread_id[i], NULL, func,
					&thread_params[i]);
		assert_int_equal(rc, 0);
	}

	/* Wait for the termination of the threads */
	for (i = 0 ; i < num_of_threads ; i++) {
		rc = pthread_join(thread_id[i], &retval);
		assert_int_equal(rc, 0);
		assert_non_null(retval);
	}

	if (post_task)
		post_task(&thread_params[0]);

	hlthunk_free(thread_params);
	hlthunk_free(thread_id);

	END_TEST;
}

VOID test_wq_threads(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;
	uint32_t max_ports;

	if (!hltests_is_gaudi_family(fd)) {
		printf("Test is skipped because the device's type is not a Gaudi\n");
		skip();
	}

	max_ports = hltests_nic_get_max_num_of_ports(fd);

	END_TEST_FUNC(test_threads(state, max_ports, wq_thread_start, NULL, NULL));
}

VOID test_conn_threads(void **state, uint32_t num_of_threads)
{

	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;

	if (!hltests_is_gaudi_family(fd)) {
		printf("Test is skipped because the device's type is not a Gaudi\n");
		skip();
	}

	END_TEST_FUNC(test_threads(state, num_of_threads, conn_thread_start,
			pre_conn_thr_start, post_conn_thr_start));
}

VOID test_conn_1_thread(void **state)
{
	END_TEST_FUNC(test_conn_threads(state, 1));
}

VOID test_conn_8_threads(void **state)
{
	END_TEST_FUNC(test_conn_threads(state, 8));
}

VOID test_conn_512_threads(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;

	/* Skip for simulator until SW-16469 is solved */
	if (hltests_is_simulator(fd)) {
		printf("Test is temporarily disabled on simulator, skipping\n");
		skip();
	}

	END_TEST_FUNC(test_conn_threads(state, 512));
}

VOID test_conn_1023_threads(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;

	/* Skip for simulator until SW-16469 is solved */
	if (hltests_is_simulator(fd)) {
		printf("Test is temporarily disabled on simulator, skipping\n");
		skip();
	}

	END_TEST_FUNC(test_conn_threads(state, 1023));
}

VOID test_print_ips_macs(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int i, fd = tests_state->fd;
	uint32_t max_ports;

	if (!hltests_is_gaudi_family(fd)) {
		printf("Test is skipped because the device's type is not a Gaudi\n");
		skip();
	}

	max_ports = hltests_nic_get_max_num_of_ports(fd);

	for (i = 0 ; i < max_ports ; i++) {
		if (!(tests_state->nic_ports_mask & BIT_ULL(i)))
			continue;

		printf("port: %d, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", i,
			tests_state->mac_addrs[i].addr[0],
			tests_state->mac_addrs[i].addr[1],
			tests_state->mac_addrs[i].addr[2],
			tests_state->mac_addrs[i].addr[3],
			tests_state->mac_addrs[i].addr[4],
			tests_state->mac_addrs[i].addr[5]);
	}

	END_TEST;
}

VOID test_nic_disabled_qm(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_cs_chunk execute_arr[2];
	void *ext_cb = NULL, *db_buf[MAX_NIC_NUMBER_OF_PORTS] = {0},
		*int_cb[MAX_NIC_NUMBER_OF_PORTS] = {0};
	uint64_t seq, db_buf_va[MAX_NIC_NUMBER_OF_PORTS] = {0};
	uint32_t i, cb_size = 0x1000, ext_cb_size = 0,
		db_buf_size[MAX_NIC_NUMBER_OF_PORTS] = {0}, nic_base_qid, max_ports;
	int rc, fd = tests_state->fd;
	struct hltests_pkt_info pkt_info;

	if (!hltests_is_gaudi(fd) && !hltests_is_gaudi2(fd)) {
		printf("Test is skipped because device is not GAUDI/GAUDI2\n");
		skip();
	}

	if (!hltests_get_parser_run_disabled_tests())
		skip();

	max_ports = hltests_nic_get_max_num_of_ports(fd);
	nic_base_qid = hltests_nic_get_base_qid(fd);

	ext_cb = hltests_create_cb(fd, cb_size, EXTERNAL, 0);
	assert_non_null(ext_cb);

	for (i = 0 ; i < max_ports ; i++) {
		if (tests_state->nic_ports_mask & BIT_ULL(i))
			continue;

		db_buf[i] = hltests_allocate_host_mem(fd, cb_size, NOT_HUGE_MAP);
		assert_non_null(db_buf[i]);

		memset(db_buf[i], 0, cb_size);

		db_buf_va[i] = hltests_get_device_va_for_host_ptr(fd,
							db_buf[i]);
	}

	for (i = 0 ; i < max_ports ; i++) {
		if (tests_state->nic_ports_mask & BIT_ULL(i))
			continue;

		int_cb[i] = hltests_create_cb(fd, HL_MAX_CB_SIZE, INTERNAL,
						db_buf_va[i]);
		assert_non_null(int_cb[i]);
	}

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.eb = EB_TRUE;
	pkt_info.mb = MB_TRUE;
	ext_cb_size = hltests_add_nop_pkt(fd, ext_cb, ext_cb_size, &pkt_info);

	for (i = 0 ; i < max_ports ; i++) {
		if (tests_state->nic_ports_mask & BIT_ULL(i))
			continue;

		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.eb = EB_TRUE;
		pkt_info.mb = MB_TRUE;
		db_buf_size[i] = hltests_add_nop_pkt(fd, db_buf[i],
							db_buf_size[i],
							&pkt_info);

		execute_arr[0].cb_ptr = int_cb[i];
		execute_arr[0].cb_size = db_buf_size[i];
		execute_arr[0].queue_index = nic_base_qid + i * 4;

		execute_arr[1].cb_ptr = ext_cb;
		execute_arr[1].cb_size = ext_cb_size;
		execute_arr[1].queue_index = hltests_get_dma_down_qid(fd,
								STREAM0);

		rc = hltests_submit_cs(fd, NULL, 0, execute_arr, 2, 0, &seq);
		assert_int_not_equal(rc, 0);
	}

	for (i = 0 ; i < max_ports ; i++) {
		if (tests_state->nic_ports_mask & BIT_ULL(i))
			continue;

		rc = hltests_destroy_cb(fd, int_cb[i]);
		assert_int_equal(rc, 0);
	}

	for (i = 0 ; i < max_ports ; i++) {
		if (tests_state->nic_ports_mask & BIT_ULL(i))
			continue;

		rc = hltests_free_host_mem(fd, db_buf[i]);
		assert_int_equal(rc, 0);
	}

	rc = hltests_destroy_cb(fd, ext_cb);
	assert_int_equal(rc, 0);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest nic_tests[] = {
	cmocka_unit_test_setup(test_conn_1_thread,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_conn_8_threads,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_conn_512_threads,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_conn_1023_threads,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_wq_threads,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_print_ips_macs,
				hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_nic_disabled_qm,
				hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"nic [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = (int)(sizeof(nic_tests) / sizeof((nic_tests)[0]));

	hltests_parser(argc, argv, usage,
			HLTEST_DEVICE_MASK_GAUDI_ALL |
			HLTEST_DEVICE_MASK_GAUDI2_ALL |
			HLTEST_DEVICE_MASK_GAUDI3_ALL,
			nic_tests, num_tests);
	hltests_set_capabilities_mask(CAP_ARC_FW_LOAD_SCHED_MASK |
				CAP_ARC_FW_LOAD_PDMA_MASK);
	return hltests_run_group_tests("nic", nic_tests, (size_t)num_tests,
				hltests_nic_setup, hltests_nic_teardown);
}

#endif /* HLTESTS_LIB_MODE */
