// SPDX-License-Identifier: MIT

/*
 * Copyright 2019-2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#include "hlthunk_nic_tests.h"
#include "ini.h"

#include <asm-generic/errno-base.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <ctype.h>

#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <infiniband/hbldv.h>

#define POLL_CCQS_RETRIES_CNT	10
#define POLL_CCQS_SLEEP_USEC	(100 * USEC_PER_MSEC) /* 100 msecs */

static uint64_t nic_basic_get_supported_features_mask(int fd)
{
	uint64_t supported_features_mask = 0;

	supported_features_mask = BIT_ULL(OP_WRITE) | BIT_ULL(OP_RDV_WRITE) | BIT_ULL(OP_RDV_READ) |
					BIT_ULL(WTD_DWQ) | BIT_ULL(CC_BBR) | BIT_ULL(ODP) |
					BIT_ULL(REDUCTION) | BIT_ULL(PLAIN_RDMA) |
					BIT_ULL(RDMA_KEYS_IN_WQE);

	if (hltests_is_gaudi2(fd))
		supported_features_mask |= BIT_ULL(ENCAP_TYPE_VXLAN);
	else if (hltests_is_gaudi3(fd))
		supported_features_mask |= BIT_ULL(CC_SWIFT) | BIT_ULL(COMPRESSION) |
						BIT_ULL(SACK) | BIT_ULL(QP_LPBK);
	else
		printf("Unsupported ASIC type\n");

	return supported_features_mask;
}

static int nic_basic_parse_cfg(int fd, struct hltests_nic_test_cfg *cfg)
{
	return 0;
}

static int nic_basic_validate_cfg(int fd, struct hltests_nic_test_cfg *cfg)
{
	int i;

	/* Don't allow input of 0 QPs */
	for (i = 0 ; i < cfg->ports_num ; i++)
		assert_true(cfg->qps_per_port[i]);

	/* if WQ resides on HBM, WTD must be enabled */
	assert_true(cfg->wq_loc == LOC_HOST || cfg->wtd_en);

	/* Gaudi2 WTD is supported only with QMAN */
	assert_true(!hltests_is_gaudi2(fd) || !cfg->wtd_en || cfg->submission == QMAN);

	/* For the Read RDV, since both local and remote address fields are being used,
	 * we cannot use the local address field for sending the remote PI. Hence the
	 * local_key field is used for it, which means that read RDV with keys is not
	 * supported.
	 */
	assert_true(!((cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) && cfg->keys_en));

	if (cfg->plain_rdma_en) {
		assert_true(cfg->cmpl == CQ_USR);
		assert_true(cfg->test_opcode == TEST_OPCODE_LINEAR_WRITE);
		assert_true(cfg->submission == USER_FIFO);
		assert_true(cfg->wq_loc == LOC_HOST);
		assert_true(cfg->cc_mode == CC_MODE_DISABLED);
		assert_true(cfg->ms_type == NIC_MS_TYPE_NONE);
		assert_false(cfg->features_bitmap & BIT_ULL(QP_LPBK));
		assert_false(cfg->wtd_en || cfg->encap_en || cfg->sack_en || cfg->reduction_en ||
			     cfg->compression_en);
	}

	return 0;
}

static int nic_basic_alloc_qps_db(struct hltests_nic_test_params *params)
{
	return 0;
}

static int nic_basic_alloc_device_mem(struct hltests_nic_test_params *params)
{
	return 0;
}

static int nic_basic_alloc_host_mem_buffers(struct hltests_nic_test_params *params)
{
	return 0;
}

static void nic_basic_fill_port_app_params(struct hltests_nic_test_params *params, uint32_t port,
						struct hltests_nic_ib_app_params *app_params)
{
	app_params->advanced = !params->cfg->plain_rdma_en;
}

/**
 * nic_basic_get_user_fifo_num() - Returns how many user fifos are necessary.
 * @params: Test parameters.
 *
 * Return: how many user fifos are necessary.
 */
static uint32_t nic_basic_get_user_fifo_num(struct hltests_nic_test_params *params)
{
	return 1;
}

/**
 * nic_basic_get_user_fifo_type() - Returns the type of the user fifo at a given index.
 * @params:   Test parameters.
 * @fifo_idx: The index of the fifo whose type is needed.
 *
 * Return: The type of the fifo.
 */
static int nic_basic_get_user_fifo_type(struct hltests_nic_test_params *params, uint32_t fifo_idx)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;

	assert_int_equal(fifo_idx, 0);

	/* Note that for Gaudi2 we always reach the else condition, as WTD isn't supported with
	 * user fifo
	 */
	if (cfg->wtd_en)
		return HBLDV_USR_FIFO_TYPE_DWQ_LIN;
	else
		return HBLDV_USR_FIFO_TYPE_DB;
}

static int nic_basic_create_qps(struct hltests_nic_test_params *params)
{
	return 0;
}

static void nic_basic_fill_qp_attr(struct hltests_nic_qp *qp_p)
{

}

static int nic_basic_set_wq_buffers(struct hltests_nic_qp *qp_p)
{
	struct hltests_nic_test_params *params = qp_p->test_params;

	if (params->cfg->wtd_en)
		return nic_common_generic_set_device_wq_buffers(qp_p);
	else
		return nic_common_generic_set_user_wq_buffers(qp_p);
}

static int nic_basic_pre_runtime(struct hltests_nic_test_params *params)
{
	return 0;
}

static int submit(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	int rc;

	if (cfg->wtd_en)
		rc = hltests_nic_submit_wtd(params);
	else
		rc = hltests_nic_submit_db(params);

	return rc;
}

static int nic_basic_get_cqes_per_qp(const struct hltests_nic_qp *qp, uint32_t *total_req_cqes,
				     uint32_t *total_res_cqes)
{
	const struct hltests_nic_test_params *params = qp->test_params;
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t cqes_count;
	int fd = params->fd;

	cqes_count = params->wqes_in_cycle;

	/* While running plain_rdma mode, we should not receive responder CQE completion. In this
	 * case we want to make sure that only the requester CQEs are counted on in the for loop.
	 * This is only true for Gaudi3 (other ASICs still get responder CQEs).
	 */
	*total_req_cqes = cfg->single_cmpl ? 1 : cqes_count;
	*total_res_cqes = (cfg->plain_rdma_en && hltests_is_gaudi3(fd)) ?
				  0 :
				  *total_req_cqes;

	return 0;
}

/**
 * nic_basic_get_sob_val() - Computes the expected SOB value.
 * @params: Test parameters.
 * @port: The relevant port for the SOB params.
 */
static void nic_basic_get_expected_sob_val(struct hltests_nic_test_params *params, uint32_t port)
{
	struct hltests_nic_sob_params *sob_params;
	struct hltests_nic_test_cfg *cfg;
	uint32_t _local_sob_val, _remote_sob_val, qps_per_port, wqes_submitted;

	cfg = params->cfg;
	sob_params = &params->sob_params[port];
	qps_per_port = params->num_qps_per_port[port];
	wqes_submitted = params->wqes_in_cycle;

	/* WR-RDV: Local SOB gets updated only when Sender side received an ACK for the
	 *         LINEAR_WRITE transaction.
	 *         Remote SOB gets updated when we receive ACK for the RDV WQE that is sent from
	 *         receiver side to sender side and when the sender side sends the LINEAR_WRITE
	 *         transaction, hence the X2 multiplication.
	 * RD-RDV: Only Remote SOB gets updated as there is no wqe on the sender side.
	 */
	if (IS_RDV(cfg->features_bitmap)) {
		_local_sob_val = (qps_per_port >> 1) * wqes_submitted;
		_remote_sob_val = _local_sob_val * 2;

		if (cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ)
			_local_sob_val = 0;
	} else {
		_local_sob_val = qps_per_port * wqes_submitted;
		_remote_sob_val = _local_sob_val;
	}

	sob_params->local_sob_val += _local_sob_val;
	sob_params->remote_sob_val += _remote_sob_val;
}

static uint32_t get_total_cqes(struct hltests_nic_test_params *params, uint32_t port)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t total_cqes, qps_per_port, num_wqes_in_wq;

	qps_per_port = params->num_qps_per_port[port];
	num_wqes_in_wq = params->num_wqes_in_wq;

	/* WR-RDV: 2 CQEs for each WQE in the sender QP and 1 CQE for each WQE in the receiver WQE.
	 * RD-RDV: 2 CQEs for each WQE in the receiver QP only.
	 * WRITE: 2 CQEs for each WQE.
	 */
	if (cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
		total_cqes = num_wqes_in_wq * 3 * (qps_per_port / 2);
	else if (cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ)
		total_cqes = num_wqes_in_wq * 2 * (qps_per_port / 2);
	else
		total_cqes = num_wqes_in_wq * 2 * qps_per_port;

	return total_cqes;
}

static int get_max_num_cycles(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t port;
	int fd, max_num_cycles, port_idx;
	bool is_gaudi2;

	fd = params->fd;
	is_gaudi2 = hltests_is_gaudi2(fd);
	max_num_cycles = 1;

	if (cfg->cmpl == CQ_USR) {
		uint32_t total_cqes, cq_buf_len;
		int num_cycles = 1;

		for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
			port = cfg->ports[port_idx];

			total_cqes = get_total_cqes(params, port);
			cq_buf_len = params->cq->user_cq.cq_buf_len;

			num_cycles = (total_cqes / cq_buf_len) + 1;

			if (max_num_cycles < num_cycles)
				max_num_cycles = num_cycles;
		}
	}

	/* Gaudi2 requires at least two cycles */
	if (is_gaudi2 && max_num_cycles == 1)
		max_num_cycles = 2;

	return next_pow2(max_num_cycles);
}

static int poll_post_cc(struct hltests_nic_test_params *params)
{
	struct hltests_nic_ccqs_poll_info ccq_poll_info = {};
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_ccq *ccqs = params->ccqs;
	struct hltests_nic_qp **qps_db, *qp_p;
	struct hltests_state *tests_state;
	uint32_t port, qp, qps_per_port, first_conn_id;
	int rc, port_idx, i;

	tests_state = params->test_ctx->tests_state;
	ccq_poll_info.ccqs = ccqs;
	qps_db = params->qps;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];
		qps_per_port = params->num_qps_per_port[port];

		first_conn_id = qps_db[port][0].conn_id;

		for (qp = 0 ; qp < qps_per_port ; qp++) {
			qp_p = &qps_db[port][qp];

			for (i = 0 ; i < POLL_CCQS_RETRIES_CNT ; i++) {
				rc = hltests_nic_ccq_poll(&ccqs[port], first_conn_id, qps_per_port);

				/* No new element was polled, try again (this is the only valid
				 * non 0 rc)
				 */
				if (rc == -ENOENT) {
					usleep(POLL_CCQS_SLEEP_USEC);
					continue;
				}

				break;
			}

			if (rc)
				return rc;

			rc = hltests_nic_post_cc(tests_state, &ccq_poll_info, port,
						cfg->cc_mode == CC_MODE_SWIFT, qp_p->conn_id);
			if (rc)
				return rc;
		}
	}

	hltests_nic_print_time_elapsed(&params->base, "poll CCQs + post CC", cfg->verbose);

	return 0;
}

/**
 * Wait for a few seconds before submitting wqes. This is needed
 * for e2e, where both peers need to be ready to receive traffic.
 */
static void wait_to_submit(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;

	if (!cfg->e2e.enabled)
		return;

	if (cfg->e2e.seconds_to_wait_to_submit > 0) {
		printf("\nsleep %ds before doorbell\n", cfg->e2e.seconds_to_wait_to_submit);
		sleep(cfg->e2e.seconds_to_wait_to_submit);
	} else {
		printf("\nwait for doorbell\n");
		getchar();
	}
}

static int nic_basic_runtime(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hlthunk_time_sync_info begin, end;
	uint32_t num_wqes_in_wq;
	int fd, rc, iter, cycle, num_cycles;

	fd = params->fd;
	num_wqes_in_wq = params->num_wqes_in_wq;
	num_cycles = get_max_num_cycles(params);

	/* num_wqes_in_wq should be divided equally between cycles */
	assert_false(num_wqes_in_wq % num_cycles);

	params->wqes_in_cycle = num_wqes_in_wq / num_cycles;

	for (iter = 0 ; iter < cfg->runtime_iterations ; iter++) {
		printf("\nruntime iteration %d\n", iter);

		if (cfg->migration.enable && iter == cfg->migration.runtime_iterations_trigger) {
			if (cfg->migration.check_event) {
				rc = nic_common_migration_check_event(params);
				assert_int_equal(rc, 0);
			}
			rc = nic_common_migrate_qps(params);
			assert_int_equal(rc, 0);
		}

		/* Reset the base in the beginning of each runtime iteration */
		clock_gettime(CLOCK_MONOTONIC_RAW, &params->base);

		rc = nic_common_reset_dst_buffers(params, params->qps, 0);
		if (rc)
			return rc;

		if (cfg->cmpl == SOB)
			nic_common_clear_sobs(params);

		hlthunk_get_time_sync_info(fd, &begin);

		for (cycle = 0 ; cycle < num_cycles ; cycle++) {
			printf("\ncycle %d\n", cycle);

			nic_common_generic_config_wqes(params);

			wait_to_submit(params);

			rc = submit(params);
			if (rc)
				return rc;

			rc = nic_common_complete(params);
			if (rc)
				return rc;
		}

		hlthunk_get_time_sync_info(fd, &end);

		if (cfg->print_bw) {
			uint64_t data_size, qps_per_port;
			double bw;

			data_size = params->data_size;
			qps_per_port = cfg->qps_per_port[0];

			bw = get_bw_gigabit_from_timesync(data_size * qps_per_port, &begin, &end);
			printf("\n%sB/W: %.02lf Gb/s%s\n", KRED, bw, KNRM);
		}

		printf("\n");

		if (cfg->data_cmp) {
			rc = nic_common_data_compare(params, params->qps, 0);
			hltests_nic_print_time_elapsed(&params->base, "data compare", cfg->verbose);
			if (rc)
				return rc;
		}

		if (cfg->cc_mode != CC_MODE_DISABLED)
			poll_post_cc(params);
	}

	printf("\n");

	return 0;
}

static int nic_basic_destroy_qps(struct hltests_nic_test_params *params)
{
	return 0;
}

static void nic_basic_free_wq_buffers(struct hltests_nic_qp *qp_p)
{
	if (qp_p->test_params->cfg->wtd_en) {
		hlthunk_free(qp_p->swq_buf);
		hlthunk_free(qp_p->rwq_buf);
	}
}

static void nic_basic_destroy_qps_db(struct hltests_nic_test_params *params)
{

}

static struct hltests_nic_qp *
nic_basic_find_qp_by_port_and_qpn(struct hltests_nic_test_params *params, uint32_t port,
				  uint32_t qpn)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t qp_idx, qps_per_port;

	qps_per_port = params->num_qps_per_port[port];

	for (qp_idx = 0; qp_idx < qps_per_port; qp_idx++) {
		struct hltests_nic_qp *qp = &params->qps[port][qp_idx];

		if (qp->conn_id == qpn)
			return qp;
	}

	if (!cfg->migration.enable || port != cfg->migration.new_port)
		return NULL;

	for (qp_idx = 0; qp_idx < params->num_qps_per_port[cfg->migration.old_port]; qp_idx++) {
		struct hltests_nic_qp *qp = &params->migration.qps[qp_idx];

		if (qp->conn_id == qpn) {
			D("Redirecting port %u, qpn %u to migration source: port %u, qpn %u", port,
			  qpn, qp->migration_old_qp->port, qp->migration_old_qp->conn_id);
			return qp->migration_old_qp;
		}
	}

	return NULL;
}

static int nic_basic_calculate_total_cqes(struct hltests_nic_test_params *params,
					  uint32_t *total_req_cqes, uint32_t *total_res_cqes)
{
	return nic_common_calculate_total_cqes(params, params->qps, params->num_qps_per_port,
					       ARRAY_SIZE(params->num_qps_per_port), total_req_cqes,
					       total_res_cqes);
}

static struct hltests_nic_test_funcs nic_basic_test_funcs = {
	.get_supported_features_mask = nic_basic_get_supported_features_mask,
	.parse_cfg = nic_basic_parse_cfg,
	.validate_cfg = nic_basic_validate_cfg,
	.set_cq_params = NULL,
	.alloc_qps_db = nic_basic_alloc_qps_db,
	.alloc_device_mem = nic_basic_alloc_device_mem,
	.alloc_host_mem_buffers = nic_basic_alloc_host_mem_buffers,
	.fill_port_app_params = nic_basic_fill_port_app_params,
	.get_user_fifo_num = nic_basic_get_user_fifo_num,
	.get_user_fifo_type = nic_basic_get_user_fifo_type,
	.create_qps = nic_basic_create_qps,
	.fill_qp_attr = nic_basic_fill_qp_attr,
	.get_expected_sob_val = nic_basic_get_expected_sob_val,
	.get_cqes_per_qp = nic_basic_get_cqes_per_qp,
	.find_qp_by_port_and_qpn = nic_basic_find_qp_by_port_and_qpn,
	.calculate_total_cqes = nic_basic_calculate_total_cqes,
	.set_wq_buffers = nic_basic_set_wq_buffers,
	.pre_runtime = nic_basic_pre_runtime,
	.runtime = nic_basic_runtime,
	.destroy_qps = nic_basic_destroy_qps,
	.free_wq_buffers = nic_basic_free_wq_buffers,
	.destroy_qps_db = nic_basic_destroy_qps_db,
};

void nic_basic_set_test_funcs(int fd)
{
	struct hltests_nic_test_ctx *test_cxt = get_nic_ctx_from_fd(fd);

	test_cxt->funcs = &nic_basic_test_funcs;
}
