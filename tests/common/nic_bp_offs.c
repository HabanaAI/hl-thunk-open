// SPDX-License-Identifier: MIT

/*
 * Copyright 2019-2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_nic_tests.h"
#include "hlthunk_tests.h"

#include <asm-generic/errno-base.h>
#include <stdarg.h>
#include <stddef.h>

#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <infiniband/hbldv.h>

#define WAIT_FOR_BP_TIMEOUT_SEC		20 /* 20 seconds */
#define WAIT_FOR_BP_TIMEOUT_PLDM_SEC	600 /* 10 minutes */

static uint64_t nic_bp_offs_get_supported_features_mask(int fd)
{
	uint64_t supported_features_mask = BIT_ULL(OP_WRITE);

	if (hltests_is_gaudi3(fd))
		supported_features_mask |= BIT_ULL(SACK);

	return supported_features_mask;
}

static int nic_bp_offs_parse_cfg(int fd, struct hltests_nic_test_cfg *cfg)
{
	return 0;
}

static int nic_bp_offs_validate_cfg(int fd, struct hltests_nic_test_cfg *cfg)
{
	int i;

	/* Don't allow input of 0 QPs */
	for (i = 0; i < cfg->ports_num; i++)
		assert_true(cfg->qps_per_port[i]);

	assert_true(cfg->runtime_iterations == 1);

	/* Due to test limitations, WQ must reside on host, this is not a HW limitation. */
	assert_true(cfg->wq_loc == LOC_HOST);
	assert_true(cfg->submission == USER_FIFO);

	/* In order to catch the backpressure indications by SW, large WQEs needs to be used and
	 * also a good amount of them. This way it is ensured that the backpressure indication
	 * happens slowly enough to be captured by SW. The numbers below are big enough for the test
	 * to pass, but the test could pass with smaller numbers as well.
	 */
	if (hltests_is_gaudi2(fd)) {
		assert_true(cfg->data_size_shift >= 24);
		assert_true(cfg->wqe_size_shift >= 17);
		assert_true(cfg->data_size_shift - cfg->wqe_size_shift >= 7);
	} else {
		/* Lower numbers are enough for PLDM, with ASIC these numbers my change */
		assert_true(cfg->data_size_shift >= 20);
		assert_true(cfg->wqe_size_shift >= 15);
		assert_true(cfg->data_size_shift - cfg->wqe_size_shift >= 5);
	}

	return 0;
}

static int nic_bp_offs_alloc_qps_db(struct hltests_nic_test_params *params)
{
	return 0;
}

static int nic_bp_offs_alloc_device_mem(struct hltests_nic_test_params *params)
{
	return 0;
}

static int nic_bp_offs_alloc_host_mem_buffers(struct hltests_nic_test_params *params)
{
	return 0;
}

static void nic_bp_offs_fill_port_app_params(struct hltests_nic_test_params *params, uint32_t port,
					     struct hltests_nic_ib_app_params *app_params)
{
	struct hltests_device *hdev = get_hdev_from_fd(params->fd);
	struct hltests_nic_asic_funcs *nic_funcs = hdev->asic_funcs->nic_funcs;
	int i;

	app_params->advanced = true;
	nic_funcs->fill_bp_offs_params(params->fd, port, &params->bp_offs_base_id[port],
				       &params->num_bp_offs[port]);

	for (i = 0; i < params->num_bp_offs[port]; i++)
		app_params->bp_offs[i] = nic_funcs->get_mem_cmpl_addr(params->fd, BP_MON_ID +
					 params->bp_offs_base_id[port] + i);
}

/**
 * nic_bp_offs_get_user_fifo_num() - Returns how many user fifos are necessary.
 * @params: Test parameters.
 *
 * Return: how many user fifos are necessary.
 */
static uint32_t nic_bp_offs_get_user_fifo_num(struct hltests_nic_test_params *params)
{
	return 1;
}

/**
 * nic_bp_offs_get_user_fifo_type() - Returns the type of the user fifo at a given index.
 * @params:   Test parameters.
 * @fifo_idx: The index of the fifo whose type is needed.
 *
 * Return: The type of the fifo.
 */
static int nic_bp_offs_get_user_fifo_type(struct hltests_nic_test_params *params, uint32_t fifo_idx)
{
	assert_int_equal(fifo_idx, 0);

	return HBLDV_USR_FIFO_TYPE_DB;
}

static int nic_bp_offs_create_qps(struct hltests_nic_test_params *params)
{
	return 0;
}

static void nic_bp_offs_fill_qp_attr(struct hltests_nic_qp *qp_p)
{
}

static int nic_bp_offs_set_wq_buffers(struct hltests_nic_qp *qp_p)
{
	return nic_common_generic_set_user_wq_buffers(qp_p);
}

static int nic_bp_offs_pre_runtime(struct hltests_nic_test_params *params)
{
	return 0;
}

static int nic_bp_offs_wait_for_bp(struct hltests_nic_qp *qp_p)
{
	uint32_t j, bp_offs_triggered, num_bp_offs, priority,
		mask_bp_offs_triggered = 0, mask_bp_offs_done = 0, port = qp_p->port;
	struct hltests_nic_test_params *params = qp_p->test_params;
	struct hltests_device *hdev;
	struct timespec base, now;
	double timeout_secs;
	int fd = params->fd;

	hdev = get_hdev_from_fd(fd);
	num_bp_offs = params->num_bp_offs[port];

	timeout_secs = (uint64_t)(hltests_is_pldm(fd) ? WAIT_FOR_BP_TIMEOUT_PLDM_SEC :
							WAIT_FOR_BP_TIMEOUT_SEC);

	/* In Gaudi2/3, the priority of data packets is hard-coded 3 */
	priority = hltests_is_gaudi2(fd) || hltests_is_gaudi3(fd) ? 3 : qp_p->req_ctx.priority;

	clock_gettime(CLOCK_MONOTONIC_RAW, &base);
	clock_gettime(CLOCK_MONOTONIC_RAW, &now);
	while (get_timediff_sec(&base, &now) < timeout_secs) {
		for (j = 0; j < num_bp_offs; j++) {
			bp_offs_triggered = hdev->asic_funcs->nic_funcs->read_mem_cmpl(fd,
					    BP_MON_ID + params->bp_offs_base_id[port] + j,
					    params->bp_cmpl_mem_hdl);

			if (bp_offs_triggered & BIT(priority))
				mask_bp_offs_triggered |= BIT(j);
			else if (mask_bp_offs_triggered & BIT(j))
				mask_bp_offs_done |= BIT(j);
		}

		if (mask_bp_offs_done == BIT(num_bp_offs) - 1)
			break;

		usleep(100);
		clock_gettime(CLOCK_MONOTONIC_RAW, &now);
	}

	if (mask_bp_offs_done != BIT(num_bp_offs) - 1) {
		W("port: %u, qp: %u", qp_p->port, qp_p->id);
		W("mask_bp_offs_triggered: %u", mask_bp_offs_triggered);
		W("mask_bp_offs_done: %u", mask_bp_offs_done);
		assert_int_equal(mask_bp_offs_done, BIT(num_bp_offs) - 1);
	}

	return 0;
}

static int submit(struct hltests_nic_test_params *params, uint32_t port)
{
	struct hltests_nic_qp *qp_p;
	uint32_t qp, qps_per_port;
	int rc;

	qps_per_port = params->num_qps_per_port[port];

	for (qp = 0; qp < qps_per_port; qp++) {
		qp_p = &params->qps[port][qp];

		rc = nic_common_generic_submit_user_fifo_db_qp(qp_p);
		if (rc)
			return rc;

		rc = nic_bp_offs_wait_for_bp(qp_p);
		if (rc)
			return rc;
	}

	return 0;
}

static int nic_bp_offs_runtime(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_asic_funcs *nic_funcs;
	struct hltests_device *hdev;
	uint32_t port;
	int rc, port_idx, fd;

	fd = params->fd;
	hdev = get_hdev_from_fd(fd);
	nic_funcs = hdev->asic_funcs->nic_funcs;

	rc = nic_common_reset_dst_buffers(params, params->qps, 0);
	if (rc)
		return rc;

	params->bp_cmpl_mem_hdl = nic_funcs->map_lbw_block(fd, &params->bp_cmpl_mem_size);
	assert_non_null(params->bp_cmpl_mem_hdl);

	nic_funcs->clear_lbw_memory(fd, params->bp_cmpl_mem_hdl, BP_MON_ID, MAX_NUM_OF_BP_OFFSETS);

	/* submit 1 wqe less than num_wqes_in_wq to WA the issue of sending all WQEs at once in
	 * Gaudi2.
	 */
	params->wqes_in_cycle = params->num_wqes_in_wq - 1;

	nic_common_generic_config_wqes(params);

	for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
		port = cfg->ports[port_idx];

		rc = submit(params, port);
		if (rc)
			return rc;
	}

	hltests_nic_print_time_elapsed(&params->base, "submit + got BP", cfg->verbose);

	rc = nic_funcs->unmap_lbw_block(fd, params->bp_cmpl_mem_hdl, params->bp_cmpl_mem_size);
	assert_int_equal(rc, 0);

	return 0;
}

static int nic_bp_offs_destroy_qps(struct hltests_nic_test_params *params)
{
	return 0;
}

static void nic_bp_offs_free_wq_buffers(struct hltests_nic_qp *qp_p)
{
}

static void nic_bp_offs_destroy_qps_db(struct hltests_nic_test_params *params)
{
}

static struct hltests_nic_test_funcs nic_bp_offs_test_funcs = {
	.get_supported_features_mask = nic_bp_offs_get_supported_features_mask,
	.parse_cfg = nic_bp_offs_parse_cfg,
	.validate_cfg = nic_bp_offs_validate_cfg,
	.set_cq_params = NULL,
	.alloc_qps_db = nic_bp_offs_alloc_qps_db,
	.alloc_device_mem = nic_bp_offs_alloc_device_mem,
	.alloc_host_mem_buffers = nic_bp_offs_alloc_host_mem_buffers,
	.fill_port_app_params = nic_bp_offs_fill_port_app_params,
	.get_user_fifo_num = nic_bp_offs_get_user_fifo_num,
	.get_user_fifo_type = nic_bp_offs_get_user_fifo_type,
	.create_qps = nic_bp_offs_create_qps,
	.fill_qp_attr = nic_bp_offs_fill_qp_attr,
	.set_wq_buffers = nic_bp_offs_set_wq_buffers,
	.pre_runtime = nic_bp_offs_pre_runtime,
	.runtime = nic_bp_offs_runtime,
	.destroy_qps = nic_bp_offs_destroy_qps,
	.free_wq_buffers = nic_bp_offs_free_wq_buffers,
	.destroy_qps_db = nic_bp_offs_destroy_qps_db,
};

void nic_bp_offs_set_test_funcs(int fd)
{
	struct hltests_nic_test_ctx *test_cxt = get_nic_ctx_from_fd(fd);

	test_cxt->funcs = &nic_bp_offs_test_funcs;
}
