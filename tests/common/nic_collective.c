// SPDX-License-Identifier: MIT
/*
 * Copyright 2019-2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#include "hlthunk_nic_tests.h"
#include "hlthunk_tests.h"
#include "ini.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <infiniband/verbs.h>

#if !defined(HLTESTS_LIB_MODE)
/* These includes are necessary for cmocka */
#include <setjmp.h>
#include <stdarg.h>

#include <cmocka.h>
#endif /* !defined(HLTESTS_LIB_MODE) */

/* Setup */
static int cfg_parser(void *user, const char *section, const char *name, const char *value);

/* Allocation, initialization and cleanup */
static int alloc_coll_comm_groups(struct hltests_nic_test_params *params);
static void dealloc_coll_comm_groups(struct hltests_nic_test_params *params);

static int alloc_qp_mem_buffers(struct hltests_nic_test_params *params);

static int alloc_wqe_arrays(struct hltests_nic_test_params *params);
static void dealloc_wqe_arrays(struct hltests_nic_test_params *params);

static int initialize_qps(struct hltests_nic_test_params *params,
			  enum hltests_nic_coll_qp_type type, uint32_t port);
static void uninitialize_qps(struct hltests_nic_test_params *params,
			     enum hltests_nic_coll_qp_type type, uint32_t port);

static void config_wqes(struct hltests_nic_test_params *params);

static void assign_device_data_buffers_to_qps(const struct hltests_nic_test_params *params,
					      const struct hltests_memory *mem,
					      uint64_t local_offset, uint64_t remote_offset);

static int copy_qp_buffers_host_to_dev(struct hltests_nic_test_params *params);

static void reset_qps_pi(struct hltests_nic_test_params *params);

static int nic_collective_reset_dst_buffers(struct hltests_nic_test_params *params);

static int coll_op_comm_group_init(struct hltests_nic_coll_comm_group_new *comm_group);

/* Runtime logic */
static int run_coll_op(struct hltests_nic_test_params *params);
static int run_coll_op_legacy(struct hltests_nic_test_params *params);
static int run_coll_op_multi_lag_rank(struct hltests_nic_test_params *params);
static int run_coll_op_multi_context(struct hltests_nic_test_params *params);
static int run_coll_op_internal(struct hltests_nic_coll_comm_group_new *comm_group);

static int nic_collective_calculate_total_cqes(struct hltests_nic_test_params *params,
					       uint32_t *total_req_cqes, uint32_t *total_res_cqes);
static int data_compare(struct hltests_nic_test_params *params);

/* Utilities  */
static struct hltests_nic_qp *
nic_collective_find_qp_by_port_and_qpn(struct hltests_nic_test_params *params, uint32_t port,
				       uint32_t qp_num);

static void nic_collective_get_expected_sob_val(struct hltests_nic_test_params *params,
						uint32_t port);
static size_t get_device_qp_buffers_count(const struct hltests_nic_test_params *params);
static inline size_t get_max_coll_comm_groups(struct hltests_nic_test_params *params);

/**
 * nic_collective_get_supported_features_mask() - Returns a bitmask of all supported features.
 * @fd: File descriptor of the open device.
 *
 * Return: bitmask of all supported features.
 */
static uint64_t nic_collective_get_supported_features_mask(int fd)
{
	uint64_t supported_features_mask = 0;

	if (!hltests_is_gaudi3(fd)) {
		printf("Unsupported ASIC type\n");
		return 0;
	}

	supported_features_mask = BIT_ULL(OP_WRITE) | BIT_ULL(OP_RDV_WRITE) | BIT_ULL(OP_RDV_READ) |
				  BIT_ULL(MS_TYPE_DUAL) | BIT_ULL(COMPRESSION) | BIT_ULL(ODP) |
				  BIT_ULL(REDUCTION) | BIT_ULL(SACK) | BIT_ULL(QP_LPBK);

	return supported_features_mask;
}

/**
 * nic_collective_parse_cfg() - Parses the configuration section that's specific to the collective
 *				tests.
 * @fd:  File descriptor of the open device.
 * @cfg: Out, the configuration structure to update with the parsed configuration.
 *
 * Return: 0 on success.
 */
static int nic_collective_parse_cfg(int fd, struct hltests_nic_test_cfg *cfg)
{
	const char *config_filename = hltests_get_config_filename();

	printf("Parsing collective configuration\n");

	if (ini_parse(config_filename, cfg_parser, cfg) < 0) {
		fail_msg("Can't load %s\n", config_filename);
		return -EFAULT;
	}

	/* TODO: SW-169786: Add support for scale up ports */
	if (cfg->coll_type == COLL_TYPE_DIRECT) {
		struct hlthunk_nic_get_ports_masks_out ports_masks;
		uint64_t ports_mask;
		uint32_t port;
		int rc;

		rc = hlthunk_nic_get_ports_masks(fd, &ports_masks);
		assert_int_equal(rc, 0);

		cfg->ports_mask &= ports_masks.ext_ports_mask;
		cfg->ports_num = 0;

		/* Recreate port list with the enabled ports only */
		for (ports_mask = cfg->ports_mask, port = 0; ports_mask > 0;
		     ports_mask >>= 1, port++) {
			if (!(ports_mask & 0x1))
				continue;

			cfg->ports[cfg->ports_num] = port;
			cfg->ports_num++;
		}
	}

	assert_int_not_equal(cfg->ports_num, 0);

	return 0;
}

/**
 * nic_collective_print_cfg() - Prints the configuration section that's specific to the collective
 *				tests.
 * @cfg: The configuration to print.
 */
static void nic_collective_print_cfg(const struct hltests_nic_test_cfg *cfg)
{
	size_t port_idx;

	/* TODO - SW-114993: update to represent coll qp ports */
	printf("total scale out collective qps_per_port:");
	for (port_idx = 0; port_idx < cfg->ports_num; port_idx++)
		printf(" %4zu", cfg->coll_qps_count[COLL_QP_TYPE_SCALE_OUT]);

	printf("\n");

	if (cfg->coll_lpbk_qps_count[COLL_QP_TYPE_SCALE_OUT]) {
		printf("scale out lpbk_qps_per_port:            ");
		for (port_idx = 0; port_idx < cfg->ports_num; port_idx++)
			printf(" %4zu", cfg->coll_lpbk_qps_count[COLL_QP_TYPE_SCALE_OUT]);

		printf("\n");
	}

	/* TODO - SW-114993: update to represent coll qp ports */
	printf("total scale up collective qps_per_port: ");
	for (port_idx = 0; port_idx < cfg->ports_num; port_idx++)
		printf(" %4zu", cfg->coll_qps_count[COLL_QP_TYPE_SCALE_UP]);

	printf("\n");

	if (cfg->coll_lpbk_qps_count[COLL_QP_TYPE_SCALE_UP]) {
		printf("scale up lpbk_qps_per_port:             ");
		for (port_idx = 0; port_idx < cfg->ports_num; port_idx++)
			printf(" %4zu", cfg->coll_lpbk_qps_count[COLL_QP_TYPE_SCALE_UP]);

		printf("\n");
	}
}

/**
 * nic_collective_validate_cfg() - Validates the loaded configuration, fails the test if something
 *				   is misconfigured.
 * @fd:  File descriptor of the open device.
 * @cfg: The test's configuration structure.
 *
 * Return: 0 on success.
 */
static int nic_collective_validate_cfg(int fd, struct hltests_nic_test_cfg *cfg)
{
	enum hltests_nic_coll_qp_type coll_qp_type;

	assert_true(cfg->coll_op != COLL_OP_DISABLED);

	/* Collective operations supported on Gaudi3 and onwards only*/
	assert_true(hltests_is_gaudi3(fd));

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		/* For collective operations, non multi-context cases, the test supports 1 QP per
		 * port for linear write, and multiple of 2 for RDV tests.
		 */
		assert_true((cfg->coll_qps_count[coll_qp_type] == 0) ||
			    (cfg->coll_qps_count[coll_qp_type] == 1) ||
			    (cfg->coll_op == COLL_OP_MODE_MULTI_CONTEXT &&
			     ((cfg->test_opcode == TEST_OPCODE_LINEAR_WRITE) ||
			      (cfg->qps_per_port[coll_qp_type] % 2 == 0))));
	}

	/* Have at least one collective QP */
	assert_true(cfg->coll_qps_count[COLL_QP_TYPE_SCALE_UP] ||
		    cfg->coll_qps_count[COLL_QP_TYPE_SCALE_OUT]);

	/* Have at least one collective QP be zero, i.e. we currently only support either
	 * scale up or scale out but not both simultaneously
	 */
	assert_true(!cfg->coll_qps_count[COLL_QP_TYPE_SCALE_UP] ||
		    !cfg->coll_qps_count[COLL_QP_TYPE_SCALE_OUT]);

	/* Gaudi3 and onward don't support QMAN */
	assert_true(cfg->submission == USER_FIFO);

	assert_true(cfg->test_opcode == TEST_OPCODE_LINEAR_WRITE ||
		    cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE ||
		    cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ);

	/* Collective doesn't support single stride */
	assert_true(cfg->ms_type == NIC_MS_TYPE_NONE || cfg->ms_type == NIC_MS_TYPE_DUAL);

	assert_true(!cfg->wtd_en);

	/* Collective operations are not part of the RoCE2 standard */
	assert_false(cfg->plain_rdma_en);

	/* disregard_rank may only be used with direct patcher. When disregard_rank is used, 1 rank
	 * is used multiple times. Meaning reduction cannot be used, as reduction operations will be
	 * done on the same buffer more than once.
	 */
	assert_true(!cfg->disregard_rank ||
		    (cfg->coll_type == COLL_TYPE_DIRECT && !cfg->reduction_en));

	return 0;
}

/**
 * nic_collective_alloc_qps_db() - Allocates and initializes memory structures for all collective
 *				   qps.
 * @params: Test parameters struct.
 *
 * Return: 0 on success
 *
 * This function allocates a qp structure for each permutation of:
 * * collective type (scale out/up)
 * * port
 * * collective qp number
 */
static int nic_collective_alloc_qps_db(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	enum hltests_nic_coll_qp_type coll_qp_type;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		size_t port_idx;

		for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
			uint32_t port;
			int rc;

			port = cfg->ports[port_idx];

			params->coll_qps[coll_qp_type][port] = hlthunk_malloc(
				sizeof(struct hltests_nic_qp) * cfg->coll_qps_count[coll_qp_type]);
			assert_non_null(params->coll_qps[coll_qp_type][port]);

			rc = initialize_qps(params, coll_qp_type, port);
			assert_int_equal(rc, 0);
		}
	}

	return 0;
}

/**
 * nic_collective_alloc_device_mem() - Allocates memory for data buffers on device memory, then
 *				       assigns them to the QPs.
 * @params: Test parameters struct.
 *
 * Return: 0 on success
 */
static int nic_collective_alloc_device_mem(struct hltests_nic_test_params *params)
{
	uint64_t local_offset = 0, remote_offset = 0;
	struct hltests_memory dev_mem;
	int rc;

	rc = nic_patcher_allocate_device_data_buffers(params, get_device_qp_buffers_count(params),
						      &dev_mem, &local_offset, &remote_offset);
	assert_int_equal(rc, 0);

	assign_device_data_buffers_to_qps(params, &dev_mem, local_offset, remote_offset);

	return 0;
}

/**
 * nic_collective_alloc_host_mem_buffers() - Allocates buffers on host memory.
 *					     Currently only QP data buffers are allocated and
 *					     assigned.
 * @params: Test parameters struct.
 *
 * Return: 0 on success
 */
static int nic_collective_alloc_host_mem_buffers(struct hltests_nic_test_params *params)
{
	/* dealloc of qp mem buffers is taken care of in global host mem buffers dealloc */
	return alloc_qp_mem_buffers(params);
}

/**
 * nic_collective_fill_port_app_params() - Updates the app_params in accordance to the running test
 *					   and port.
 * @params:	Test parameters.
 * @port:	The port whose app params to update.
 * @app_params:	Out, the app params to update.
 */
static void nic_collective_fill_port_app_params(struct hltests_nic_test_params *params,
						uint32_t port,
						struct hltests_nic_ib_app_params *app_params)
{
	app_params->advanced = true;
}

/**
 * nic_collective_get_user_fifo_num() - Returns how many user fifos are necessary.
 * @params: Test parameters.
 *
 * Return: how many user fifos are necessary.
 */
static uint32_t nic_collective_get_user_fifo_num(struct hltests_nic_test_params *params)
{
	return 1;
}

/**
 * nic_collective_get_user_fifo_type() - Returns the type of the user fifo at a given index.
 * @params:   Test parameters.
 * @fifo_idx: The index of the fifo whose type is needed.
 *
 * Return: The type of the fifo.
 */
static int nic_collective_get_user_fifo_type(struct hltests_nic_test_params *params,
					     uint32_t fifo_idx)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;

	assert_int_equal(fifo_idx, 0);

	switch (cfg->coll_type) {
	case COLL_TYPE_CONTEXT:
		return (cfg->rdv_type == HLTESTS_NIC_RDV_V_OP) ? HBLDV_USR_FIFO_TYPE_COLL_OPS_LONG :
								 HBLDV_USR_FIFO_TYPE_COLL_OPS_SHORT;
	case COLL_TYPE_DIRECT:
		return (cfg->rdv_type == HLTESTS_NIC_RDV_V_OP) ?
			       HBLDV_USR_FIFO_TYPE_COLL_DIR_OPS_LONG :
			       HBLDV_USR_FIFO_TYPE_COLL_DIR_OPS_SHORT;
	default:
		E("Invalid coll type! %u", cfg->coll_type);
		fail();
	}

	return -1;
}

/**
 * nic_collective_create_qps() - Allocates collective QP numbers, creates matching QPs for each
 *				 port, then initializes the QPs
 * @params: Test parameters.
 *
 * Return: 0 on success
 */
static int nic_collective_create_qps(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	enum hltests_nic_coll_qp_type coll_qp_type;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		int rc = nic_patcher_create_qps(params, params->coll_qps[coll_qp_type],
						cfg->coll_qps_count[coll_qp_type],
						coll_qp_type == COLL_QP_TYPE_SCALE_OUT,
						/* Direct patcher needs to reserve collective QPs */
						cfg->coll_type == COLL_TYPE_DIRECT);

		assert_int_equal(rc, 0);
	}

	return 0;
}

/**
 * nic_collective_fill_qp_attr() - Fills up the QP's requester context.
 * @qp: Out, QP structure.
 */
static void nic_collective_fill_qp_attr(struct hltests_nic_qp *qp)
{
	const struct hltests_nic_test_cfg *cfg = qp->test_params->cfg;
	struct hltests_nic_requester_conn_ctx *req_ctx = &qp->req_ctx;

	if (!qp->is_coll)
		return;

	/* Update flag before it's sent to `hbldv_modify_qp`, only direct patcher uses collective
	 * QPs
	 */
	qp->is_coll = (cfg->coll_type == COLL_TYPE_DIRECT);

	switch (cfg->coll_op) {
	case COLL_OP_MODE_LEGACY: {
		req_ctx->coll_lag_idx = 0;
		req_ctx->coll_last_in_lag = 1;
		req_ctx->coll_lag_size = 1;
		break;
	}
	case COLL_OP_MODE_MULTI_LAG:
	case COLL_OP_MODE_MULTI_CONTEXT:
	case COLL_OP_MODE_MULTI_RANK: {
		if (cfg->rdv_type == HLTESTS_NIC_RDV_V_OP) {
			/* V-operation assumes lag size of 1, and lag index 0*/
			req_ctx->coll_lag_idx = 0;
			req_ctx->coll_last_in_lag = 1;
			req_ctx->coll_lag_size = 1;
		} else {
			req_ctx->coll_lag_idx = (uint8_t)qp->lag_index;
			req_ctx->coll_last_in_lag = qp->lag_index == (cfg->ports_num - 1);
			req_ctx->coll_lag_size = (uint8_t)cfg->ports_num;
		}

		break;
	}
	default:
		/* Not supposed to reach this */
		break;
	}
}

/**
 * nic_collective_set_wq_buffers() - Does nothing, in collective operations the `swqe_arr` and
 *				     `rwqe_arr` are used instead of the mmapped WQs.
 * @qp: Out, QP structure.
 *
 * Return: 0 on success
 */
static int nic_collective_set_wq_buffers(struct hltests_nic_qp *qp)
{
	return 0;
}

/**
 * nic_collective_pre_runtime() - Performs any tasks necessary before runtime.
 * @params: Test parameters.
 *
 * Return: 0 on success
 *
 * Currently the performed tasks are:
 * 1. In case the data location is on the device (HBM/SRAM), copies over the QPs buffers from the
 *    host to the device.
 * 2. Reset the PIs of all the QPs.
 */
static int nic_collective_pre_runtime(struct hltests_nic_test_params *params)
{
	if (params->data_mem_location != LOC_HOST) {
		int rc;

		rc = copy_qp_buffers_host_to_dev(params);
		assert_int_equal(rc, 0);
	}

	reset_qps_pi(params);

	return 0;
}

/**
 * nic_collective_runtime() - Performs the runtime tasks.
 * @params: Test parameters.
 *
 * Return: 0 on success
 *
 * Currently the performed tasks are:
 * 1. Resets data destination buffers.
 * 2. Clears SOBs (if necessary).
 * 3. Configures the collective WQEs and submits doorbell.
 * 4. Runs the collective operation.
 * 5. Waits for completion and verifies it (using SOBs or CQs).
 * 6. Compares the transferred data to the original (if necessary).
 * 7. Polls and posts CCs (if necessary).
 */
static int nic_collective_runtime(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	int fd = params->fd;

	for (size_t iter = 0; iter < cfg->runtime_iterations; iter++) {
		int rc;

		printf("\nruntime iteration %lu\n", iter);

		if (cfg->migration.enable && iter == cfg->migration.runtime_iterations_trigger) {
			if (cfg->migration.check_event) {
				rc = nic_common_migration_check_event(params);
				assert_int_equal(rc, 0);
			}
			rc = nic_common_migrate_qps(params);
			assert_int_equal(rc, 0);
		}

		rc = nic_collective_reset_dst_buffers(params);
		assert_int_equal(rc, 0);
		hltests_nic_print_time_elapsed(
			&params->base, "collective reset destination buffers", cfg->verbose);

		if (cfg->cmpl == SOB)
			nic_common_clear_sobs(params);
		/* user fifo in collective mode updates CI via LBW SOBs. */
		hltests_clear_sobs_offset(fd, (uint16_t)params->max_num_of_ports, DB_FIFO_SOB_ID);

		config_wqes(params);
		hltests_nic_print_time_elapsed(&params->base, "collective configured WQEs",
					       cfg->verbose);

		rc = hltests_nic_submit_db(params);
		assert_int_equal(rc, 0);
		hltests_nic_print_time_elapsed(&params->base, "collective submitted WQEs via DB",
					       cfg->verbose);

		rc = run_coll_op(params);
		assert_int_equal(rc, 0);
		hltests_nic_print_time_elapsed(
			&params->base, "collective started collective operation", cfg->verbose);

		rc = nic_common_complete(params);
		assert_int_equal(rc, 0);
		hltests_nic_print_time_elapsed(&params->base,
					       "collective finished handling all completions",
					       cfg->verbose);

		if (cfg->data_cmp) {
			rc = data_compare(params);
			assert_int_equal(rc, 0);
		}
	}

	return 0;
}

/**
 * nic_collective_destroy_qps() - disassociates and destroys all collective qps.
 * @params: Test parameters.
 *
 * Return: 0 on success
 */
static int nic_collective_destroy_qps(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	enum hltests_nic_coll_qp_type coll_qp_type;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		size_t qp_idx;

		for (qp_idx = 0; qp_idx < cfg->coll_qps_count[coll_qp_type]; qp_idx++) {
			size_t port_idx;

			for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
				struct hltests_nic_qp *qp;
				uint32_t port = cfg->ports[port_idx];
				int rc;

				qp = &params->coll_qps[coll_qp_type][port][qp_idx];

				rc = nic_common_destroy_qp(qp);
				assert_int_equal(rc, 0);
			}
		}
	}

	return 0;
}

/**
 * nic_collective_free_wq_buffers() - Does nothing.
 * @qp: QP struct.
 */
static void nic_collective_free_wq_buffers(struct hltests_nic_qp *qp)
{
}

/**
 * nic_collective_destroy_qps_db() - Uninitializes and frees all allocated collective QPs.
 * @params: Test parameters.
 */
static void nic_collective_destroy_qps_db(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	enum hltests_nic_coll_qp_type coll_qp_type;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		size_t port_idx;

		for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
			uint32_t port = cfg->ports[port_idx];

			uninitialize_qps(params, coll_qp_type, port);

			hlthunk_free(params->coll_qps[coll_qp_type][port]);
			params->coll_qps[coll_qp_type][port] = NULL;
		}
	}
}

/**
 * nic_collective_init() - Performs tasks that have to be done early on in the test's lifetime,
 *			   right after opening the device.
 * @params: Test parameters.
 *
 * Return: 0 on success.
 *
 * Performs the following tasks:
 * 1. Update coll lag size through debugfs.
 * 2. Allocate collective communication groups.
 * 3. Allocate collective WQE arrays (must be contiguous buffers).
 */
static int nic_collective_init(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	int fd = params->fd;
	int rc = 0;

	/* Only Gaudi3 has a global lag size configuration. */
	if (hltests_is_gaudi3(params->fd)) {
		/**
		 * TODO - SW-171834: Check the effects if this is removed, lag size is initialized
		 * to 3 in the driver.
		 */
		if ((cfg->coll_op == COLL_OP_MODE_LEGACY) ||
		    (cfg->rdv_type == HLTESTS_NIC_RDV_V_OP)) {
			rc = hltests_nic_debugfs_set_coll_lag_size(fd, 1);
			assert_int_equal(rc, 0);
		} else {
			rc = hltests_nic_debugfs_set_coll_lag_size(fd, cfg->ports_num);
			assert_int_equal(rc, 0);
		}
	}

	rc = alloc_coll_comm_groups(params);
	assert_int_equal(rc, 0);

	rc = alloc_wqe_arrays(params);
	assert_int_equal(rc, 0);

	return 0;
}

/**
 * nic_collective_fini() - Performs uninitialization tasks.
 * @params: Test parameters.
 *
 * Performs the following tasks:
 * 1. Deallocate the collective WQE arrays.
 * 2. Deallocate the collective communication groups.
 */
static void nic_collective_fini(struct hltests_nic_test_params *params)
{
	dealloc_wqe_arrays(params);
	dealloc_coll_comm_groups(params);
}

/**
 * cfg_parser() - parses collective configuration parameters and populates the relevant fields in
 *                the configuration structure.
 * @user:	Pointer to configuration structure.
 * @section:	The section from which the parameter comes.
 * @name:	The name of the parameter.
 * @value:	The value of the parameter.
 *
 * Return: 1 if the configuration field was consumed.
 */
static int cfg_parser(void *user, const char *section, const char *name, const char *value)
{
	struct hltests_nic_test_cfg *cfg = (struct hltests_nic_test_cfg *)user;

	errno = 0;

	if (MATCH("collective", "scale_up_coll_qps")) {
		unsigned long temp = strtoul(value, NULL, 0);

		if (errno == ERANGE || temp > UINT32_MAX) {
			printf("scale_up_coll_qps out of range!\n");
			return 0;
		}

		cfg->coll_qps_count[COLL_QP_TYPE_SCALE_UP] = temp;
	} else if (MATCH("collective", "scale_up_coll_lpbk_qps")) {
		unsigned long temp = strtoul(value, NULL, 0);

		if (errno == ERANGE || temp > UINT32_MAX) {
			printf("scale_up_coll_lpbk_qps out of range!\n");
			return 0;
		}

		cfg->coll_lpbk_qps_count[COLL_QP_TYPE_SCALE_UP] = temp;
	} else if (MATCH("collective", "scale_out_coll_qps")) {
		unsigned long temp = strtoul(value, NULL, 0);

		if (errno == ERANGE || temp > UINT32_MAX) {
			printf("scale_out_coll_qps out of range!\n");
			return 0;
		}

		cfg->coll_qps_count[COLL_QP_TYPE_SCALE_OUT] = temp;
	} else if (MATCH("collective", "scale_out_coll_lpbk_qps")) {
		unsigned long temp = strtoul(value, NULL, 0);

		if (errno == ERANGE || temp > UINT32_MAX) {
			printf("scale_out_coll_lpbk_qps out of range!\n");
			return 0;
		}

		cfg->coll_lpbk_qps_count[COLL_QP_TYPE_SCALE_OUT] = temp;
	} else if (MATCH("collective", "coll_type")) {
		if (!strcmp(value, "context")) {
			cfg->coll_type = COLL_TYPE_CONTEXT;
		} else if (!strcmp(value, "direct")) {
			cfg->coll_type = COLL_TYPE_DIRECT;
		} else {
			printf("Invalid coll_type: [%s]\n", value);
			return 0;
		};
	} else if (MATCH("collective", "coll_op")) {
		if (!strcmp(value, "legacy")) {
			cfg->coll_op = COLL_OP_MODE_LEGACY;
		} else if (!strcmp(value, "multi_lag")) {
			cfg->coll_op = COLL_OP_MODE_MULTI_LAG;
		} else if (!strcmp(value, "multi_rank")) {
			cfg->coll_op = COLL_OP_MODE_MULTI_RANK;
		} else if (!strcmp(value, "multi_context")) {
			cfg->coll_op = COLL_OP_MODE_MULTI_CONTEXT;
		} else {
			printf("Invalid coll_op: [%s]\n", value);
			return 0;
		};
	} else if (MATCH("collective", "coll_patcher_op")) {
		if (!strcmp(value, "gen")) {
			cfg->coll_patcher_op = COLL_PATCHER_OPCODE_GEN;
		} else if (!strcmp(value, "vop")) {
			cfg->coll_patcher_op = COLL_PATCHER_OPCODE_VOP;
		} else {
			printf("Invalid coll_patcher_op: [%s]\n", value);
			return 0;
		};
	} else if (MATCH("collective", "coll_data_type")) {
		if (!strcmp(value, "reduction")) {
			cfg->coll_data_type = HLTESTS_NIC_COLL_DATA_TYPE_REDUCTION;
		} else if (!strcmp(value, "4_bits")) {
			cfg->coll_data_type = HLTESTS_NIC_COLL_DATA_TYPE_4_BITS;
		} else if (!strcmp(value, "1_byte")) {
			cfg->coll_data_type = HLTESTS_NIC_COLL_DATA_TYPE_1_BYTE;
		} else if (!strcmp(value, "2_bytes")) {
			cfg->coll_data_type = HLTESTS_NIC_COLL_DATA_TYPE_2_BYTES;
		} else if (!strcmp(value, "4_bytes")) {
			cfg->coll_data_type = HLTESTS_NIC_COLL_DATA_TYPE_4_BYTES;
		} else if (!strcmp(value, "128_bytes") || !strcmp(value, "128")) {
			cfg->coll_data_type = HLTESTS_NIC_COLL_DATA_TYPE_128_BYTE;
		} else if (!strcmp(value, "256_bytes") || !strcmp(value, "256")) {
			cfg->coll_data_type = HLTESTS_NIC_COLL_DATA_TYPE_256_BYTE;
		} else {
			printf("Invalid coll_data_type: [%s]\n", value);
			return 0;
		};
	} else if (MATCH("collective", "coll_rank_axis")) {
		if (!strcmp(value, "z")) {
			cfg->coll_rank_axis = COLL_DESC_Z_AXIS;
			printf("coll_rank_axis: [COLL_DESC_Z_AXIS]\n");
		} else if (!strcmp(value, "x")) {
			printf("coll_rank_axis: [COLL_DESC_X_AXIS]\n");
			cfg->coll_rank_axis = COLL_DESC_X_AXIS;
		} else if (!strcmp(value, "y")) {
			printf("coll_rank_axis: [COLL_DESC_Y_AXIS]\n");
			cfg->coll_rank_axis = COLL_DESC_Y_AXIS;
		} else {
			printf("Invalid coll_rank_axis: [%s]\n", value);
			return 0;
		};
	} else if (MATCH("collective", "coll_ranks_num")) {
		unsigned long coll_ranks_num = strtoul(value, NULL, 0);

		if (errno == ERANGE || coll_ranks_num > UINT8_MAX) {
			printf("coll_ranks_num out of range!\n");
			return 0;
		}

		printf("coll_ranks_num: [%lu]\n", coll_ranks_num);

		cfg->coll_ranks_num = (uint8_t)coll_ranks_num;
	} else if (MATCH("collective", "disregard_rank")) {
		if (!strcmp(value, "yes")) {
			cfg->disregard_rank = true;
		} else if (!strcmp(value, "no")) {
			cfg->disregard_rank = false;
		} else {
			printf("Invalid disregard_rank: [%s]\n", value);
			return 0;
		};
	} else {
		/* unknown section/name, error */
		return 0;
	}

	return 1;
}

/**
 * alloc_coll_comm_groups() - Allocates an array containing all the communication group structures.
 * @params: Test parameters.
 *
 * Return: 0 on success.
 */
static int alloc_coll_comm_groups(struct hltests_nic_test_params *params)
{
	params->coll_comm_group =
		hlthunk_malloc(sizeof(*params->coll_comm_group) * get_max_coll_comm_groups(params));
	assert_non_null(params->coll_comm_group);

	return 0;
}

/**
 * dealloc_coll_comm_groups() - Deallocates the array containing all the communication group
 *				structures.
 * @params: Test parameters.
 */
static void dealloc_coll_comm_groups(struct hltests_nic_test_params *params)
{
	hlthunk_free(params->coll_comm_group);
	params->coll_comm_group = NULL;
}

/**
 * alloc_qp_mem_buffers() - Allocates memory for data buffers on host memory, then assigns them to
 *			    the QPs.
 * @params: Test parameters.
 *
 * Return: 0 on success.
 */
static int alloc_qp_mem_buffers(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	enum hltests_nic_coll_qp_type coll_qp_type;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		struct hltests_nic_qp **qps = params->coll_qps[coll_qp_type];
		size_t qp_idx;

		for (qp_idx = 0; qp_idx < cfg->coll_qps_count[coll_qp_type]; qp_idx++) {
			size_t port_idx;

			for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
				uint32_t port = cfg->ports[port_idx];
				struct hltests_nic_qp *qp = &qps[port][qp_idx];
				int rc;

				if (cfg->single_alloc && qp_idx) {
					qp->host_src_buf = qps[port][0].host_src_buf;
					qp->host_dst_buf = qps[port][0].host_dst_buf;

					continue;
				}

				rc = nic_common_alloc_qp_mem_buffers(params, qp);
				assert_int_equal(rc, 0);
			}
		}
	}

	return 0;
}

/**
 * alloc_wqe_arrays() - Allocates the send and receive WQEs arrays.
 * @params: Test parameters.
 *
 * Return: 0 on success.
 */
static int alloc_wqe_arrays(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t max_ports_count;
	int fd = params->fd;

	max_ports_count = hltests_nic_get_max_num_of_ports(fd);

	size_t wqes_per_qp_count, swq_size, rwq_size, max_qps_per_port_count;

	max_qps_per_port_count = MAX(cfg->coll_qps_count[COLL_QP_TYPE_SCALE_OUT],
				     cfg->coll_qps_count[COLL_QP_TYPE_SCALE_UP]);

	/* +1 due to extra ethernet QP */
	max_qps_per_port_count++;

	wqes_per_qp_count = (params->num_wqes_in_wq < WQES_MIN) ? WQES_MIN : params->num_wqes_in_wq;

	swq_size = max_qps_per_port_count * wqes_per_qp_count * hltests_nic_get_swqe_size(fd);
	rwq_size = max_qps_per_port_count * wqes_per_qp_count * hltests_nic_get_rwqe_size(fd);

	ALLOC_2D_ARR(params->swqe_arr, max_ports_count, swq_size);
	ALLOC_2D_ARR(params->rwqe_arr, max_ports_count, rwq_size);

	return 0;
}

/**
 * dealloc_wqe_arrays() - Deallocates the send and receive WQE arrays.
 * @params: Test parameters.
 *
 * Return: 0 on success.
 */
static void dealloc_wqe_arrays(struct hltests_nic_test_params *params)
{
	uint32_t max_n_ports;
	int fd = params->fd;

	max_n_ports = hltests_nic_get_max_num_of_ports(fd);

	FREE_2D_ARR(params->swqe_arr, max_n_ports);
	FREE_2D_ARR(params->rwqe_arr, max_n_ports);
}

/**
 * initialize_qps() - Initializes all collective QPs of a specific type and port.
 * @params: Test parameters struct.
 * @type:   The type of collective QPs to initialize.
 * @port:   The port whose QPs to initialize.
 *
 * Return: 0 on success.
 *
 * The initialization includes allocating memory for the completion mapping and initializing the
 * QP's fields.
 */
static int initialize_qps(struct hltests_nic_test_params *params,
			  enum hltests_nic_coll_qp_type type, uint32_t port)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_qp *coll_qps = params->coll_qps[type][port];
	size_t coll_qps_count = cfg->coll_qps_count[type], qp_idx;

	for (qp_idx = 0; qp_idx < coll_qps_count; qp_idx++) {
		struct hltests_nic_qp *qp_p = &coll_qps[qp_idx];

		memset(qp_p, 0, sizeof(*qp_p));

		qp_p->id = (uint32_t)qp_idx;

		qp_p->port = port;
		qp_p->test_params = params;

		/*
		 * At this point we mark all collective QPs as collective, even if this is not
		 * entirely correct, as context patcher uses regular QPs and not collective ones.
		 * We need this because we're trying to reuse the common code as much as possible,
		 *
		 * Later on the common logic will call `nic_collective_fill_qp_attr`, both for
		 * regular and collective QPs, we're using this flag to identify the collective QPs.
		 *
		 * Then in `nic_collective_fill_qp_attr` the flag will be set to it's correct value,
		 * before being copied into the `hbldv_qp_attr` struct.
		 */
		qp_p->is_coll = true;

		if (IS_RDV(cfg->features_bitmap)) {
			if (qp_idx & 0x1) {
				qp_p->is_rdv_sender = true;
				qp_p->rdv_recv_qp = &coll_qps[qp_idx - 1];
			} else {
				qp_p->rdv_send_qp = &coll_qps[qp_idx + 1];
			}
		}

		if (qp_idx < cfg->coll_lpbk_qps_count[type])
			qp_p->is_lpbk = true;

		if (cfg->cmpl == CQ_USR) {
			bool *req_comp_map, *res_comp_map;
			uint32_t num_wqes_in_wq = params->num_wqes_in_wq;

			req_comp_map = hlthunk_malloc(num_wqes_in_wq * sizeof(*req_comp_map));
			assert_non_null(req_comp_map);

			res_comp_map = hlthunk_malloc(num_wqes_in_wq * sizeof(*res_comp_map));
			assert_non_null(res_comp_map);

			qp_p->req_comp_params.cmpl_map = req_comp_map;
			qp_p->res_comp_params.cmpl_map = res_comp_map;
			qp_p->req_comp_params.cmpl_map_length = num_wqes_in_wq;
			qp_p->res_comp_params.cmpl_map_length = num_wqes_in_wq;
		}
	}

	return 0;
}

/**
 * uninitialize_qps() - Uninitializes all collective QPs of a specific type and port.
 * @params: Test parameters struct.
 * @type:   The type of collective QPs to initialize.
 * @port:   The port whose QPs to initialize.
 */
static void uninitialize_qps(struct hltests_nic_test_params *params,
			     enum hltests_nic_coll_qp_type type, uint32_t port)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	size_t qp_idx;

	if (cfg->cmpl != CQ_USR)
		return;

	for (qp_idx = 0; qp_idx < cfg->coll_qps_count[type]; qp_idx++) {
		struct hltests_nic_qp *qp = &params->coll_qps[type][port][qp_idx];

		hlthunk_free(qp->req_comp_params.cmpl_map);
		hlthunk_free(qp->res_comp_params.cmpl_map);

		qp->req_comp_params.cmpl_map = NULL;
		qp->res_comp_params.cmpl_map = NULL;
	}
}

/**
 * config_wqes() - Configures all collective WQEs.
 * @params: Test parameters struct.
 *
 * Basically this configures each QPs PI, and then proceeds to send the hardware information about
 * all the QPs WQEs, their buffers, their sizes and other flags.
 */
static void config_wqes(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	enum hltests_nic_coll_qp_type coll_qp_type;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		size_t qp_idx;

		for (qp_idx = 0; qp_idx < cfg->coll_qps_count[coll_qp_type]; qp_idx++) {
			uint32_t port_idx;

			/* TODO - SW-114993: support scale up/out */
			for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
				uint32_t port = cfg->ports[port_idx];
				struct hltests_nic_qp *qp =
					&params->coll_qps[coll_qp_type][port][qp_idx];

				/* For RD-RDV, there is no WQE to be posted for the send side */
				if ((cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) &&
				    qp->is_rdv_sender)
					continue;

				qp->curr_pi = 0;
				qp->dest_pi = params->num_wqes_in_wq;

				nic_common_config_wqes(qp, port_idx);
			}
		}
	}

	hltests_nic_print_time_elapsed(&params->base, "config collective wqes", cfg->verbose);
}

/**
 * assign_device_data_buffers_to_qps() - Assigns the device memory data buffers to the QPs.
 * @params:        Test parameters.
 * @dev_mem:       Device memory block.
 * @local_offset:  The offset of the allocated local buffer.
 * @remote_offset: The offset of the allocated remote buffer.
 *
 * Return: 0 on success.
 */
static void assign_device_data_buffers_to_qps(const struct hltests_nic_test_params *params,
					      const struct hltests_memory *dev_mem,
					      uint64_t local_offset, uint64_t remote_offset)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	const uint64_t data_size = params->data_size;
	const uint64_t dst_data_size = params->dst_data_size;

	size_t offset = 0;
	enum hltests_nic_coll_qp_type coll_qp_type;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		size_t port_idx;

		for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
			size_t qp_idx;
			uint32_t port = cfg->ports[port_idx];

			for (qp_idx = 0; qp_idx < cfg->coll_qps_count[coll_qp_type]; qp_idx++) {
				struct hltests_nic_qp *qp =
					&params->coll_qps[coll_qp_type][port][qp_idx];

				qp->dev_mem = *dev_mem;

				if (cfg->single_alloc) {
					qp->local_dev_mem_offset =
						local_offset + (port_idx * data_size);
					qp->remote_dev_mem_offset =
						remote_offset + (port_idx * dst_data_size);
				} else {
					qp->local_dev_mem_offset =
						local_offset + (offset * data_size);
					qp->remote_dev_mem_offset =
						remote_offset + (offset * dst_data_size);
					offset++;
				}
			}
		}
	}
}

/**
 * copy_qp_buffers_host_to_dev() - Copies the QP buffers from host to device memory (HBM/SRAM).
 * @params: Test parameters.
 *
 * Return: 0 on success.
 */
static int copy_qp_buffers_host_to_dev(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	enum hltests_nic_coll_qp_type coll_qp_type;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		size_t qp_idx;

		for (qp_idx = 0; qp_idx < cfg->coll_qps_count[coll_qp_type]; qp_idx++) {
			size_t port_idx;

			/**
			 * TODO - SW-114993: once we have scale up/scale out ports, transition to
			 * using them instead of the generic ports
			 */
			for (port_idx = 0; port_idx < params->cfg->ports_num; port_idx++) {
				struct hltests_nic_qp *qp;
				uint32_t port;
				int rc;

				if (cfg->single_alloc && qp_idx > 0)
					break;

				port = params->cfg->ports[port_idx];

				qp = &params->coll_qps[coll_qp_type][port][qp_idx];

				rc = nic_common_copy_buff_host_to_dev(params, qp->host_src_buf,
								      &qp->dev_mem,
								      qp->local_dev_mem_offset,
								      params->data_size);
				assert_int_equal(rc, 0);
			}
		}
	}

	return 0;
}

/**
 * reset_qps_pi() - Resets the current and destination PI of all QPs.
 * @params: Test parameters.
 */
static void reset_qps_pi(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	enum hltests_nic_coll_qp_type coll_qp_type;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		size_t qp_idx;

		for (qp_idx = 0; qp_idx < cfg->coll_qps_count[coll_qp_type]; qp_idx++) {
			size_t port_idx;

			for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
				uint32_t port = cfg->ports[port_idx];

				params->coll_qps[coll_qp_type][port][qp_idx].curr_pi = 0;
				params->coll_qps[coll_qp_type][port][qp_idx].dest_pi = 0;
			}
		}
	}
}

static int nic_collective_reset_dst_buffers(struct hltests_nic_test_params *params)
{
	enum hltests_nic_coll_qp_type coll_qp_type;
	int rc;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		rc = nic_common_reset_dst_buffers(params, params->coll_qps[coll_qp_type],
				(uint32_t)params->cfg->coll_qps_count[coll_qp_type]);
		assert_int_equal(rc, 0);
	}

	return 0;
}

/**
 * coll_op_comm_group_init() - Initializes the communication group.
 * @comm_group: The communication group.
 *
 * Return: 0 on success.
 */
static int coll_op_comm_group_init(struct hltests_nic_coll_comm_group_new *comm_group)
{
	/* TODO - SW-114993: support scale up/out */
	const struct hltests_nic_test_params *params = comm_group->params;
	enum hltests_nic_coll_qp_type coll_qp_type;
	uint32_t port_idx;

	assert_non_null(comm_group->tests_state);
	assert_non_null(comm_group->params);
	assert_non_null(comm_group->nodes_mask);

	coll_qp_type = nic_common_get_coll_qp_type(comm_group->params);

	comm_group->allocated = 1;

	switch (params->cfg->coll_op) {
	case COLL_OP_MODE_LEGACY: {
		comm_group->n_ranks = 1;
		comm_group->nodes_per_rank = 1;
		break;
	}
	case COLL_OP_MODE_MULTI_LAG: {
		comm_group->n_ranks = 1;
		/**
		 * TODO - SW-114993: once we have scale up/scale out ports, transition to
		 * using them instead of the generic ports
		 */
		comm_group->nodes_per_rank = params->cfg->ports_num;
		break;
	}
	case COLL_OP_MODE_MULTI_RANK:
	case COLL_OP_MODE_MULTI_CONTEXT: {
		if (params->cfg->rdv_type == HLTESTS_NIC_RDV_V_OP)
			/*  V operations supports only 1 rank */
			comm_group->n_ranks = 1;
		else
			comm_group->n_ranks = params->cfg->coll_ranks_num ?
						      params->cfg->coll_ranks_num :
						      MAX_COLL_COMM_RANKS;

		comm_group->nodes_per_rank = params->cfg->ports_num;
		break;
	}
	default: {
		printf("Unsupported coll op %d\n", params->cfg->coll_op);
		fail();
	}
	}

	for (port_idx = 0; port_idx < params->cfg->ports_num; port_idx++) {
		struct hltests_nic_coll_comm_node_new *comm_node;
		uint32_t port = params->cfg->ports[port_idx];

		comm_node = &comm_group->nodes[port];

		comm_node->conn_id = params->coll_qps[coll_qp_type][port][comm_group->id].conn_id;
		comm_node->port_id = port;
		comm_node->comm_group = comm_group;
		comm_node->db_fifo = &params->user_fifos[0][port];
	}

	return 0;
}

/**
 * run_coll_op() - Runs the collective operation.
 * @params: Test parameters structure.
 *
 * Return: 0 on success.
 */
static int run_coll_op(struct hltests_nic_test_params *params)
{
	int rc;

	switch (params->cfg->coll_op) {
	case COLL_OP_MODE_LEGACY: {
		rc = run_coll_op_legacy(params);
		assert_int_equal(rc, 0);
		break;
	}
	case COLL_OP_MODE_MULTI_LAG:
	case COLL_OP_MODE_MULTI_RANK: {
		rc = run_coll_op_multi_lag_rank(params);
		assert_int_equal(rc, 0);
		break;
	}
	case COLL_OP_MODE_MULTI_CONTEXT: {
		rc = run_coll_op_multi_context(params);
		assert_int_equal(rc, 0);
		break;
	}
	default: {
		fail();
	}
	}

	return 0;
}

/**
 * run_coll_op_legacy() - Runs the legacy collective operation.
 * @params: Test parameters structure.
 *
 * Return: 0 on success.
 *
 * For legacy operation we have to submit the coll op for each port separately.
 */
static int run_coll_op_legacy(struct hltests_nic_test_params *params)
{
	struct hltests_nic_coll_comm_group_new *comm_group = params->coll_comm_group;
	size_t port_idx;

	for (port_idx = 0; port_idx < params->cfg->ports_num; port_idx++) {
		uint32_t port = params->cfg->ports[port_idx];
		int rc;

		/* We coalesce communication group clean-up at end of
		 * the test. To track allocated resources, use a new entry
		 * for each port.
		 */
		memset(comm_group, 0, sizeof(*comm_group));

		comm_group->tests_state = params->test_ctx->tests_state;
		comm_group->params = params;
		comm_group->id = 0;
		comm_group->nodes_mask = BIT_ULL(port);

		rc = run_coll_op_internal(comm_group);
		assert_int_equal(rc, 0);
	}

	return 0;
}

/**
 * run_coll_op_multi_lag_rank() - Runs the multi lag or multi rank collective
 *				  operation.
 * @params: Test parameters structure.
 *
 * Return: 0 on success.
 *
 * For multi lag or multi rank operation we have to submit the coll op just once.
 */
static int run_coll_op_multi_lag_rank(struct hltests_nic_test_params *params)
{
	struct hltests_nic_coll_comm_group_new *comm_group;

	/* We coalesce communication group clean-up at end of
	 * the test. To track allocated resources, use a new entry
	 * for each port.
	 */
	comm_group = &params->coll_comm_group[0];
	memset(comm_group, 0, sizeof(*comm_group));

	comm_group->tests_state = params->test_ctx->tests_state;
	comm_group->params = params;
	comm_group->id = 0;
	comm_group->nodes_mask = params->cfg->ports_mask;

	return run_coll_op_internal(comm_group);
}

/**
 * run_coll_op_multi_context() - Runs the multi context collective operation.
 * @params: Test parameters structure.
 *
 * Return: 0 on success.
 *
 * For multi context operation we have to submit the coll op for each QP.
 *
 * There is no concept of multi-context in direct patcher since all the descriptors are tied to
 * a QP. But we want to leverage the existing infra to get the qp id via the comm_group->id,
 * so this function is being used by direct patcher to run the Rendezvous tests.
 */
static int run_coll_op_multi_context(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_coll_comm_group_new *comm_group;
	struct hltests_nic_asic_funcs *nic_funcs;
	struct hltests_device *hdev;
	enum hltests_nic_coll_qp_type coll_qp_type;
	int rc = 0, fd;

	fd = params->fd;
	hdev = get_hdev_from_fd(fd);
	nic_funcs = hdev->asic_funcs->nic_funcs;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		/* TODO - SW-114993: support scale up/out */
		uint32_t qp_idx;

		for (qp_idx = 0; qp_idx < cfg->coll_qps_count[coll_qp_type]; qp_idx++) {
			/* No packets are sent on requester side for rd-rdv */
			if (cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ && (qp_idx & 0x1))
				continue;

			/* Each context uses the same QP index (not ID) on all ports. */
			comm_group = &params->coll_comm_group[qp_idx];
			memset(comm_group, 0, sizeof(*comm_group));

			comm_group->tests_state = params->test_ctx->tests_state;
			comm_group->params = params;
			comm_group->id = qp_idx;

			if (cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE &&
			    ((qp_idx & 0x1) == 0)) {
				size_t port_idx;

				for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
					uint32_t port = cfg->ports[port_idx];

					comm_group->nodes_mask = BIT_ULL(port);
					rc = run_coll_op_internal(comm_group);
					assert_int_equal(rc, 0);
				}

				continue;
			}

			if (cfg->rdv_type == HLTESTS_NIC_RDV_V_OP &&
			    cfg->coll_type == COLL_TYPE_CONTEXT) {
				/**
			 * V-OP requires two coll op messages. one for lower half of the ports and
			 * one for the upper part.
			 */

				/* lower half */
				/* TODO - SW-114993 */
				comm_group->nodes_mask =
					nic_funcs->get_half_port_mask(fd, cfg->ports_mask, false);
				if (comm_group->nodes_mask) {
					rc = run_coll_op_internal(comm_group);
					assert_int_equal(rc, 0);
				}

				/* upper half */
				/* TODO - SW-114993 */
				comm_group->nodes_mask =
					nic_funcs->get_half_port_mask(fd, cfg->ports_mask, true);
				if (comm_group->nodes_mask) {
					rc = run_coll_op_internal(comm_group);
					assert_int_equal(rc, 0);
				}

				continue;
			}

			/* TODO - SW-114993 */
			comm_group->nodes_mask = cfg->ports_mask;
			rc = run_coll_op_internal(comm_group);
			assert_int_equal(rc, 0);
		}
	}

	return 0;
}

/**
 * run_coll_op_internal() - Initializes the comm group and calls the HW specific logic to run the
 *			    coll op.
 * @comm_group: The comm group to run.
 *
 * Return: 0 on success.
 */
static int run_coll_op_internal(struct hltests_nic_coll_comm_group_new *comm_group)
{
	int rc;

	rc = coll_op_comm_group_init(comm_group);
	assert_int_equal(rc, 0);

	rc = hltests_nic_run_coll_op_new(comm_group->tests_state->fd, comm_group);
	assert_int_equal(rc, 0);

	return 0;
}

/**
 * nic_collective_calculate_total_cqes() - Calculates the total amount of CQEs that are supposed to
 *                                         arrive.
 * @params: Test parameters.
 * @total_req_cqes: Out, will be updated to contain the total expected amount of requester CQEs.
 * @total_res_cqes: Out, will be updated to contain the total expected amount of responder CQEs.
 *
 * Return: 0 on success.
 *
 * Additionally, initializes each QP's completion params.
 */
static int nic_collective_calculate_total_cqes(struct hltests_nic_test_params *params,
					       uint32_t *total_req_cqes, uint32_t *total_res_cqes)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;

	enum hltests_nic_coll_qp_type coll_qp_type;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		nic_common_calculate_total_cqes(params, params->coll_qps[coll_qp_type],
						&cfg->coll_qps_count[coll_qp_type], 1,
						total_req_cqes, total_res_cqes);
	}

	return 0;
}

static int data_compare(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	enum hltests_nic_coll_qp_type coll_qp_type;
	int rc;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		rc = nic_common_data_compare(params, params->coll_qps[coll_qp_type],
					     (uint32_t)cfg->coll_qps_count[coll_qp_type]);
		assert_int_equal(rc, 0);

		printf("collective type %u - ", coll_qp_type);
		hltests_nic_print_time_elapsed(&params->base, "data compare", cfg->verbose);
	}

	return 0;
}

/**
 * nic_collective_get_cqes_per_qp() - Returns the amount of requester and responder CQEs each QP is
 *                                    supposed to receive.
 * @qp: The QP for which to calculate the amounts.
 * @req_cqes: Out, how many requester CQEs to expect.
 * @res_cqes: Out, how many responder CQEs to expect.
 * We're supposed to get one CQE per each "network operation".
 * There are 4 possible modes of collective operations:
 * 1. Legacy - a. reusing the same communication group for all the ports
 *             b. single rank
 *             c. single QP
 *             d. multiple ports (in the test each port is associated to one node)
 *             This means there's 1 operation per port -> 1 operation per QP.
 *             Therefore each QP should get 1 REQ and 1 RES CQE.
 * 2. Multi lag - a. single communications group
 *                b. single rank
 *                c. single QP
 *                d. multiple ports (in the test each port is associated to one node)
 *                This means there's 1 operation per port -> 1 operation per QP.
 *                Therefore each QP (1 per port) should get 1 REQ and 1 RES CQE.
 * 3. Multi rank - a. single communications group
 *                 b. multiple ranks
 *                 c. single QP
 *                 d. multiple ports (in the test each port is associated to one node)
 *                 Each port sends packets to coll_ranks_num destinations.
 *                 Therefore each QP (1 per port) should get `coll_ranks_num` REQ and RES
 *                 CQEs.
 * 3. Multi context - a. single communications group
 *                    b. multiple ranks
 *                    c. multiple QPs
 *                    d. multiple ports (in the test each port is associated to one node)
 *                    Each port sends packets to coll_ranks_num destinations.
 *                    Therefore each QP (1 per port) should get `coll_ranks_num` REQ and RES
 *                    CQEs.
 * Return: 0 on success.
 */
static int nic_collective_get_cqes_per_qp(const struct hltests_nic_qp *qp, uint32_t *req_cqes,
					  uint32_t *res_cqes)
{
	const struct hltests_nic_test_params *params = qp->test_params;
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t cqes_count;

	switch (cfg->coll_op) {
	case COLL_OP_MODE_LEGACY:
	case COLL_OP_MODE_MULTI_LAG: {
		cqes_count = 1;
		break;
	}
	case COLL_OP_MODE_MULTI_RANK:
	case COLL_OP_MODE_MULTI_CONTEXT: {
		cqes_count = cfg->coll_ranks_num;
		break;
	}
	default: {
		fail_msg("Unsupported coll op [%u]", cfg->coll_op);
		return -1;
	}
	}

	*req_cqes = cfg->single_cmpl ? 1 : cqes_count;
	*res_cqes = *req_cqes;

	return 0;
}

/**
 * nic_collective_find_qp_by_port_and_qpn() - Find the correct QP.
 * @params: Test parameters.
 * @port:   The port to which the QP belongs to.
 * @qp_num: The QP's number.
 *
 * Return: pointer to the QP if found, NULL otherwise.
 */
static struct hltests_nic_qp *
nic_collective_find_qp_by_port_and_qpn(struct hltests_nic_test_params *params, uint32_t port,
				       uint32_t qp_num)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	enum hltests_nic_coll_qp_type coll_qp_type;
	size_t qp_idx;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		for (qp_idx = 0; qp_idx < params->cfg->coll_qps_count[coll_qp_type]; qp_idx++) {
			if (params->coll_qps[coll_qp_type][port][qp_idx].conn_id == qp_num)
				return &params->coll_qps[coll_qp_type][port][qp_idx];
		}
	}

	if (!cfg->migration.enable || port != cfg->migration.new_port)
		return NULL;

	for (qp_idx = 0; qp_idx < params->num_qps_per_port[cfg->migration.old_port]; qp_idx++) {
		struct hltests_nic_qp *qp = &params->migration.qps[qp_idx];

		if (qp->conn_id == qp_num) {
			D("Redirecting port %u, qpn %u to migration source: port %u, qpn %u", port,
			  qp_num, qp->migration_old_qp->port, qp->migration_old_qp->conn_id);
			return qp->migration_old_qp;
		}
	}

	return NULL;
}

/**
 * nic_collective_get_expected_sob_val() - Computes the expected SOB value.
 * @params: Test parameters.
 * @port: The relevant port for the SOB params.
 */
static void nic_collective_get_expected_sob_val(struct hltests_nic_test_params *params,
						uint32_t port)
{
	uint32_t sob_val = 0;
	size_t comm_group_idx, max_coll_comm_groups;
	struct hltests_nic_sob_params *sob_params = &params->sob_params[port];

	max_coll_comm_groups = get_max_coll_comm_groups(params);

	/* Linear write: Each node updates local/remote SOB. Each rank transfer equally
	 * updates local/remote SOB. Local SOB is updated for ACKs and remote SOB is updated
	 * for write data transfer.
	 */
	for (comm_group_idx = 0; comm_group_idx < max_coll_comm_groups; comm_group_idx++) {
		struct hltests_nic_coll_comm_group_new *comm_group =
			&params->coll_comm_group[comm_group_idx];

		if (comm_group->allocated)
			sob_val += (comm_group->nodes_per_rank * comm_group->n_ranks);
	}

	sob_params->local_sob_val = sob_val;
	sob_params->remote_sob_val = sob_val;

	/* Rendezvous write:
	 * SW-114271: By configuring QPC_RX_WQE_CT_MASK_DEFAULT to 0x3 we change the expected value
	 * of the SOB to be 2 times than sender (local) side since now ACK for RDV receiver message
	 * is also increment the SOB (in addition to the regular sender data).
	 */
	if (params->cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
		sob_params->local_sob_val /= 2;

	/* Rendezvous read:
	 * Sender: No local SOB is updated. No doorbell is pushed since PI
	 * is updated by receiver. No communication group is allocated.
	 * Receiver: Remote SOB is updated for ACK received for sender WQE update
	 * and actual read data sent by sender.
	 */
	if (params->cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) {
		sob_params->remote_sob_val *= 2;
		sob_params->local_sob_val = 0;
	}
}

/**
 * get_device_qp_buffers_count() - Calculates the total necessary amount of QP buffers.
 * @params:   Test parameters.
 *
 * Return: The total amount of QP buffers.
 */
static size_t get_device_qp_buffers_count(const struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	size_t buffers_per_port_count = 0;
	enum hltests_nic_coll_qp_type coll_qp_type;

	for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++) {
		if (cfg->coll_qps_count[coll_qp_type] == 0)
			continue;

		if (cfg->single_alloc) {
			buffers_per_port_count += 1;
			continue;
		}

		/* All participating ports have the same amount of collective qps */
		buffers_per_port_count += cfg->coll_qps_count[coll_qp_type];
	}

	return buffers_per_port_count * cfg->ports_num;
}

/**
 * get_max_coll_comm_groups() - Returns the maximum amount of collective comm groups.
 * @params:   Test parameters.
 *
 * Return: The maximum amount of collective comm groups.
 */
static inline size_t get_max_coll_comm_groups(struct hltests_nic_test_params *params)
{
	return (params->cfg->coll_type == COLL_TYPE_DIRECT) ? MAX_COLL_COMM_GROUPS_DIRECT :
							      MAX_COLL_COMM_GROUPS;
}

static struct hltests_nic_test_funcs nic_collective_test_funcs = {
	.get_supported_features_mask = nic_collective_get_supported_features_mask,
	.parse_cfg = nic_collective_parse_cfg,
	.validate_cfg = nic_collective_validate_cfg,
	.print_cfg = nic_collective_print_cfg,
	.set_cq_params = NULL,
	.alloc_qps_db = nic_collective_alloc_qps_db,
	.alloc_device_mem = nic_collective_alloc_device_mem,
	.alloc_host_mem_buffers = nic_collective_alloc_host_mem_buffers,
	.fill_port_app_params = nic_collective_fill_port_app_params,
	.get_user_fifo_num = nic_collective_get_user_fifo_num,
	.get_user_fifo_type = nic_collective_get_user_fifo_type,
	.create_qps = nic_collective_create_qps,
	.get_expected_sob_val = nic_collective_get_expected_sob_val,
	.fill_qp_attr = nic_collective_fill_qp_attr,
	.get_cqes_per_qp = nic_collective_get_cqes_per_qp,
	.find_qp_by_port_and_qpn = nic_collective_find_qp_by_port_and_qpn,
	.calculate_total_cqes = nic_collective_calculate_total_cqes,
	.set_wq_buffers = nic_collective_set_wq_buffers,
	.pre_runtime = nic_collective_pre_runtime,
	.runtime = nic_collective_runtime,
	.destroy_qps = nic_collective_destroy_qps,
	.free_wq_buffers = nic_collective_free_wq_buffers,
	.destroy_qps_db = nic_collective_destroy_qps_db,
	.init = nic_collective_init,
	.fini = nic_collective_fini,
};

/**
 * nic_collective_set_test_funcs() - Initialized the test context's test functions.
 * @fd: Device file descriptor.
 */
void nic_collective_set_test_funcs(int fd)
{
	struct hltests_nic_test_ctx *test_cxt = get_nic_ctx_from_fd(fd);

	test_cxt->funcs = &nic_collective_test_funcs;
}
