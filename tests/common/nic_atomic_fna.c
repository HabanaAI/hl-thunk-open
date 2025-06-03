// SPDX-License-Identifier: MIT

/*
 * test atomic fetch and add:
 *
 *
 *
 * Copyright 2019-2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#include "hlthunk_nic_tests.h"
#include "hlthunk_tests.h"
#include "ini.h"

#include <asm-generic/errno-base.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <ctype.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include <infiniband/hbldv.h>

#define NIC_AFA_MASK_SIZE	      16
#define NIC_AFA_READ_CMPL_MEM_RETRIES 20
#define NIC_AFA_CTR_VALUE_MASK	      6
#define NIC_AFA_CTR_VAL_WRAP_VAL      (BIT_ULL(NIC_AFA_CTR_VALUE_MASK) - 2)

/**
 * get_nic_funcs
 * Return a pointer to the nic funcs callbacks
 *
 * @param params the test params
 */
static const struct hltests_nic_asic_funcs *
get_nic_funcs(struct hltests_nic_test_params *params)
{
	struct hltests_device *hdev;

	hdev = get_hdev_from_fd(params->fd);
	return hdev->asic_funcs->nic_funcs;
}

/**
 * read_fna_mem_cmpl_reg
 * Read given qp's completion register. We have up to 8 addresses that
 * we can provide to the HW to use as completion for the FnA operations.
 * Currently due to HW limitation, we support 2 addresses. This function
 * returns mmHD0_SYNC_MNGR_OBJS_MON_PAY_ADDRL_1_0 for the even QPs and
 * mmHD0_SYNC_MNGR_OBJS_MON_PAY_ADDRL_1_1 for the odd ones.
 *
 * @param params test params
 * @param qp     current QP.
 * @param blk    DCOREX base.
 * @return uint32_t Completion register value.
 */
static uint32_t read_fna_mem_cmpl_reg(struct hltests_nic_test_params *params, uint32_t qp,
				      uint8_t *blk)
{
	const struct hltests_nic_asic_funcs *nic_funcs = get_nic_funcs(params);

	return nic_funcs->read_mem_cmpl(params->fd,
		FNA_MON_ID + (qp % AFA_MAX_NUM_OF_CMPL_REGS), blk);
}

/**
 * reset_fna_op_mem
 * Reset Fetch and Add operation memory. Fetch and Add operates against
 * the SRAM or the DRAM. This routine will memset the relevant memory
 * of the FnA operation location to 0.
 *
 * @param fd Device file descriptor.
 * @param dst_addr Destination SRAM address to reset.
 * @param size SRAM memory block size.
 * @return int
 */
static int reset_fna_op_mem(int fd, uint64_t dst_addr, uint32_t size)
{
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info hw_ip;
	int rc, fna_cb_size = 0;
	uint16_t pdma_qid;
	void *fna_cb;

	pdma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	fna_cb = hltests_create_cb(fd, SZ_4K, INTERNAL, 0);
	assert_non_null(fna_cb);

	memset(&pkt_info, 0, sizeof(pkt_info));
	pkt_info.qid = pdma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_FALSE;
	pkt_info.dma.dst_addr = dst_addr;
	pkt_info.dma.size = size;
	pkt_info.dma.memset = 1;
	fna_cb_size = hltests_add_dma_pkt(fd, fna_cb, fna_cb_size, &pkt_info);

	return hltests_submit_and_wait_cs(fd, fna_cb, fna_cb_size, pdma_qid, DESTROY_CB_TRUE,
					  HL_WAIT_CS_STATUS_COMPLETED);
}

/**
 * modify_wqe_size
 * Set size of all wqes to zero
 *
 * @param qp_p pointer to qp
 */
static void modify_wqe_size(struct hltests_nic_qp *qp_p)
{
	const struct hltests_nic_asic_funcs *nic_funcs =
		get_nic_funcs(qp_p->test_params);
	uint32_t i, nwqs;

	nwqs = qp_p->test_params->num_wqes_in_wq;

	for (i = 1; i < nwqs; i++) {
		void *swqe = hltests_nic_get_swqe(qp_p->test_params->fd, qp_p->swq_buf, i);

		nic_funcs->ovrd_wqes_data_size(swqe);
	}
}

/**
 * trigger_fna_qp
 * Trigger fna request. Since the fna wqe is at index 0 (see special
 * treatment in gaudi3_nic_fill_wqe). Therefore the pi is 1.
 *
 * @param qp_p pointer to qp
 */
static int trigger_fna_qp(struct hltests_nic_qp *qp_p)
{
	struct hltests_nic_db_fifo_packet user_fifo_packet;
	uint32_t pi_fna_wqe = 1;
	struct hltests_nic_test_params *params = qp_p->test_params;
	int rc;

	if (params->cfg->atomic_fna_cmpl == AFA_REG_CMPL)
		qp_p->atomic_fna_prev_cmpl = read_fna_mem_cmpl_reg(params, qp_p->conn_id,
								   params->atomic_fna_cmpl_mem_hdl);

	rc = hltests_nic_create_db_packet(&user_fifo_packet, pi_fna_wqe, qp_p->conn_id, qp_p->port);
	if (rc)
		return rc;

	rc = hltests_nic_submit_user_fifo(params, qp_p->port, &user_fifo_packet);

	hlthunk_free(user_fifo_packet.packet);

	return rc;
}

/**
 * complete_fna_qp
 * Treat the completion for the fna request.
 *
 * @param qp_p pointer to qp
 */
static int complete_fna_qp(struct hltests_nic_qp *qp_p)
{
	struct hltests_nic_test_params *params = qp_p->test_params;
	int rc = 0;
	uint32_t cmp_res = 0;

	if (params->cfg->atomic_fna_cmpl == AFA_REG_CMPL) {
		uint32_t prev = qp_p->atomic_fna_prev_cmpl;
		uint32_t retries = hltests_is_pldm(params->fd) ?
			NIC_AFA_READ_CMPL_MEM_RETRIES * 1000 : NIC_AFA_READ_CMPL_MEM_RETRIES;

		do
			cmp_res = read_fna_mem_cmpl_reg(params, qp_p->conn_id,
							params->atomic_fna_cmpl_mem_hdl);
		while (--retries && (cmp_res <= prev) &&
		       !((prev - cmp_res) == NIC_AFA_CTR_VAL_WRAP_VAL));

		if (!retries && (cmp_res <= prev)) {
			printf("Timeout reading from SM lbw register\n");
			if (!retries)
				return -1;
		}
	} else if (params->cfg->atomic_fna_cmpl == AFA_CQ_USR_CMPL) {
		struct hl_nic_cqe *cq_buf_out, *cqe;
		uint32_t cq_buf_out_len;
		uint32_t cq_buf_out_size;
		bool stop_cq_loop = false;
		uint32_t num_of_cqes;
		uint32_t cqe_idx;
		struct hltests_nic_cq *cq = qp_p->test_params->cq;
		uint64_t cq_timeout_us = NIC_CQ_TIMEOUT_USEC;

		if (hltests_is_pldm(params->fd))
			cq_timeout_us = NIC_CQ_TIMEOUT_PLDM_USEC;

		/*
		 * There are 2 completions per QP.
		 * Reception of WQE on the responder
		 * Reception of ACK at the requestor
		 */
		cq_buf_out_len = 2;
		cq_buf_out_size = cq_buf_out_len * sizeof(struct hl_nic_cqe);
		cq_buf_out = hlthunk_malloc(cq_buf_out_size);
		if (!cq_buf_out)
			return -1;

		while (!stop_cq_loop) {
			rc = hltests_nic_cq_poll(params->fd, cq, cq_buf_out_len, cq_buf_out,
				&num_of_cqes, cq_timeout_us);
			assert_int_equal(rc, 0);
			for (cqe_idx = 0; cqe_idx < num_of_cqes; cqe_idx++) {
				cqe = &cq_buf_out[cqe_idx];

				if (cqe->type == HL_NIC_CQE_TYPE_REQ) {
					/* +1 is because the value for first F&A would be
					 * '0'
					 */
					cmp_res = cqe->requester.wqe_index + 1;
					stop_cq_loop = true;
					break;
				}
			}
		}
		hlthunk_free(cq_buf_out);
	}

	if ((cmp_res & 0xff) > params->cfg->atomic_fna_thresh)
		/* QP above the threshold, should send its WQE with data size 0 */
		modify_wqe_size(qp_p);
	else
		/* QP below the threshold, should be marked as a QP that sends its data */
		qp_p->atomic_fna_send_data = 1;

	return 0;
}

/**
 * submit_fna_for_qp
 * Submit and complete the fna request on the specified qp.
 *
 * @param qp_p pointer to qp
 */
static int submit_fna_for_qp(struct hltests_nic_qp *qp_p)
{
	int rc;

	rc = trigger_fna_qp(qp_p);
	if (rc)
		return rc;

	rc = complete_fna_qp(qp_p);
	if (rc)
		return rc;
	return 0;
}

/**
 * submit_fna_for_port
 * Submit and complete the fna request for all qps of the specified port.
 *
 * @param params pointer to test params
 * @param port   the port to act on
 */
static int submit_fna_for_port(struct hltests_nic_test_params *params, uint32_t port)
{
	uint32_t qp, qps_per_port;
	int rc = 0;

	qps_per_port = params->num_qps_per_port[port];

	for (qp = 0; qp < qps_per_port; qp++) {
		struct hltests_nic_qp *qp_p = &params->qps[port][qp];

		rc = submit_fna_for_qp(qp_p);
		if (rc)
			break;
	}
	return rc;
}

/**
 * submit_fna
 * Submit and complete the fna request for ports.
 *
 * @param params pointer to test params
 */
static int submit_fna(struct hltests_nic_test_params *params)
{
	uint32_t port;
	int rc, port_idx;

	for (port_idx = 0; port_idx < params->cfg->ports_num; port_idx++) {
		port = params->cfg->ports[port_idx];

		rc = submit_fna_for_port(params, port);
		if (rc)
			return rc;
	}
	return 0;
}

/**
 * acquire_resources
 * Allocate fna specific resources, i.e. memory for the fna value
 * and for the completion
 *
 * @param params pointer to test params
 */
static int acquire_resources(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint64_t fna_val_alloc_size = 0;
	int rc = 0, fd = params->fd;
	const struct hltests_nic_asic_funcs *nic_funcs = get_nic_funcs(params);

	params->atomic_fna_op_addr = (uintptr_t)NULL;
	if (cfg->atomic_val_loc == AFA_OP_DRAM) {
		void *local_fna_op_addr;

		fna_val_alloc_size = hltests_get_cache_line_size(fd);
		local_fna_op_addr =
			hltests_allocate_device_mem(fd, fna_val_alloc_size, 0, CONTIGUOUS);
		assert_non_null(local_fna_op_addr);

		params->atomic_fna_op_addr = (uint64_t)(uintptr_t)local_fna_op_addr;
	} else if (cfg->atomic_val_loc == AFA_OP_SRAM) {
		params->atomic_fna_op_addr = params->test_ctx->tests_state->hw_ip.sram_base_address;
		fna_val_alloc_size = sizeof(uint32_t);
	}

	rc = reset_fna_op_mem(fd, params->atomic_fna_op_addr, fna_val_alloc_size);
	assert_int_equal(rc, 0);

	if (cfg->atomic_fna_cmpl == AFA_REG_CMPL) {
		params->atomic_fna_cmpl_mem_hdl =
			nic_funcs->map_lbw_block(fd, &params->atomic_fna_cmpl_mem_size);
		assert_non_null(params->atomic_fna_cmpl_mem_hdl);

		nic_funcs->clear_lbw_memory(params->fd, params->atomic_fna_cmpl_mem_hdl, FNA_MON_ID,
					    AFA_MAX_NUM_OF_CMPL_REGS);
	}
	return 0;
}

/**
 * release_resources
 * Free fna specific resources, i.e. memory for the fna value
 * and for the completion
 *
 * @param params pointer to test params
 */
static int release_resources(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	int rc, fd = params->fd;

	if (cfg->atomic_fna_cmpl == AFA_REG_CMPL) {
		rc = hltests_unmap_hw_block(fd, params->atomic_fna_cmpl_mem_hdl,
					    params->atomic_fna_cmpl_mem_size);
		assert_int_equal(rc, 0);
		params->atomic_fna_cmpl_mem_hdl = 0;
	}
	if (cfg->atomic_val_loc == AFA_OP_DRAM && params->atomic_fna_op_addr) {
		assert_int_equal(hltests_free_device_mem(fd,
			(void *)params->atomic_fna_op_addr), 0);
		params->atomic_fna_op_addr = 0;
	}

	return 0;
}

/**
 * submit
 * deal with remaining wqes
 *
 * @param params pointer to test params
 */
static int submit(struct hltests_nic_test_params *params)
{
	return nic_common_generic_submit_user_fifo_db(params);
}

/**
 * reset_qps
 * reset fna specific qp parameters.
 *
 * @param params pointer to test params
 */
static int reset_qps(struct hltests_nic_test_params *params)
{
	int port_idx;

	for (port_idx = 0; port_idx < params->cfg->ports_num; port_idx++) {
		struct hltests_nic_qp *qp_p;
		uint32_t qp, qps_per_port;
		uint32_t port = params->cfg->ports[port_idx];

		qps_per_port = params->num_qps_per_port[port];

		for (qp = 0; qp < qps_per_port; qp++) {
			qp_p = &params->qps[port][qp];

			qp_p->atomic_fna_send_data = 0;
			qp_p->atomic_fna_prev_cmpl = 0;
		}
	}
	return 0;
}

/**
 * data_cmp
 * compare the data.
 * In case of FnA, first WQE of the WQ is a FnA WQE.
 * Comparing the data is done without the first WQE by
 * starting to compare at the second WQE of each QP and
 * reducing the size of the comparison by one WQE size.
 *
 * @param params pointer to test params
 */
static int data_cmp(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t port, qp, qps_per_port, qps_jump = 1;
	int port_idx, rc;

	for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
		port = cfg->ports[port_idx];
		qps_per_port = params->num_qps_per_port[port];

		for (qp = 0; qp < qps_per_port; qp += qps_jump) {
			struct hltests_nic_qp *qp_p = &params->qps[port][qp];

			if (qp_p->atomic_fna_send_data) {
				uint8_t *src = (uint8_t *)qp_p->host_src_buf + params->wqe_size;
				uint8_t *dst = (uint8_t *)qp_p->host_dst_buf + params->wqe_size;

				rc = hltests_mem_compare(src, dst,
							 params->data_size - params->wqe_size);
				if (rc)
					return rc;
			}
		}
	}

	hltests_nic_print_time_elapsed(&params->base, "data compare", cfg->verbose);
	return 0;
}

/**
 * nic_afa_get_sob_val() - Computes the expected SOB value.
 * @params: Test parameters.
 * @port: The relevant port for the SOB params.
 */
static void nic_afa_get_expected_sob_val(struct hltests_nic_test_params *params, uint32_t port)
{
	struct hltests_nic_sob_params *sob_params;
	struct hltests_nic_test_cfg *cfg;
	uint32_t _local_sob_val, _remote_sob_val, qps_per_port;

	cfg = params->cfg;
	sob_params = &params->sob_params[port];
	qps_per_port = params->num_qps_per_port[port];
	_local_sob_val = qps_per_port * (params->wqes_in_cycle - 1);

	if (params->cfg->atomic_fna_cmpl == AFA_REG_CMPL)
		_remote_sob_val = qps_per_port * params->wqes_in_cycle;
	else
		_remote_sob_val = _local_sob_val;

	sob_params->local_sob_val += _local_sob_val;
	sob_params->remote_sob_val += _remote_sob_val;
}

/**
 * nic_afa_get_supported_features_mask
 * Callback provided to common
 *
 * @param fd file descriptor from test params
 */
static uint64_t nic_afa_get_supported_features_mask(int fd)
{
	uint64_t supported_features_mask = 0;

	supported_features_mask = BIT_ULL(OP_WRITE);

	return supported_features_mask;
}


/**
 * nic_afa_cfg_parser
 * Parse the fna section in the configuratin file
 *
 * @param fd file descriptor from test params
 */
static int cfg_parser(void *user, const char *section, const char *name,
				     const char *value)
{
	struct hltests_nic_test_cfg *cfg = (struct hltests_nic_test_cfg *)user;

	if (MATCH("fna", "fna_cmpl")) {
		if (!strcmp(value, "reg"))
			cfg->atomic_fna_cmpl = AFA_REG_CMPL;
		else if (!strcmp(value, "cq_usr"))
			cfg->atomic_fna_cmpl = AFA_CQ_USR_CMPL;
		else
			cfg->atomic_fna_cmpl = AFA_CMPL_MODE_MAX;
	} else if (MATCH("fna", "atomic_val_loc")) {
		if (!strcmp(value, "dram"))
			cfg->atomic_val_loc = AFA_OP_DRAM;
		else if (!strcmp(value, "sram"))
			cfg->atomic_val_loc = AFA_OP_SRAM;
		else
			cfg->atomic_val_loc = AFA_OP_MAX;
	} else if (MATCH("fna", "fna_thresh")) {
		cfg->atomic_fna_thresh = strtoul(value, NULL, 0);
	}
	return 0;
}

/**
 * nic_afa_parse_cfg
 * Callback provided to common
 *
 * @param fd file descriptor from test params
 * @param cfg pointer to cfg structure
 */
static int nic_afa_parse_cfg(int fd, struct hltests_nic_test_cfg *cfg)
{
	const char *config_filename = hltests_get_config_filename();

	if (ini_parse(config_filename, cfg_parser, cfg) < 0) {
		fail_msg("Can't load %s\n", config_filename);
		return -EFAULT;
	}

	return 0;
}

/**
 * nic_afa_validate_cfg
 * Callback provided to common
 *
 * @param fd file descriptor from test params
 * @param cfg pointer to cfg structure
 */
static int nic_afa_validate_cfg(int fd, struct hltests_nic_test_cfg *cfg)
{
	int rc;
	struct hlthunk_hw_ip_info hw_ip;

	if (!hltests_is_gaudi3(fd)) {
		printf("FnA test only supported for gaudi3, skipping test\n");
		return -ENOTSUP;
	}

	assert_true(cfg->test_opcode == TEST_OPCODE_ATOMIC_FETCH_ADD);

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);


	if (cfg->atomic_val_loc == AFA_OP_DRAM && !hw_ip.dram_enabled) {
		printf("DRAM must be enabled for FnA tests, skipping test\n");
		return -ENOTSUP;
	}

	if (cfg->atomic_val_loc == AFA_OP_SRAM && !hw_ip.sram_size) {
		printf("FnA operation on SRAM is N/A when cache is enabled, skipping test\n");
		return -ENOTSUP;
	}

	/* FnA test is currently supported only for gaudi3, user_db, SOB completion.
	 * Also, both FnA CQ Completion and the Test CQ completion cannot be enabled together
	 * as we are overloading the wqe_index field of the cqe_sw to retrieve the F&A data.
	 */
	assert_true((hltests_is_gaudi3(fd) && cfg->cmpl == SOB &&
		     !(cfg->atomic_fna_cmpl == AFA_CQ_USR_CMPL && (cfg->cmpl & CQ_USR))));
	return 0;
}

/**
 * nic_afa_set_cq_params
 * Callback provided to common. The fna flag is used
 * in the hltests_nic_asic_funcs get_user_cqe callback
 * to overload the wqe index with the fna data
 *
 * @param params pointer to test params
 */
static void nic_afa_set_cq_params(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	bool fna = cfg->atomic_fna_cmpl == AFA_CQ_USR_CMPL;
	int i;

	for (i = 0 ; i <= cfg->user_cq_idx ; i++)
		params->cqs[i].fna = fna;
}

/**
 * nic_afa_alloc_qps_db
 * Callback provided to common
 *
 * @param params pointer to test params
 */
static int nic_afa_alloc_qps_db(struct hltests_nic_test_params *params)
{
	return 0;
}

/**
 * nic_afa_alloc_device_mem
 * Callback provided to common
 *
 * @param params pointer to test params
 */
static int nic_afa_alloc_device_mem(struct hltests_nic_test_params *params)
{
	return 0;
}

/**
 * nic_afa_alloc_host_mem_buffers
 * Callback provided to common
 *
 * @param params pointer to test params
 */
static int nic_afa_alloc_host_mem_buffers(struct hltests_nic_test_params *params)
{
	return 0;
}

/**
 * nic_afa_fill_port_app_params
 * Callback provided to common
 *
 * @param params pointer to test params
 * @param port   port
 * @param app_params pointer to app params
 */
static void nic_afa_fill_port_app_params(struct hltests_nic_test_params *params,
						uint32_t port,
						struct hltests_nic_ib_app_params *app_params)
{
	struct hltests_device *hdev = get_hdev_from_fd(params->fd);
	struct hltests_nic_asic_funcs *nic_funcs = hdev->asic_funcs->nic_funcs;
	int i;

	if (params->cfg->atomic_fna_cmpl == AFA_REG_CMPL) {
		for (i = 0; i < AFA_MAX_NUM_OF_CMPL_REGS; i++)
			app_params->fna_fifo_offs[i] = nic_funcs->get_mem_cmpl_addr(params->fd,
										    FNA_MON_ID + i);
	}
	app_params->fna_mask_size = NIC_AFA_MASK_SIZE;
	app_params->advanced = 1;
}

/**
 * nic_afa_get_user_fifo_num() - Returns how many user fifos are necessary.
 * @params: Test parameters.
 *
 * Return: how many user fifos are necessary.
 */
static uint32_t nic_afa_get_user_fifo_num(struct hltests_nic_test_params *params)
{
	return 1;
}

/**
 * nic_afa_get_user_fifo_type() - Returns the type of the user fifo at a given index.
 * @params:   Test parameters.
 * @fifo_idx: The index of the fifo whose type is needed.
 *
 * Return: The type of the fifo.
 */
static int nic_afa_get_user_fifo_type(struct hltests_nic_test_params *params, uint32_t fifo_idx)
{
	assert_int_equal(fifo_idx, 0);

	return HBLDV_USR_FIFO_TYPE_DB;
}

/**
 * nic_afa_create_qps
 * Callback provided to common
 *
 * @param params pointer to test params
 */
static int nic_afa_create_qps(struct hltests_nic_test_params *params)
{
	return 0;
}

/**
 * nic_afa_fill_qp_attr
 * Callback provided to common
 *
 * @param qp_p pointer to qp
 */
static void nic_afa_fill_qp_attr(struct hltests_nic_qp *qp_p)
{
}

/**
 * nic_afa_set_wq_buffers
 * Callback provided to common
 *
 * @param qp_p pointer to qp
 */
static int nic_afa_set_wq_buffers(struct hltests_nic_qp *qp_p)
{
	return nic_common_generic_set_user_wq_buffers(qp_p);
}

/**
 * nic_afa_pre_runtime
 * Callback provided to common
 *
 * @param params pointer to test params
 */
static int nic_afa_pre_runtime(struct hltests_nic_test_params *params)
{
	return 0;
}

/**
 * nic_afa_runtime
 * Callback provided to common
 *
 * @param params pointer to test params
 */
static int nic_afa_runtime(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	int rc, iter;

	params->wqes_in_cycle = params->num_wqes_in_wq;

	for (iter = 0; iter < cfg->runtime_iterations; iter++) {

		printf("\nruntime iteration %d\n", iter);

		/* Reset the base in the beginning of each runtime iteration */
		clock_gettime(CLOCK_MONOTONIC_RAW, &params->base);
		acquire_resources(params);

		rc = nic_common_reset_dst_buffers(params, params->qps, 0);
		if (rc)
			goto release_resources;

		if (cfg->cmpl == SOB)
			nic_common_clear_sobs(params);

		nic_common_generic_config_wqes(params);

		rc = submit_fna(params);
		if (rc)
			goto release_resources;

		rc = submit(params);
		if (rc)
			goto release_resources;

		rc = nic_common_complete(params);
		if (rc)
			goto release_resources;

		reset_qps(params);

		if (cfg->data_cmp) {
			rc = data_cmp(params);
			if (rc)
				goto release_resources;
		}
		release_resources(params);
	}
	printf("\n");

	return 0;

release_resources:
	release_resources(params);
	return rc;
}

/**
 * nic_afa_destroy_qps
 * Callback provided to common
 *
 * @param params pointer to test params
 */
static int nic_afa_destroy_qps(struct hltests_nic_test_params *params)
{
	return 0;
}

/**
 * nic_afa_free_wq_buffers
 * Callback provided to common
 *
 * @param qp_p pointer to qp
 */
static void nic_afa_free_wq_buffers(struct hltests_nic_qp *qp_p)
{
}

/**
 * nic_afa_destroy_qps_db
 * Callback provided to common
 *
 * @param params pointer to test params
 */
static void nic_afa_destroy_qps_db(struct hltests_nic_test_params *params)
{
}

static struct hltests_nic_test_funcs nic_afa_test_funcs = {
	.get_supported_features_mask = nic_afa_get_supported_features_mask,
	.parse_cfg = nic_afa_parse_cfg,
	.validate_cfg = nic_afa_validate_cfg,
	.set_cq_params = nic_afa_set_cq_params,
	.alloc_qps_db = nic_afa_alloc_qps_db,
	.alloc_device_mem = nic_afa_alloc_device_mem,
	.alloc_host_mem_buffers = nic_afa_alloc_host_mem_buffers,
	.fill_port_app_params = nic_afa_fill_port_app_params,
	.get_user_fifo_num = nic_afa_get_user_fifo_num,
	.get_user_fifo_type = nic_afa_get_user_fifo_type,
	.create_qps = nic_afa_create_qps,
	.fill_qp_attr = nic_afa_fill_qp_attr,
	.get_expected_sob_val = nic_afa_get_expected_sob_val,
	.set_wq_buffers = nic_afa_set_wq_buffers,
	.pre_runtime = nic_afa_pre_runtime,
	.runtime = nic_afa_runtime,
	.destroy_qps = nic_afa_destroy_qps,
	.free_wq_buffers = nic_afa_free_wq_buffers,
	.destroy_qps_db = nic_afa_destroy_qps_db,
};

/**
 * nic_afa_set_test_funcs
 * set the funcs pointer in the test context
 *
 * @param fd file descriptor in test params
 */
void nic_afa_set_test_funcs(int fd)
{
	struct hltests_nic_test_ctx *test_cxt = get_nic_ctx_from_fd(fd);

	test_cxt->funcs = &nic_afa_test_funcs;
}
