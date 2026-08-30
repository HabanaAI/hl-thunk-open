// SPDX-License-Identifier: MIT

/*
 * Copyright 2019-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk_nic_tests.h"
#include "ini.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <ctype.h>

#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "reduction_test.h"
#include "nic_root.h"

#include <infiniband/hbldv.h>

#define member_size(type, member) sizeof(((type *)0)->member)

#define CQ_NUM_OF_ENTRIES	BIT_ULL(15) /* 32K */

#define E2E_PRINT_LEN		32

#define MAC_STR_LEN		(ETH_ALEN * 2 + (ETH_ALEN - 1))

#define AFA_MASK_SIZE			16
#define AFA_READ_CMPL_MEM_RETRIES	20
#define AFA_CTR_VALUE_MASK		6
#define AFA_CTR_VAL_WRAP_VAL		(BIT_ULL(AFA_CTR_VALUE_MASK) - 2)

#define WAIT_FOR_BP_TIMEOUT_SEC	10 /* 10 seconds */
#define WAIT_FOR_BP_TIMEOUT_PLDM_SEC	600 /* 10 minutes */

#define NIC_MAX_TNL_HDR_SIZE 32

static int ibdev_alloc_conn(uint32_t port, uint32_t conn_idx,
			    struct hltests_nic_ib_in_params *ib_in_params,
			    bool is_coll, uint32_t qp_id_hint);

static void nic_setup_ctx_set_remote_size(int fd, struct hltests_nic_requester_conn_ctx *req,
						uint32_t nwq, bool is_rdv_send)
{
	uint32_t wqe_num = MAX(nwq, WQES_MIN);

	if (is_rdv_send)
		req->wq_remote_log_size = 1;
	else if (hltests_is_gaudi2(fd))
		/* SW-61290: Since there is a HW bug in WR-RDV/RD-RDV, the sender WQ size
		 * must be at least 4 times bigger than receiver side. Since we multiply
		 * the receiver by x2 (see nic_setup_ctx_wqe_index) we need here in fact
		 * x8. Also if the number of wqes is less than the min, cap it to minimum.
		 */
		req->wq_remote_log_size = (uint8_t)HL_LOG2(wqe_num << 3);
	else
		req->wq_remote_log_size = (uint8_t)HL_LOG2(wqe_num);
}

static inline void nic_setup_ctx_mac(struct hltests_nic_requester_conn_ctx *req,
					struct hltests_nic_responder_conn_ctx *res,
					uint8_t addr[ETH_ALEN])
{
	hltests_nic_copy_mac_reverse(req->dst_mac_addr, addr);
	hltests_nic_copy_mac_reverse(res->dst_mac_addr, addr);
}

static inline void nic_setup_ctx_wqe_index(int fd, struct hltests_nic_requester_conn_ctx *req,
						enum hltests_nic_cmpl cmpl, uint32_t nwq,
						bool is_rdv, bool is_rdv_send, bool force_nwq)
{
	uint32_t wq_size = 0;

	if (is_rdv) {
		if (hltests_is_gaudi2(fd)) {
			if (is_rdv_send)
				/* SW-61290: Since there is a HW bug in WR-RDV/RD-RDV, the sender WQ
				 * size must be at least 4 times bigger than receiver side. Since
				 * we multiply the receiver by x2 (see below) we need here in fact
				 * x8. Also if the number of wqes is less than the min, cap it to
				 * minimum.
				 */
				wq_size = (MAX(WQES_MIN, nwq) << 3);
			else
				/* H6-3320: In some cases the test can cause that PI equal to CI.
				 * In such case the HW can't tell how many WQEs were pushed to the
				 * WQ. In order to overcome it we'll use twice entries to the WQ.
				 */
				wq_size = (MAX(WQES_MIN, nwq) << 1);
		} else {
			wq_size = MAX(WQES_MIN, nwq);
		}
	} else {
		/*
		 * SW-35814: in case of CQ we want to process all the
		 * WQEs in one doorbell so we need the last index to be
		 * +1 to avoid wraparound and an infinite loop.
		 *
		 * When using qman the wraparound issue is avoided by using half cycles and fences.
		 * Instead of sending all WQEs at once, half of the WQEs are sent first, and a
		 * fence is used. The fence makes sure that all QPs have sent half of the WQEs,
		 * meaning the CI is no longer 0, and the new PI can be 0 (wraparound of wq size).
		 *
		 * When using SOB with user_db the wraparound issue is avoided by using quarter
		 * cycles and different SOB per quarter. Using this logic, it is safe to set PI as 0
		 * (wraparound of wq size), after all QPs have incremented the first quarter SOB.
		 * Since it means that CI is non zero on all queues.
		 */
		if (hltests_is_gaudi(fd) || hltests_is_gaudi2(fd))
			wq_size = (cmpl == SOB && !force_nwq) ? (nwq) : (nwq + 1);
		else
			/* in gaudi3 and up wq_size must be power of 2. next_pow2 will keep the
			 * same value for values which are already power of 2, or will increase the
			 * value for the next power 2 for the ones which are not.
			 */
			wq_size = next_pow2(nwq);
	}

	/* gaudi uses the last_index field, whereas gaudi2 and above use the wq_size field. */
	if (hltests_is_gaudi(fd))
		req->last_index = wq_size - 1;
	else
		req->wq_size = wq_size;
}

static inline void nic_get_wq_arr_nwqe(int fd, struct hltests_nic_in_params *in, uint32_t *max_nwqe)
{
	struct hltests_nic_requester_conn_ctx req = {0};
	uint32_t nwq;
	bool is_rdv, force_nwq;
	int i;

	/* configured wq-array size should be bigger than max_wq we intend to use */
	nwq = in->nwq < WQES_MIN ? WQES_MIN : in->nwq;

	is_rdv = (in->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE) ||
			(in->test_opcode == TEST_OPCODE_RENDEZVOUS_READ);
	force_nwq = is_rdv ? false : !!in->bp_offs;

	for (*max_nwqe = 0, i = 0 ; i < 2 ; i++) {
		nic_setup_ctx_wqe_index(fd, &req, in->cmpl, nwq,
					is_rdv, i ? true : false, force_nwq);

		/* gaudi uses the last_index field */
		if (hltests_is_gaudi(fd))
			req.wq_size = req.last_index + 1;

		if (req.wq_size > *max_nwqe)
			*max_nwqe = req.wq_size;
	}

	/* number of wq entries must be ^2 */
	*max_nwqe = next_pow2(*max_nwqe);
}

static inline void nic_setup_ctx_wq_peer_size(int fd, struct hltests_nic_requester_conn_ctx *req,
						struct hltests_nic_responder_conn_ctx *res)
{
	if (!hltests_is_gaudi(fd) && !hltests_is_gaudi2(fd))
		res->wq_peer_size = req->wq_size;
}

static inline void nic_setup_ctx_mtu(struct hltests_nic_requester_conn_ctx *req, uint16_t mtu)
{
	req->mtu = mtu;
}

static inline void nic_setup_ctx_dst_conn_id(struct hltests_nic_requester_conn_ctx *req,
						struct hltests_nic_responder_conn_ctx *res,
						uint32_t dst_conn_id)
{
	req->dst_conn_id = res->dst_conn_id = dst_conn_id;
}

static inline void nic_setup_ctx_dst_ip_addr(struct hltests_nic_requester_conn_ctx *req,
						struct hltests_nic_responder_conn_ctx *res,
						uint32_t ip_addr)
{
	req->dst_ip_addr = res->dst_ip_addr = ip_addr;
}

static inline void nic_setup_ctx_lag_info(int fd, struct hltests_nic_requester_conn_ctx *req,
						enum hltests_nic_coll_op_mode coll_op,
						uint32_t n_ports, uint32_t lag_idx, bool is_vop)
{
	/* patcher is available in gaudi3 and onwards*/
	if (hltests_is_gaudi(fd) || hltests_is_gaudi2(fd))
		return;

	if (coll_op == COLL_OP_MODE_LEGACY) {
		req->coll_lag_idx = 0;
		req->coll_last_in_lag = 1;
	} else if (coll_op == COLL_OP_MODE_MULTI_LAG ||
			coll_op == COLL_OP_MODE_MULTI_CONTEXT ||
			coll_op == COLL_OP_MODE_MULTI_RANK) {
		/* V-operation assumes lag size of 1, and lag index 0*/
		req->coll_lag_idx = (uint8_t)(is_vop ? 0 : lag_idx);

		if (lag_idx == (n_ports - 1) || is_vop)
			req->coll_last_in_lag = 1;

	}
}

static inline void nic_setup_ctx_congestion_en(int fd, uint32_t port,
						struct hltests_nic_requester_conn_ctx *req,
						enum hltests_nic_cc_mode cc_mode,
						uint64_t cc_port_mask)
{
	/* congestion is available in gaudi2 onwards*/
	if (hltests_is_gaudi(fd))
		return;

	if (hltests_is_gaudi2(fd))
		req->congestion_en = (BIT(port) & cc_port_mask) ?
						cc_mode == CC_MODE_BBR : false;
	else
		req->congestion_en = cc_mode != CC_MODE_DISABLED;
}

static void mac_to_gid(uint8_t *mac_addr, union ibv_gid *gid)
{
	gid->global.subnet_prefix = htobe64(DEFAULT_GID_SUBNET_PREFIX);

	/* Set interface ID. */
	memcpy(&gid->raw[8], mac_addr, 3); /* OUI */
	gid->raw[8] ^= 2; /* Flip bit 1. Marks MAC as locally administered. */

	/* Fixed IB constants. */
	gid->raw[11] = 0xff;
	gid->raw[12] = 0xfe;

	memcpy(&gid->raw[8] + 5, mac_addr + 3, 3); /* NIC specific */
}

static void ip_to_gid(uint32_t ipv4, struct in6_addr *a)
{
	a->s6_addr32[0] = 0;
	a->s6_addr32[1] = 0;
	a->s6_addr32[2] = htobe32(0x0000ffff);
	a->s6_addr32[3] = htobe32(ipv4);
}

static inline int ipv6_addr_v4mapped(const struct in6_addr *a)
{
	return IN6_IS_ADDR_V4MAPPED(&a->s6_addr32) ||
	/* IPv4 encoded multicast addresses */
			(a->s6_addr32[0]  == htobe32(0xff0e0000) &&
			((a->s6_addr32[1] |
			(a->s6_addr32[2] ^ htobe32(0x0000ffff))) == 0UL));
}

static int ibdev_set_responder_conn_ctx(int fd, struct ibv_qp *ibqp, uint32_t port,
					struct hltests_nic_responder_conn_ctx *res_ctx,
					struct hltests_nic_requester_conn_ctx *req_ctx,
					enum hltests_nic_test test)
{
	struct ibv_qp_attr ibv_qp_attr = {};
	struct hbldv_qp_attr hl_qp_attr = {};
	int attr_mask;

	ibv_qp_attr.qp_state = IBV_QPS_RTR;
	ibv_qp_attr.dest_qp_num = res_ctx->dst_conn_id;

	/* Setup AH and GRH. */
	ibv_qp_attr.ah_attr.is_global = 1;
	ibv_qp_attr.ah_attr.grh.hop_limit = 0xff;

	/* IB core calculates source GID using AH attribute port and GRH sgid_index. */
	ibv_qp_attr.ah_attr.port_num = (uint8_t)hltests_nic_to_ibdev_port_num(fd, port);
	ibv_qp_attr.path_mtu = hltests_nic_convert_mtu_to_ibv_mtu(req_ctx->mtu);

	/* Destination GID is same as source GID for MAC lpbk. */
	if (test == LPBK) {
		/* Default GID 0 is reserved for MAC address, used for L2 networks */
		ibv_qp_attr.ah_attr.grh.sgid_index = 0;

		int rc = hlibv_query_gid(ibqp->context,
					ibv_qp_attr.ah_attr.port_num,
					ibv_qp_attr.ah_attr.grh.sgid_index,
					&ibv_qp_attr.ah_attr.grh.dgid);
		assert_int_equal(rc, 0);
	} else {
		/* Config GID from the destination MAC or IP. */
		if (res_ctx->dst_ip_addr) {
			int rc, index = 0;
			union ibv_gid gid;
			struct ibv_port_attr port_attr;
			enum ibv_gid_type_sysfs sgid_type;

			hlibv_query_port(ibqp->context, ibv_qp_attr.ah_attr.port_num, &port_attr);
			assert_false(port_attr.gid_tbl_len < 3);

			for (index = 0; index < port_attr.gid_tbl_len; index++) {
				rc = hlibv_query_gid(ibqp->context,
						     ibv_qp_attr.ah_attr.port_num, index,
						     &gid);
				assert_int_equal(rc, 0);

				if (ipv6_addr_v4mapped((struct in6_addr *)&gid.raw)) {
					rc = hlibv_query_gid_type(ibqp->context,
								  ibv_qp_attr.ah_attr.port_num,
								  (uint32_t)index, &sgid_type);
					assert_int_equal(rc, 0);

					if (sgid_type == IBV_GID_TYPE_SYSFS_ROCE_V2)
						break;
				}
			}

			assert_true(index < port_attr.gid_tbl_len);

			ibv_qp_attr.ah_attr.grh.sgid_index = (uint8_t)index;

			ip_to_gid(res_ctx->dst_ip_addr,
					(struct in6_addr *)ibv_qp_attr.ah_attr.grh.dgid.raw);
		} else {
			uint8_t mac_addr[ETH_ALEN] = {};

			/* Default GID 0 is reserved for MAC address, used for L2 networks */
			ibv_qp_attr.ah_attr.grh.sgid_index = 0;

			hltests_nic_copy_mac_reverse(mac_addr, res_ctx->dst_mac_addr);
			mac_to_gid(mac_addr, &ibv_qp_attr.ah_attr.grh.dgid);
		}
	}

	hl_qp_attr.priority = res_ctx->priority;
	hl_qp_attr.caps |= res_ctx->loopback ? HBLDV_QP_CAP_LOOPBACK : 0; /* QP loopback. */
	hl_qp_attr.local_key = res_ctx->local_key;
	/* Selective acknowledgment. */
	hl_qp_attr.caps |= res_ctx->sack_en ? HBLDV_QP_CAP_SACK : 0;

	hl_qp_attr.caps |= res_ctx->encap_en ? HBLDV_QP_CAP_ENCAP : 0;
	hl_qp_attr.encap_num = res_ctx->encap_id;

	/* IB core mandates below QP attribute mask. */
	attr_mask = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
			IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

	return hbldv_modify_qp(ibqp, &ibv_qp_attr, attr_mask, &hl_qp_attr);
}

static int ibdev_set_requester_conn_ctx(struct ibv_qp *ibqp, uint32_t port,
					struct hltests_nic_requester_conn_ctx *req_ctx,
					enum hltests_nic_test test)
{
	struct ibv_qp_attr ibv_qp_attr = {};
	struct hbldv_qp_attr hl_qp_attr = {};
	int attr_mask;

	ibv_qp_attr.qp_state = IBV_QPS_RTS;
	ibv_qp_attr.dest_qp_num = req_ctx->dst_conn_id;
	ibv_qp_attr.timeout = req_ctx->timer_granularity;

	hl_qp_attr.priority = req_ctx->priority;
	hl_qp_attr.caps |= req_ctx->loopback ? HBLDV_QP_CAP_LOOPBACK : 0; /* QP loopback. */
	/* Selective acknowledgment. */
	hl_qp_attr.caps |= req_ctx->sack_en ? HBLDV_QP_CAP_SACK : 0;
	hl_qp_attr.caps |= req_ctx->compression_en ? HBLDV_QP_CAP_COMPRESSION : 0;
	hl_qp_attr.dest_wq_size = BIT(req_ctx->wq_remote_log_size);
	hl_qp_attr.caps |= req_ctx->congestion_en ? HBLDV_QP_CAP_CONG_CTRL : 0;
	hl_qp_attr.congestion_wnd = req_ctx->congestion_wnd;
	hl_qp_attr.coll_lag_idx = req_ctx->coll_lag_idx;
	hl_qp_attr.coll_last_in_lag = req_ctx->coll_last_in_lag;

	hl_qp_attr.caps |= req_ctx->encap_en ? HBLDV_QP_CAP_ENCAP : 0;
	hl_qp_attr.encap_num = req_ctx->encap_id;

	/* IB core mandates below QP attribute mask. */
	attr_mask = IBV_QP_STATE | IBV_QP_MAX_QP_RD_ATOMIC | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
			IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN;

	return hbldv_modify_qp(ibqp, &ibv_qp_attr, attr_mask, &hl_qp_attr);
}

static void fill_hlthunk_requester_conn_ctx(struct hlthunk_requester_conn_ctx *hlthunk_req_ctx,
					const struct hltests_nic_requester_conn_ctx *hltest_req_ctx)
{
	memset(hlthunk_req_ctx, 0, sizeof(*hlthunk_req_ctx));

	hlthunk_req_ctx->dst_ip_addr = hltest_req_ctx->dst_ip_addr;
	hlthunk_req_ctx->dst_conn_id = hltest_req_ctx->dst_conn_id;
	hlthunk_req_ctx->last_index = hltest_req_ctx->last_index;
	memcpy(hlthunk_req_ctx->dst_mac_addr, hltest_req_ctx->dst_mac_addr,
		sizeof(hlthunk_req_ctx->dst_mac_addr));
	hlthunk_req_ctx->priority = hltest_req_ctx->priority;
	hlthunk_req_ctx->timer_granularity = hltest_req_ctx->timer_granularity;
	hlthunk_req_ctx->swq_granularity = hltest_req_ctx->swq_granularity;
	hlthunk_req_ctx->wq_type = hltest_req_ctx->wq_type;
	hlthunk_req_ctx->cq_number = hltest_req_ctx->cq_number;
	hlthunk_req_ctx->wq_remote_log_size = hltest_req_ctx->wq_remote_log_size;
	hlthunk_req_ctx->congestion_wnd = hltest_req_ctx->congestion_wnd;
	hlthunk_req_ctx->mtu = hltest_req_ctx->mtu;
	hlthunk_req_ctx->congestion_en = hltest_req_ctx->congestion_en;
	hlthunk_req_ctx->encap_en = hltest_req_ctx->encap_en;
	hlthunk_req_ctx->encap_id = hltest_req_ctx->encap_id;
	hlthunk_req_ctx->loopback = hltest_req_ctx->loopback;
	hlthunk_req_ctx->wq_size = hltest_req_ctx->wq_size;
	hlthunk_req_ctx->coll_lag_idx = hltest_req_ctx->coll_lag_idx;
	hlthunk_req_ctx->coll_last_in_lag = hltest_req_ctx->coll_last_in_lag;
	hlthunk_req_ctx->compression_en = hltest_req_ctx->compression_en;
	hlthunk_req_ctx->remote_key = hltest_req_ctx->remote_key;
	hlthunk_req_ctx->sack_en = hltest_req_ctx->sack_en;
}

static void fill_hlthunk_responder_conn_ctx(struct hlthunk_responder_conn_ctx *hlthunk_res_ctx,
				const struct hltests_nic_responder_conn_ctx *hltests_res_ctx)
{
	memset(hlthunk_res_ctx, 0, sizeof(*hlthunk_res_ctx));

	hlthunk_res_ctx->dst_ip_addr = hltests_res_ctx->dst_ip_addr;
	hlthunk_res_ctx->dst_conn_id = hltests_res_ctx->dst_conn_id;
	memcpy(hlthunk_res_ctx->dst_mac_addr, hltests_res_ctx->dst_mac_addr,
		sizeof(hlthunk_res_ctx->dst_mac_addr));
	hlthunk_res_ctx->priority = hltests_res_ctx->priority;
	hlthunk_res_ctx->wq_peer_granularity = hltests_res_ctx->wq_peer_granularity;
	hlthunk_res_ctx->cq_number = hltests_res_ctx->cq_number;
	hlthunk_res_ctx->conn_peer = hltests_res_ctx->conn_peer;
	hlthunk_res_ctx->rdv = hltests_res_ctx->rdv;
	hlthunk_res_ctx->loopback = hltests_res_ctx->loopback;
	hlthunk_res_ctx->wq_peer_size = hltests_res_ctx->wq_peer_size;
	hlthunk_res_ctx->encap_en = hltests_res_ctx->encap_en;
	hlthunk_res_ctx->encap_id = hltests_res_ctx->encap_id;
	hlthunk_res_ctx->local_key = hltests_res_ctx->local_key;
	hlthunk_res_ctx->sack_en = hltests_res_ctx->sack_en;
}

int legacy_set_requester_conn_ctx(int fd, uint32_t port, uint32_t conn_id,
					const struct hltests_nic_requester_conn_ctx *hltests_ctx,
					struct hlthunk_requester_conn_ctx_out *out)
{
	struct hlthunk_requester_conn_ctx req_ctx;

	fill_hlthunk_requester_conn_ctx(&req_ctx, hltests_ctx);

	return hlthunk_set_requester_conn_ctx(fd, port, conn_id, &req_ctx, out);
}

int legacy_set_responder_conn_ctx(int fd, uint32_t port, uint32_t conn_id,
					const struct hltests_nic_responder_conn_ctx *hltests_ctx)
{
	struct hlthunk_responder_conn_ctx res_ctx;

	fill_hlthunk_responder_conn_ctx(&res_ctx, hltests_ctx);

	return hlthunk_set_responder_conn_ctx(fd, port, conn_id, &res_ctx);
}

static void nic_pre_setup_ctx_lpbk(int fd, struct hltests_nic_lpbk_cfg *cfg,
					struct hltests_nic_contexts *nic_ctx,
					struct hltests_nic_in_params *in_params)
{
	uint32_t conn, port, qps_per_port, port_idx;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];
		if (!(in_params->port_mask & BIT_ULL(port)))
			continue;

		qps_per_port = cfg->qps_per_port[port_idx];
		for (conn = 0 ; conn < qps_per_port ; conn++) {
			if ((cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE) ||
				(cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ))
				hltests_nic_pre_setup_default_ctx_rdv(fd,
							&nic_ctx->req_ctx[port][conn],
							cfg->test_opcode, conn & 1,
							cfg->rdv_type == HLTESTS_NIC_RDV_MS);
			else
				hltests_nic_pre_setup_ctx(fd, &nic_ctx->req_ctx[port][conn]);
		}
	}
}

/* For WR-RDV test, these are the considerations:
 * 1.There are 2 QPs involved per transaction. One Sender and Other receiver.
 * 2.We assign the receive side QPs as the even qp indexes and the send side QPs to be the
 *   odd qp indexes. The actual QP IDs assigned by the LKD can be anything we dont worry about that.
 * 3.In the QP context, the destination QP needs to be programmed to the correct QP. For ex:
 *   let's say QP ids, QP1 and QP2 are the pair for RDV transfer. Then the destination QP of QP1
 *   should be '2' and destination QP of QP2 should be '1'.
 */
static int nic_setup_ctx_lpbk(int fd, struct hltests_nic_lpbk_cfg *cfg,
				struct hltests_state *tests_state,
				struct hltests_nic_conn_out *qp_conn,
				struct hltests_nic_contexts *nic_ctx,
				struct hltests_nic_in_params *in_params)
{
	uint32_t conn, conn_id, wq_nwq, nwq, port, qps_per_port, port_idx, lag_idx = 0,
		mmap_num_wqes, swq_size, rwq_size;
	struct hbldv_query_qp_attr dv_qp_attr = {};
	struct hlthunk_requester_conn_ctx_out req_out_params;
	int rc = 0;

	nwq = in_params->nwq;
	wq_nwq = nwq < WQES_MIN ? WQES_MIN : nwq;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];
		if (!(in_params->port_mask & BIT_ULL(port)))
			continue;

		qps_per_port = cfg->qps_per_port[port_idx];
		for (conn = 0 ; conn < qps_per_port ; conn++) {
			conn_id = qp_conn->conn_id[port][conn];

			if ((cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE) ||
				(cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ)) {
				hltests_nic_setup_default_ctx_rdv(fd, (int)port,
								  &nic_ctx->req_ctx[port][conn],
								  &nic_ctx->res_ctx[port][conn],
								  conn & 1, conn_id,
								  cfg->rdv_type ==
								  HLTESTS_NIC_RDV_MS);

				if (conn & 1) {
					nic_setup_ctx_dst_conn_id(&nic_ctx->req_ctx[port][conn],
							&nic_ctx->res_ctx[port][conn],
							qp_conn->conn_id[port][conn - 1]);
				} else {
					nic_setup_ctx_dst_conn_id(&nic_ctx->req_ctx[port][conn],
							&nic_ctx->res_ctx[port][conn],
							qp_conn->conn_id[port][conn + 1]);
				}

				nic_setup_ctx_wqe_index(fd, &nic_ctx->req_ctx[port][conn],
							cfg->cmpl, nwq, true, conn & 1, false);

				nic_setup_ctx_set_remote_size(fd, &nic_ctx->req_ctx[port][conn],
								nwq, conn & 1);

				nic_setup_ctx_wq_peer_size(fd, &nic_ctx->req_ctx[port][conn],
							&nic_ctx->res_ctx[port][conn]);
			} else {
				hltests_nic_setup_ctx_lpbk(fd, (int)port,
							   &nic_ctx->req_ctx[port][conn],
							   &nic_ctx->res_ctx[port][conn], conn,
							   cfg);

				nic_setup_ctx_dst_conn_id(&nic_ctx->req_ctx[port][conn],
							&nic_ctx->res_ctx[port][conn], conn_id);

				nic_setup_ctx_wqe_index(fd, &nic_ctx->req_ctx[port][conn],
							cfg->cmpl, nwq, false, false,
							!!cfg->bp_offs);
			}

			nic_setup_ctx_mac(&nic_ctx->req_ctx[port][conn],
						&nic_ctx->res_ctx[port][conn],
						tests_state->mac_addrs[port].addr);

			nic_setup_ctx_mtu(&nic_ctx->req_ctx[port][conn], cfg->mtu);

			nic_setup_ctx_lag_info(fd, &nic_ctx->req_ctx[port][conn],
						cfg->coll_op, in_params->n_ports, lag_idx,
						cfg->rdv_type == HLTESTS_NIC_RDV_V_OP);

			nic_setup_ctx_congestion_en(fd, port, &nic_ctx->req_ctx[port][conn],
							cfg->cc_cq, in_params->cc_port_mask);

			/* No corresponding bit in responder QPC. */
			nic_ctx->req_ctx[port][conn].compression_en = cfg->compression_en;

			if (cfg->assign_qp_priority) {
				/* Assign QP priority as 1,2,3 to every QP in round robin */
				nic_ctx->req_ctx[port][conn].priority = (uint8_t)(1 + conn % 3);

				/* In Gaudi3, requester side of LPBK QP supports priorites 0,1 */
				if (hltests_is_gaudi3(fd) && nic_ctx->req_ctx[port][conn].loopback)
					nic_ctx->req_ctx[port][conn].priority = conn % 2;
			} else {
				nic_ctx->req_ctx[port][conn].priority = 1;
			}

			nic_ctx->res_ctx[port][conn].sack_en = cfg->sack_en;
			nic_ctx->req_ctx[port][conn].sack_en = cfg->sack_en;
			nic_ctx->req_ctx[port][conn].timer_granularity = NIC_QP_TIMER_GRAN;

			/* adhering to ibverbs spec, first config the responder, then
			 * config the requester.
			 */
			if (hltests_nic_is_ibdev(fd))
				rc = ibdev_set_responder_conn_ctx(fd, qp_conn->ibqp[port][conn],
							port, &nic_ctx->res_ctx[port][conn],
							&nic_ctx->req_ctx[port][conn],
							in_params->test);
			else
				rc = legacy_set_responder_conn_ctx(fd, port, conn_id,
						&nic_ctx->res_ctx[port][conn]);
			assert_int_equal(rc, 0);

			if (hltests_nic_is_ibdev(fd))
				rc = ibdev_set_requester_conn_ctx(qp_conn->ibqp[port][conn], port,
							&nic_ctx->req_ctx[port][conn],
							in_params->test);
			else
				rc = legacy_set_requester_conn_ctx(fd, port, conn_id,
							&nic_ctx->req_ctx[port][conn],
							&req_out_params);
			assert_int_equal(rc, 0);

			if (!in_params->wtd_en && !in_params->coll_op) {
				mmap_num_wqes = hltests_is_gaudi(fd) ?
						nic_ctx->req_ctx[port][conn].last_index + 1 :
						nic_ctx->req_ctx[port][conn].wq_size;

				conn_id -= hltests_nic_get_wq_offset(fd, (int)port, conn_id);

				if (hltests_nic_is_ibdev(fd)) {
					hbldv_query_qp(qp_conn->ibqp[port][conn], &dv_qp_attr);
					qp_conn->swq_buf[port][conn_id] = dv_qp_attr.swq_cpu_addr;
				} else {
					swq_size = mmap_num_wqes * hltests_nic_get_swqe_size(fd);
					qp_conn->swq_buf[port][conn_id] =
							hltests_mmap(fd, swq_size, (off_t)
								req_out_params.swq_mem_handle);
				}

				assert_ptr_not_equal(qp_conn->swq_buf[port][conn_id], MAP_FAILED);

				if (hltests_nic_is_ibdev(fd)) {
					qp_conn->rwq_buf[port][conn_id] = dv_qp_attr.rwq_cpu_addr;
				} else {
					rwq_size = mmap_num_wqes * hltests_nic_get_rwqe_size(fd);
					qp_conn->rwq_buf[port][conn_id] =
							hltests_mmap(fd, rwq_size, (off_t)
								req_out_params.rwq_mem_handle);
				}

				assert_ptr_not_equal(qp_conn->rwq_buf[port][conn_id], MAP_FAILED);
			}
		}
		/* increment lag per port */
		lag_idx++;
	}

	return rc;
}

static void nic_pre_setup_ctx_e2e(int fd, struct hltests_nic_e2e_cfg *cfg,
					struct hltests_nic_contexts *nic_ctx)
{
	uint32_t i, conn, port, qps_per_port, *port_list, ports_num;

	port_list = cfg->ports;
	ports_num = cfg->ports_num;

	for (i = 0 ; i < ports_num ; i++) {
		port = port_list[i];
		qps_per_port = cfg->qps_per_port[i];

		for (conn = 0 ; conn < qps_per_port ; conn++)
			hltests_nic_pre_setup_ctx(fd, &nic_ctx->req_ctx[port][conn]);
	}
}

static int nic_setup_ctx_e2e(int fd, struct hltests_nic_e2e_cfg *cfg,
				struct hltests_state *tests_state,
				struct hltests_nic_conn_out *qp_conn,
				struct hltests_nic_contexts *nic_ctx,
				struct hltests_nic_in_params *in_params)
{
	uint32_t i, conn, conn_id, conn_idx, wq_nwq, nwq, port, qps_per_port, *port_list, ports_num,
		qps_till_now = 0, mmap_num_wqes, swq_size, rwq_size;
	struct hlthunk_requester_conn_ctx_out req_out_params;
	struct hbldv_query_qp_attr dv_qp_attr = {};
	int rc = 0;

	nwq = in_params->nwq;
	wq_nwq = nwq < WQES_MIN ? WQES_MIN : nwq;

	port_list = cfg->ports;
	ports_num = cfg->ports_num;

	for (i = 0 ; i < ports_num ; i++) {
		port = port_list[i];
		qps_per_port = cfg->qps_per_port[i];

		for (conn = 0 ; conn < qps_per_port ; conn++) {
			conn_id = qp_conn->conn_id[port][conn];
			conn_idx = qps_till_now + conn;

			hltests_nic_setup_ctx_e2e(fd, (int)port, &nic_ctx->req_ctx[port][conn],
						  &nic_ctx->res_ctx[port][conn], cfg);

			nic_setup_ctx_mac(&nic_ctx->req_ctx[port][conn],
						&nic_ctx->res_ctx[port][conn],
						cfg->dst_macs[conn_idx]);

			nic_setup_ctx_dst_ip_addr(&nic_ctx->req_ctx[port][conn],
							&nic_ctx->res_ctx[port][conn],
							cfg->dst_ips[conn_idx]);

			nic_setup_ctx_dst_conn_id(&nic_ctx->req_ctx[port][conn],
							&nic_ctx->res_ctx[port][conn],
							cfg->dst_conn_ids[conn_idx]);

			nic_setup_ctx_wqe_index(fd, &nic_ctx->req_ctx[port][conn], cfg->cmpl,
						nwq, false, false, false);

			nic_setup_ctx_mtu(&nic_ctx->req_ctx[port][conn], cfg->mtu);

			nic_setup_ctx_congestion_en(fd, port, &nic_ctx->req_ctx[port][conn],
							cfg->cc_cq, in_params->cc_port_mask);

			nic_ctx->req_ctx[port][conn].priority = 1;
			nic_ctx->req_ctx[port][conn].timer_granularity = NIC_QP_TIMER_GRAN;

			/* adhering to ibverbs spec, first config the responder, then
			 * config the requester.
			 */
			if (hltests_nic_is_ibdev(fd))
				rc = ibdev_set_responder_conn_ctx(fd, qp_conn->ibqp[port][conn],
							port, &nic_ctx->res_ctx[port][conn],
							&nic_ctx->req_ctx[port][conn],
							in_params->test);
			else
				rc = legacy_set_responder_conn_ctx(fd, port, conn_id,
							&nic_ctx->res_ctx[port][conn]);

			assert_int_equal(rc, 0);

			if (hltests_nic_is_ibdev(fd))
				rc = ibdev_set_requester_conn_ctx(qp_conn->ibqp[port][conn], port,
							&nic_ctx->req_ctx[port][conn],
							in_params->test);
			else
				rc = legacy_set_requester_conn_ctx(fd, port,
						conn_id, &nic_ctx->req_ctx[port][conn],
						&req_out_params);
			assert_int_equal(rc, 0);

			if (!in_params->wtd_en && !in_params->coll_op) {
				mmap_num_wqes = hltests_is_gaudi(fd) ?
						nic_ctx->req_ctx[port][conn].last_index + 1 :
						nic_ctx->req_ctx[port][conn].wq_size;

				conn_id -= hltests_nic_get_wq_offset(fd, (int)port, conn_id);

				if (hltests_nic_is_ibdev(fd)) {
					hbldv_query_qp(qp_conn->ibqp[port][conn], &dv_qp_attr);
					qp_conn->swq_buf[port][conn_id] = dv_qp_attr.swq_cpu_addr;
				} else {
					swq_size = mmap_num_wqes * hltests_nic_get_swqe_size(fd);
					qp_conn->swq_buf[port][conn_id] =
							hltests_mmap(fd, swq_size,
							(off_t)req_out_params.swq_mem_handle);
				}

				assert_ptr_not_equal(qp_conn->swq_buf[port][conn_id], MAP_FAILED);

				if (hltests_nic_is_ibdev(fd)) {
					qp_conn->rwq_buf[port][conn_id] = dv_qp_attr.rwq_cpu_addr;
				} else {
					rwq_size = mmap_num_wqes * hltests_nic_get_rwqe_size(fd);
					qp_conn->rwq_buf[port][conn_id] =
							hltests_mmap(fd, rwq_size, (off_t)
							req_out_params.rwq_mem_handle);
				}

				assert_ptr_not_equal(qp_conn->rwq_buf[port][conn_id], MAP_FAILED);
			}
		}
		qps_till_now += qps_per_port;
	}

	return rc;
}

static int wait_for_transfer_completion(void *dst, uint64_t size, uint64_t timeout_us)
{
	struct timespec now;
	struct timespec later;
	uint64_t *dst_guard = (uint64_t *) (((uint8_t *) dst) + size - PLAIN_RDMA_MAGIC_SIZE);

	clock_gettime(CLOCK_MONOTONIC, &now);

	later.tv_sec = now.tv_sec + (time_t)(timeout_us / USEC_PER_SEC);
	later.tv_nsec = now.tv_nsec + (time_t)((timeout_us % USEC_PER_SEC) * NSEC_PER_USEC);

	while (1) {
		clock_gettime(CLOCK_MONOTONIC, &now);

		/* Return with error if timed out. */
		if (later.tv_sec <= now.tv_sec)
			return -ETIME;

		if (*dst_guard == PLAIN_RDMA_MAGIC)
			return 0;

		usleep(1000);
	}
}

static VOID nic_data_cmp(int fd, struct hltests_nic_in_params *in_params, uint32_t max_num_ports)
{
	uint64_t port_mask = in_params->port_mask, data_size;
	uint32_t qps_per_port, nic, qp, size_of_wqe = in_params->wqe_size, src_qp_rdv_offset = 0;
	bool single_alloc = in_params->single_alloc;
	void **src_buf, **dst_buf;
	int rc = 0;

	/* Compare host memories
	 * For WR-RDV transaction, we need to compare the dest buffer of the recv side with the
	 * source buf of the send side
	 * For RD-RDV transaction, we need to compare the source buffer and dest buffer from the
	 * receive side. This is because, there is no WQE posted for the send side and the receive
	 * side WQE is entirely copied onto the send side and executed by the send side QP.
	 */
	for (nic = 0 ; nic < max_num_ports ; nic++) {
		if (!(port_mask & BIT_ULL(nic)))
			continue;

		qps_per_port = in_params->qps_per_port[nic];

		/* In case of reduction, compare the dest buf with the reference
		 * buffer that was calculated by the test.
		 */
		if (in_params->reduction_cfg) {
			src_buf = (void **) in_params->dst_buf_ref[nic];
			dst_buf = (void **) in_params->dst_buf[nic];
			data_size = in_params->dst_data_size;
		} else {
			src_buf = (void **) in_params->src_buf[nic];
			dst_buf = (void **) in_params->dst_buf[nic];
			data_size = in_params->data_size;
			src_qp_rdv_offset = 1;
		}

		if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE) {
			for (qp = 0 ; qp < qps_per_port ; qp += 2) {
				if (single_alloc) {
					if (qp)
						continue;
					rc = hltests_mem_compare(src_buf[0],
							dst_buf[0], data_size);
					assert_int_equal(rc, 0);
				} else {
					rc = hltests_mem_compare(src_buf[qp + src_qp_rdv_offset],
								dst_buf[qp], data_size);
					assert_int_equal(rc, 0);
				}
			}
		} else if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) {
			for (qp = 0 ; qp < qps_per_port ; qp += 2) {
				if (single_alloc && qp)
					continue;
				rc = hltests_mem_compare(src_buf[qp], dst_buf[qp], data_size);
				assert_int_equal(rc, 0);
			}
		} else if (in_params->test_opcode == TEST_OPCODE_ATOMIC_FETCH_ADD) {
			/* In case of FnA, first WQE of the WQ is a FnA WQE.
			 * Comparing the data is done without the first WQE by
			 * starting to compare at the second WQE of each QP and
			 * reducing the size of the comparison by one WQE size.
			 */
			for (qp = 0 ; qp < qps_per_port ; qp++) {
				uint8_t *src = (uint8_t *)(src_buf[qp]) + size_of_wqe;
				uint8_t *dst = (uint8_t *)(dst_buf[qp]) + size_of_wqe;

				if (in_params->fna_qp_send_data[nic][qp])
					rc = hltests_mem_compare(src, dst, data_size - size_of_wqe);

				assert_int_equal(rc, 0);
			}
		} else {
			for (qp = 0 ; qp < qps_per_port ; qp++) {
				if (single_alloc && qp)
					continue;
				if (in_params->is_plain_rdma) {
					uint64_t timeout_us = hltests_is_pldm(fd) ?
								NIC_CQ_TIMEOUT_PLDM_USEC :
								NIC_CQ_TIMEOUT_USEC;

					rc = wait_for_transfer_completion(dst_buf[qp], data_size,
									timeout_us);
					assert_int_equal(rc, 0);
				}
				rc = hltests_mem_compare(src_buf[qp], dst_buf[qp],
							data_size);
				assert_int_equal(rc, 0);
			}
		}

		/* In these modes, all ports collectively transmit data.
		 * We use source data buffer of first available port.
		 */
		if (in_params->coll_op == COLL_OP_MODE_MULTI_LAG ||
			in_params->coll_op == COLL_OP_MODE_MULTI_RANK ||
			in_params->coll_op == COLL_OP_MODE_MULTI_CONTEXT)
			break;
	}

	END_TEST;
}

static int e2e_parser(void *user, const char *section, const char *name, const char *value)
{
	struct hltests_nic_e2e_cfg *cfg = (struct hltests_nic_e2e_cfg *) user;
	char str[INI_MAX_LINE] = {0}, *token;
	size_t len = strlen(value);
	struct in_addr inp;
	uint32_t *ptr;

	if (MATCH("e2e", "ports")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			cfg->ports[cfg->ports_num++] = (uint32_t)strtoul(token, NULL, 0);
			token = strtok(NULL, " ");
		}
	} else if (MATCH("e2e", "qps_per_port")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			ptr = &cfg->qps_per_port[cfg->qps_per_port_num_elements];
			*ptr = (uint32_t)strtoul(token, NULL, 0);
			/* saving max_qps_per_port since some tests need it */
			if (*ptr > cfg->max_qps_per_port)
				cfg->max_qps_per_port = *ptr;
			cfg->qps_per_port_num_elements++;
			token = strtok(NULL, " ");
		}
	} else if (MATCH("e2e", "dst_ips")) {
		memcpy(str, value, strlen(value));
		token = strtok(str, " ");
		while (token) {
			if (!inet_aton(token, &inp)) {
				printf("dst ip %s is invalid\n", token);
				return 0;
			}
			/* switch to native endianness */
			cfg->dst_ips[cfg->dst_ips_num++] = be32toh(inp.s_addr);
			token = strtok(NULL, " ");
		}
	} else if (MATCH("e2e", "dst_conn_ids")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			cfg->dst_conn_ids[cfg->dst_conn_ids_num++] =
				(uint32_t)strtoul(token, NULL, 0);
			token = strtok(NULL, " ");
		}
	} else if (MATCH("e2e", "remote_sob_idx")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			cfg->remote_sob_idx[cfg->remote_sob_idx_num++] =
				(uint32_t)strtoul(token, NULL, 0);
			token = strtok(NULL, " ");
		}
	} else if (MATCH("e2e", "remote_addr_idx")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			cfg->remote_addr_idx[cfg->remote_addr_idx_num++] =
				(uint32_t)strtoul(token, NULL, 0);
			token = strtok(NULL, " ");
		}
	} else if (MATCH("e2e", "dst_macs")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			if (strlen(token) == MAC_STR_LEN)
				hltests_nic_parse_mac(cfg->dst_macs[cfg->dst_macs_num++], token);
			token = strtok(NULL, " ");
		}
	} else if (MATCH("e2e", "data_size_shift")) {
		cfg->data_size_shift = (uint8_t)strtoul(value, NULL, 0);
	} else if (MATCH("e2e", "wqe_size_shift")) {
		cfg->wqe_size_shift = (uint8_t)strtoul(value, NULL, 0);
	} else if (MATCH("e2e", "cmpl")) {
		if (!strcmp(value, "cq_usr"))
			cfg->cmpl = CQ_USR;
		else
			cfg->cmpl = SOB;
	} else if (MATCH("e2e", "user_cq_buf_len_shift")) {
		cfg->user_cq_buf_len_shift = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("e2e", "user_cq_idx")) {
		cfg->user_cq_idx = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("e2e", "print_data")) {
		cfg->print_data = !strcmp(value, "yes");
	} else if (MATCH("e2e", "seed")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			cfg->seed[cfg->seed_num++] = (uint32_t)strtoul(token, NULL, 0);
			token = strtok(NULL, " ");
		}
	} else if (MATCH("e2e", "iterations")) {
		cfg->iterations = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("e2e", "wait_for_cleanup")) {
		cfg->wait_for_cleanup = !strcmp(value, "yes");
	} else if (MATCH("e2e", "plain_rdma")) {
		cfg->plain_rdma = !strcmp(value, "yes");
	}  else if (MATCH("e2e", "sleep_before_cleanup")) {
		cfg->sleep_before_cleanup = (uint8_t)strtoul(value, NULL, 0);
	} else if (MATCH("e2e", "lazy")) {
		cfg->lazy = !strcmp(value, "yes");
	} else if (MATCH("e2e", "doorbell_to")) {
		cfg->doorbell_to = (uint8_t)strtoul(value, NULL, 0);
	} else if (MATCH("e2e", "rand_data")) {
		cfg->rand_data = !strcmp(value, "yes");
	} else if (MATCH("e2e", "data_cmp")) {
		cfg->data_cmp = !strcmp(value, "yes");
	} else if (MATCH("e2e", "cleanup")) {
		cfg->cleanup = !strcmp(value, "yes");
	} else if (MATCH("e2e", "wq_loc")) {
		if (!strcmp(value, "host"))
			cfg->wq_loc = WQ_LOC_HOST;
		else
			cfg->wq_loc = WQ_LOC_DEVICE;
	} else if (MATCH("e2e", "verbose")) {
		if (!strcmp(value, "0"))
			cfg->verbose = VERBOSE_NONE;
		else if (!strcmp(value, "1"))
			cfg->verbose = VERBOSE_INFO;
		else
			cfg->verbose = VERBOSE_DEBUG;
	} else if (MATCH("e2e", "mtu")) {
		cfg->mtu = (uint16_t)strtoul(value, NULL, 0);
	} else if (MATCH("e2e", "user_db")) {
		cfg->user_db = !strcmp(value, "yes");
	} else if (MATCH("e2e", "cc_cq")) {
		cfg->cc_cq = !strcmp(value, "yes");
	} else if (MATCH("e2e", "encap_type")) {
		if (!strcmp(value, "vxlan"))
			cfg->encap_type = HL_NIC_ENCAP_OVER_UDP;
		else if (!strcmp(value, "gre"))
			cfg->encap_type = HL_NIC_ENCAP_OVER_IPV4;
		else
			cfg->encap_type = HL_NIC_ENCAP_NONE;
	} else if (MATCH("e2e", "src_ip")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			if (!inet_aton(token, &inp)) {
				printf("ip %s is invalid\n", token);
				return 0;
			}

			/* switch to native endianness */
			cfg->src_ip_addr = be32toh(inp.s_addr);
			token = strtok(NULL, " ");
		}
	} else {
		return 0; /* unknown section/name, error */
	}

	return 1;
}

static int lpbk_parser(void *user, const char *section, const char *name, const char *value)
{
	struct hltests_nic_lpbk_cfg *cfg = (struct hltests_nic_lpbk_cfg *) user;
	char str[INI_MAX_LINE] = {0}, *token;
	struct in_addr inp;
	size_t len = strlen(value) > 200 ? 200 : strlen(value);
	uint32_t *ptr;

	if (MATCH("lpbk", "ports")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			cfg->ports[cfg->ports_num++] = (uint32_t)strtoul(token, NULL, 0);
			token = strtok(NULL, " ");
		}
	} else if (MATCH("lpbk", "qps_per_port")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			ptr = &cfg->qps_per_port[cfg->qps_per_port_num_elements];
			*ptr = (uint32_t)strtoul(token, NULL, 0);
			/* saving max_qps_per_port since some tests need it */
			if (*ptr > cfg->max_qps_per_port)
				cfg->max_qps_per_port = *ptr;
			cfg->qps_per_port_num_elements++;
			token = strtok(NULL, " ");
		}
	} else if (MATCH("lpbk", "iterations_mem")) {
		cfg->iterations_mem = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("lpbk", "iterations_db")) {
		cfg->iterations_db = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("lpbk", "iterations_wq")) {
		cfg->iterations_wq = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("lpbk", "cq_buf_len_shift")) {
		cfg->cq_buf_len_shift = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("lpbk", "user_cq_buf_len_shift")) {
		cfg->user_cq_buf_len_shift = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("lpbk", "user_cq_idx")) {
		cfg->user_cq_idx = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("lpbk", "data_loc")) {
		if (!strcmp(value, "host"))
			cfg->data_loc = DATA_LOC_HOST;
		else if (!strcmp(value, "dram"))
			cfg->data_loc = DATA_LOC_DRAM;
		else if (!strcmp(value, "sram"))
			cfg->data_loc = DATA_LOC_SRAM;
		else
			cfg->data_loc = DATA_LOC_ALL;
	} else if (MATCH("lpbk", "wq_loc")) {
		if (!strcmp(value, "host"))
			cfg->wq_loc = WQ_LOC_HOST;
		else if (!strcmp(value, "device"))
			cfg->wq_loc = WQ_LOC_DEVICE;
		else
			cfg->wq_loc = WQ_LOC_ALL;
	} else if (MATCH("lpbk", "cmpl")) {
		if (!strcmp(value, "cq_usr"))
			cfg->cmpl = CQ_USR;
		else
			cfg->cmpl = SOB;
	} else if (MATCH("lpbk", "data_size_shift")) {
		cfg->data_size_shift = (uint8_t)strtoul(value, NULL, 0);
	} else if (MATCH("lpbk", "wqe_size_shift")) {
		cfg->wqe_size_shift = (uint8_t)strtoul(value, NULL, 0);
	} else if (MATCH("lpbk", "data_cmp")) {
		cfg->data_cmp = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "single_alloc")) {
		cfg->single_alloc = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "cleanup")) {
		cfg->cleanup = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "wait_for_cleanup")) {
		cfg->wait_for_cleanup = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "verbose")) {
		if (!strcmp(value, "0"))
			cfg->verbose = VERBOSE_NONE;
		else if (!strcmp(value, "1"))
			cfg->verbose = VERBOSE_INFO;
		else
			cfg->verbose = VERBOSE_DEBUG;
	} else if (MATCH("lpbk", "db_qman")) {
		cfg->db_qman = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "wtd_en")) {
		cfg->wtd_en = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "eq_poll")) {
		cfg->eq_poll = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "user_db")) {
		cfg->user_db = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "mtu")) {
		cfg->mtu = (uint16_t)strtoul(value, NULL, 0);
	} else if (MATCH("lpbk", "test_opcode")) {
		if (!strcmp(value, "wr-rdv"))
			cfg->test_opcode = TEST_OPCODE_RENDEZVOUS_WRITE;
		else if (!strcmp(value, "rd-rdv"))
			cfg->test_opcode = TEST_OPCODE_RENDEZVOUS_READ;
		else if (!strcmp(value, "fna"))
			cfg->test_opcode = TEST_OPCODE_ATOMIC_FETCH_ADD;
		else
			cfg->test_opcode = TEST_OPCODE_LINEAR_WRITE;
	} else if (MATCH("lpbk", "fna_cmpl")) {
		if (!strcmp(value, "reg"))
			cfg->fna_cmpl = AFA_REG_CMPL;
		else if (!strcmp(value, "cq_usr"))
			cfg->fna_cmpl = AFA_CQ_USR_CMPL;
		else
			cfg->fna_cmpl = AFA_CMPL_MODE_MAX;
	} else if (MATCH("lpbk", "atomic_val_loc")) {
		if (!strcmp(value, "dram"))
			cfg->atomic_val_loc = AFA_OP_DRAM;
		else if (!strcmp(value, "sram"))
			cfg->atomic_val_loc = AFA_OP_SRAM;
		else
			cfg->atomic_val_loc = AFA_OP_MAX;
	} else if (MATCH("lpbk", "fna_thresh")) {
		cfg->fna_thresh = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("lpbk", "encap_type")) {
		if (!strcmp(value, "vxlan"))
			cfg->encap_type = HL_NIC_ENCAP_OVER_UDP;
		else if (!strcmp(value, "gre"))
			cfg->encap_type = HL_NIC_ENCAP_OVER_IPV4;
		else
			cfg->encap_type = HL_NIC_ENCAP_NONE;
	} else if (MATCH("lpbk", "src_ip")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			if (!inet_aton(token, &inp)) {
				printf("ip %s is invalid\n", token);
				return 0;
			}
			/* switch to native endianness */
			cfg->src_ip_addr = be32toh(inp.s_addr);
			token = strtok(NULL, " ");
		}
	} else if (MATCH("lpbk", "reduction_en")) {
		cfg->reduction_en = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "red_dt")) {
		if (!strcmp(value, "int8"))
			cfg->red_dt = HLTESTS_NIC_REDUCTION_INT8;
		else if (!strcmp(value, "bf16"))
			cfg->red_dt = HLTESTS_NIC_REDUCTION_BF16;
		else if (!strcmp(value, "fp32"))
			cfg->red_dt = HLTESTS_NIC_REDUCTION_FP32;
		else if (!strcmp(value, "upscale"))
			cfg->red_dt = HLTESTS_NIC_REDUCTION_UPSCALING_BF16;
		else if (!strcmp(value, "downscale"))
			cfg->red_dt = HLTESTS_NIC_REDUCTION_DOWNSCALING_TO_BF16;
		else if (!strcmp(value, "down_and_up"))
			cfg->red_dt = HLTESTS_NIC_REDUCTION_BF16_DOWN_AND_UP;
		else
			cfg->red_dt = HLTESTS_NIC_REDUCTION_DT_INVALID;
	} else if (MATCH("lpbk", "red_op")) {
		if (!strcmp(value, "add"))
			cfg->red_op = HLTESTS_NIC_REDUCTION_OP_ADDITION;
		else if (!strcmp(value, "sub"))
			cfg->red_op = HLTESTS_NIC_REDUCTION_OP_SUBTRACTION;
		else if (!strcmp(value, "max"))
			cfg->red_op = HLTESTS_NIC_REDUCTION_OP_MAXIMUM;
		else if (!strcmp(value, "min"))
			cfg->red_op = HLTESTS_NIC_REDUCTION_OP_MINIMUM;
		else
			cfg->red_op = HLTESTS_NIC_REDUCTION_OP_INVALID;
	} else if (MATCH("lpbk", "cc_cq")) {
		if (!strcmp(value, "disabled"))
			cfg->cc_cq = CC_MODE_DISABLED;
		else if (!strcmp(value, "swift"))
			cfg->cc_cq = CC_MODE_SWIFT;
		else
			cfg->cc_cq = CC_MODE_BBR;
	} else if (MATCH("lpbk", "qp_loopback")) {
		if (!strcmp(value, "no"))
			cfg->qp_loopback = QP_LPBK_DISABLED;
		else if (!strcmp(value, "yes"))
			cfg->qp_loopback = QP_LPBK_ENABLED;
		else
			cfg->qp_loopback = QP_LPBK_MIXED;
	} else if (MATCH("lpbk", "coll_op")) {
		if (!strcmp(value, "legacy"))
			cfg->coll_op = COLL_OP_MODE_LEGACY;
		else if (!strcmp(value, "multi_lag"))
			cfg->coll_op = COLL_OP_MODE_MULTI_LAG;
		else if (!strcmp(value, "multi_rank"))
			cfg->coll_op = COLL_OP_MODE_MULTI_RANK;
		else if (!strcmp(value, "multi_context"))
			cfg->coll_op = COLL_OP_MODE_MULTI_CONTEXT;
		else
			cfg->coll_op = COLL_OP_DISABLED;
	} else if (MATCH("lpbk", "rdv_type")) {
		if (!strcmp(value, "ms"))
			cfg->rdv_type = HLTESTS_NIC_RDV_MS;
		else if (!strcmp(value, "v-op"))
			cfg->rdv_type = HLTESTS_NIC_RDV_V_OP;
		else
			cfg->rdv_type = HLTESTS_NIC_RDV_SND_RCV;
	} else if (MATCH("lpbk", "coll_op_type")) {
		if (!strcmp(value, "direct"))
			cfg->coll_type = COLL_TYPE_DIRECT;
		else
			cfg->coll_type = COLL_TYPE_CONTEXT;
	} else if (MATCH("lpbk", "compression_en")) {
		cfg->compression_en = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "plain_rdma")) {
		cfg->plain_rdma = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "bp_offs")) {
		cfg->bp_offs = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "assign_qp_priority")) {
		cfg->assign_qp_priority = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "coll_dt")) {
		if (!strcmp(value, "256"))
			cfg->coll_dt = HLTESTS_NIC_COLL_DATA_TYPE_256_BYTE;
		else if (!strcmp(value, "128"))
			cfg->coll_dt = HLTESTS_NIC_COLL_DATA_TYPE_128_BYTE;
		else
			cfg->coll_dt = HLTESTS_NIC_COLL_DATA_TYPE_REDUCTION;
	} else if (MATCH("lpbk", "sack_en")) {
		cfg->sack_en = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "err_inject_percent")) {
		cfg->err_inject_percent = (uint8_t)atoi(value);
	} else if (MATCH("lpbk", "force_wq_with_pmmu")) {
		cfg->force_wq_with_pmmu = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "odp")) {
		cfg->odp = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "single_cmpl")) {
		cfg->single_cmpl = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "rank_axis")) {
		if (!strcmp(value, "x"))
			cfg->axis_rank = COLL_DESC_X_AXIS;
		else if (!strcmp(value, "y"))
			cfg->axis_rank = COLL_DESC_Y_AXIS;
		else
			cfg->axis_rank = COLL_DESC_Z_AXIS;
	} else if (MATCH("lpbk", "number_of_ranks")) {
		cfg->number_of_ranks = (uint8_t)strtoul(value, NULL, 0);
	} else if (MATCH("lpbk", "print_bw")) {
		cfg->print_bw = !strcmp(value, "yes");
	} else if (MATCH("lpbk", "disregard_rank")) {
		cfg->disregard_rank = !strcmp(value, "yes");
	} else {
		return 0; /* unknown section/name, error */
	}

	return 1;
}

static void print_loopback_test_status(void **state, struct hltests_nic_lpbk_cfg *cfg,
				       uint32_t **sent_wqe_cnt,
				       uint32_t **recv_wqe_cnt,
				       struct hltests_nic_in_params *in_params,
				       struct hltests_nic_conn_out *conn_out)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	uint64_t port_mask = tests_state->nic_ports_mask;
	uint32_t max_n_ports, nwq = in_params->nwq, port, qp, total_err_sent_wqes = 0,
	    total_err_recv_wqes = 0, total_used_qps = 0, total_sent_wqes = 0, total_recv_wqes = 0,
	    port_idx;

	max_n_ports = hltests_nic_get_max_num_of_ports(tests_state->fd);

	printf("port\tQP\tsent:%d\treceived:%d\n", nwq, nwq);
	printf("=====================================================\n");
	for (port = 0, port_idx = 0 ; port < max_n_ports ; port++) {
		if (port != cfg->ports[port_idx])
			continue;

		if (!(port_mask & BIT_ULL(port))) {
			printf("test run on disabled port %d\n", port);
			break;
		}
		for (qp = 0 ; qp < cfg->qps_per_port[port_idx] ; qp++) {
			total_sent_wqes += sent_wqe_cnt[port][qp];
			total_recv_wqes += recv_wqe_cnt[port][qp];

			if (sent_wqe_cnt[port][qp] == nwq &&
			    recv_wqe_cnt[port][qp] == nwq)
				continue;

			/* print the connection id for port and qp */
			printf("%d\t%d\t%d\t%d\n",
			       port, conn_out->conn_id[port][qp],
			       sent_wqe_cnt[port][qp],
			       recv_wqe_cnt[port][qp]);

			total_err_sent_wqes += sent_wqe_cnt[port][qp];
			total_err_recv_wqes += recv_wqe_cnt[port][qp];
		}
		total_used_qps += cfg->qps_per_port[port_idx];
		port_idx++;
	}
	printf("=====================================================\n");
	printf("total\t  \t%u\t%u\n", total_err_sent_wqes, total_err_recv_wqes);
	printf("test tried to send %d\n",
	       nwq * total_used_qps);
	printf("actually sent: %u, received: %u\n", total_sent_wqes,
	       total_recv_wqes);
}

static uint32_t coll_op_get_cqe_count(struct hltests_nic_in_params *in_params,
					uint32_t *cq_buf_out_len, uint32_t *num_req_cqe,
					uint32_t *num_res_cqe)
{
	struct hltests_nic_coll_comm_group *comm_group;
	uint32_t n_cqe = 0, i;

	if (in_params->coll_op == COLL_OP_MODE_LEGACY)
		n_cqe = in_params->n_ports;
	else
		for (i = 0 ; i < in_params->max_coll_comm_groups ; i++) {
			comm_group = &in_params->comm_group[i];
			if (comm_group->allocated)
				n_cqe += (comm_group->nodes_per_rank * comm_group->n_ranks);
		}

	if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE) {
		/* Both sender and receiver requester generates CQE.
		 * Only receiver responder generates CQE.
		 */
		*num_req_cqe = n_cqe;
		*num_res_cqe = n_cqe / 2;
	} else if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) {
		/* Only receiver requester and responder generate CQE.
		 * No communication group is allocated for sender.
		 */
		*num_req_cqe = n_cqe;
		*num_res_cqe = n_cqe;
	} else {
		*num_req_cqe = *num_res_cqe = n_cqe;
	}

	/* We use same CQ buffer for both requester and responder completion. */
	*cq_buf_out_len = *num_req_cqe + *num_res_cqe;

	return *cq_buf_out_len;
}

static uint32_t get_port_seed(int fd, struct hltests_nic_in_params *in_params, uint32_t port)
{
	uint32_t max_n_ports = hltests_nic_get_max_num_of_ports(fd), i, port_idx = 0;
	uint64_t port_mask = in_params->port_mask;

	for (i = 0 ; i < max_n_ports ; i++) {
		if (!(port_mask & BIT_ULL(i)))
			continue;

		if (i == port)
			break;
		port_idx++;
	}

	return in_params->seed[port_idx];
}

static VOID hl_nic_cq_process(void **state, void *cfg, struct hlthunk_time_sync_info *end,
				struct hltests_nic_in_params *in_params)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int rc, fd = tests_state->fd;
	struct hltests_nic_conn_out *conn_out = in_params->nic_conn;
	struct hltests_nic_cq *cq = in_params->cq;
	bool stop_cq_loop = false, msg_id_found, is_wr_rdv = false,
		is_rd_rdv = false, is_rdv = false;
	struct hl_nic_cqe *cqe;
	struct hl_nic_cqe *cq_buf_out;
	uint8_t *tag_found, plain_rdma;
	uint32_t max_n_ports = hltests_nic_get_max_num_of_ports(fd),
		 max_n_qps = MAX_NUM_OF_QPS, nwq = in_params->nwq, **tag_cnt, **wqe_cnt, idx,
		 port, qp, num_of_cqes, cqe_indx, cq_buf_out_len, cq_buf_out_size, num_req_cqe = 0,
		 num_res_cqe = 0, req_cqe = 0, res_cqe = 0,
		 max_qps_per_port = in_params->max_qps_per_port, num_of_nics, i, j;

	uint64_t cq_timeout_us, port_mask = in_params->port_mask;
	size_t num_of_tags = nwq * max_n_ports * max_n_qps;

	ALLOC_2D_ARR(tag_cnt, max_n_ports, max_n_qps);
	ALLOC_2D_ARR(wqe_cnt, max_n_ports, max_n_qps);
	tag_found = hlthunk_malloc(num_of_tags);
	assert_non_null(tag_found);

	plain_rdma = (in_params->test == E2E) ? ((struct hltests_nic_e2e_cfg *) cfg)->plain_rdma :
						((struct hltests_nic_lpbk_cfg *) cfg)->plain_rdma;

	num_of_nics = (uint32_t)__builtin_popcountll(in_params->port_mask);

	if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
		is_wr_rdv = true;
	else if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ)
		is_rd_rdv = true;

	is_rdv = is_wr_rdv || is_rd_rdv;

	if (in_params->coll_op) {
		coll_op_get_cqe_count(in_params, &cq_buf_out_len, &num_req_cqe, &num_res_cqe);
		assert_int_not_equal(num_req_cqe, 0);
	} else if (is_wr_rdv) {
		/* For WR-RDV transfers, we get 3 CQEs per WQE transaction.
		 * Also since a pair of qps are consumed for a single transfer,
		 * we divide the num qps by 2
		 */
		cq_buf_out_len = 3 * nwq * (max_qps_per_port >> 1) * max_n_ports;
		num_req_cqe = 2 * nwq * (max_qps_per_port >> 1) * num_of_nics;
		num_res_cqe = nwq * (max_qps_per_port >> 1) * num_of_nics;
	} else if (is_rd_rdv) {
		/* For RD-RDV transfers, we get 2 CQEs per WQE transaction.
		 * Also since a pair of qps are consumed for a single transfer,
		 * we divide the num qps by 2
		 */
		cq_buf_out_len = 2 * nwq * (max_qps_per_port >> 1) * max_n_ports;
		num_req_cqe = nwq * (max_qps_per_port >> 1) * num_of_nics;
		num_res_cqe = num_req_cqe;
	} else {
		/* In case running plain_rdma mode, we should not receive responder
		 * CQE completion. In this case we want to make sure that only the
		 * requester CQEs are counted on in the for loop.
		 * This is only true for Gaudi3; Gaudi & Gaudi2 still get responder CQEs.
		 */
		num_req_cqe = nwq;
		num_res_cqe = (plain_rdma && hltests_is_gaudi3(fd)) ? 0 : num_req_cqe;
		cq_buf_out_len = nwq * max_qps_per_port * max_n_ports;
	}

	cq_buf_out_size = cq_buf_out_len * sizeof(struct hl_nic_cqe);
	cq_buf_out = hlthunk_malloc(cq_buf_out_size);
	assert_non_null(cq_buf_out);

	cq_timeout_us = hltests_is_pldm(fd) ?
			NIC_CQ_TIMEOUT_PLDM_USEC : NIC_CQ_TIMEOUT_USEC;

	/* For E2E or LPBK with single completion tests, only one CQE is required for last WQE */
	if (in_params->test == E2E || in_params->single_cmpl) {
		num_req_cqe = 1;
		/* In case running plain_rdma mode, we should not receive responder
		 * CQE completion. In this case we want to make sure that only the
		 * requester CQEs are counted on in the for loop.
		 * This is only true for Gaudi3; Gaudi & Gaudi2 still get responder CQEs.
		 */
		num_res_cqe = (plain_rdma && hltests_is_gaudi3(fd)) ? 0 : 1;
	}

	memset(tag_found, 0, num_of_tags);

	while (!stop_cq_loop) {
		memset(cq_buf_out, 0, cq_buf_out_size);

		/* In case there is an error event arrived to the EQ we should fail */
		assert_int_equal(in_params->eq->is_error_event, 0);

		rc = hltests_nic_cq_poll(fd, cq, cq_buf_out_len, cq_buf_out, &num_of_cqes,
						cq_timeout_us);

		if (rc && in_params->test == LPBK)
			print_loopback_test_status(state, cfg, wqe_cnt, tag_cnt, in_params,
							conn_out);

		assert_int_equal(rc, 0);

		for (cqe_indx = 0 ; cqe_indx < num_of_cqes ; cqe_indx++) {
			cqe = &cq_buf_out[cqe_indx];
			port = cqe->port;

			if (cqe->type == HL_NIC_CQE_TYPE_REQ) {
				for (qp = 0 ; qp < max_n_qps ; qp++)
					if (conn_out->conn_id[port][qp] == cqe->qp_number)
						break;

				assert_int_not_equal(qp, max_n_qps);

				if (in_params->test == E2E || in_params->single_cmpl) {
					assert_int_equal(cqe->requester.wqe_index, nwq - 1);
				} else {
					assert_int_equal(cqe->requester.wqe_index,
								wqe_cnt[cqe->port][qp]);
				}

				wqe_cnt[cqe->port][qp]++;

				if (in_params->coll_op || is_rdv)
					req_cqe++;

				if (cqe->requester.wqe_index == (nwq - 1))
					hlthunk_get_time_sync_info(fd, end);

				continue;
			}

			/* for HL_NIC_CQE_TYPE_RES */
			if (in_params->test == E2E) {
				/* the RDMA QPs are after the ETH QP so remove it to have a zero
				 * based index
				 */
				qp = cqe->responder.msg_id - get_port_seed(fd, in_params, port) - 1;
				assert_in_range(qp, 0, in_params->max_qps_per_port);
				tag_cnt[port][qp]++;
				continue;
			}

			/* LPBK */
			qp = cqe->responder.msg_id & (next_pow2(in_params->max_qps_per_port) - 1);

			/* Gaudi & Gaudi2 plain_rdma provides responder CQEs, but tags won't match
			 * so skip tag matching.
			 */
			if (in_params->single_cmpl || (plain_rdma && !hltests_is_gaudi3(fd))) {
				tag_cnt[port][qp]++;
				continue;
			}

			msg_id_found = false;

			/* In collective operations, same WQE config is used across all ports/QPs
			 * in the communication group. Hence, skip responder tag match. Instead CQ
			 * completion is checked by counting number of responder/requester CQEs.
			 */
			if (!in_params->coll_op) {
				for (i = 0 ; i < nwq ; i++) {
					idx = (port * max_n_qps + qp) * nwq + i;
					if (tag_found[idx])
						continue;

					/* If SACK is enabled, responder WQEs won't be
					 * in-order. Search for tag in all WQE tag entries
					 */
					if ((in_params->sack_en) &&
						(in_params->tag[idx] != cqe->responder.msg_id))
						continue;

					if (!in_params->sack_en)
						assert_int_equal(in_params->tag[idx],
								cqe->responder.msg_id);

					tag_found[idx] = true;
					tag_cnt[port][qp]++;
					msg_id_found = true;
					break;
				}

				if (!msg_id_found) {
					printf(
						"Responder msg id 0x%x not found for port: %d, QP: %d\n",
						cqe->responder.msg_id, port, qp);
					assert_true(msg_id_found);
				}
			}

			if (in_params->coll_op || is_rdv)
				res_cqe++;
		}

		stop_cq_loop = true;
		if (is_rdv || in_params->coll_op) {
			if ((req_cqe != num_req_cqe) || (res_cqe != num_res_cqe))
				stop_cq_loop = false;
		} else {
			for (i = 0 ; (i < max_n_ports) ; i++) {
				if (!(port_mask & BIT_ULL(i)))
					continue;

				for (j = 0 ; j < in_params->qps_per_port[i] ; j++) {
					if (tag_cnt[i][j] != num_res_cqe ||
						wqe_cnt[i][j] != num_req_cqe) {
						stop_cq_loop = false;
						break;
					}
				}

				if (!stop_cq_loop)
					break;
			}
		}
	}

	FREE_2D_ARR(tag_cnt, max_n_ports);
	FREE_2D_ARR(wqe_cnt, max_n_ports);
	hlthunk_free(tag_found);
	hlthunk_free(cq_buf_out);

	END_TEST;
}

static int coll_op_get_sob_val(struct hltests_nic_in_params *in_params, bool is_local)
{
	struct hltests_nic_coll_comm_group *comm_group;
	int sob_val = 0, i;

	/* Linear write: Each node updates local/remote SOB. Each rank transfer equally
	 * updates local/remote SOB. Local SOB is updated for ACKs and remote SOB is updated
	 * for write data transfer.
	 */
	for (i = 0 ; i < in_params->max_coll_comm_groups ; i++) {
		comm_group = &in_params->comm_group[i];
		if (comm_group->allocated)
			sob_val += (int)(comm_group->nodes_per_rank * comm_group->n_ranks);
	}

	/* Rendezvous write:
	 * SW-114271: By configuring QPC_RX_WQE_CT_MASK_DEFAULT to 0x3 we change the expected value
	 * of the SOB to be 2 times than sender (local) side since now ACK for RDV receiver message
	 * is also increment the SOB (in addition to the regular sender data).
	 */
	if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE && is_local)
		sob_val /= 2;

	/* Rendezvous read:
	 * Sender: No local SOB is updated. No doorbell is pushed since PI
	 * is updated by receiver. No communication group is allocated.
	 * Receiver: Remote SOB is updated for ACK received for sender WQE update
	 * and actual read data sent by sender.
	 */
	if (!is_local && in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ)
		sob_val *= 2;
	else if (is_local && in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ)
		sob_val = 0;

	return sob_val;
}

static VOID hl_nic_process_sob(void **state, void *cfg, struct hlthunk_time_sync_info *end,
				struct hltests_nic_in_params *in_params)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd, sob_val, rc;
	uint32_t max_n_ports = hltests_nic_get_max_num_of_ports(fd), nwq = in_params->nwq,
			qps_per_port, iterations_db, i, nic_idx, port, sobs_per_port;
	uint64_t first_sob;
	bool is_wr_rdv = false, is_rd_rdv = false, is_rdv = false, is_fna = false, is_coll_op;

	if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
		is_wr_rdv = true;
	else if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ)
		is_rd_rdv = true;
	else if (in_params->test_opcode == TEST_OPCODE_ATOMIC_FETCH_ADD)
		is_fna = true;

	is_rdv = is_wr_rdv || is_rd_rdv;
	is_coll_op = in_params->coll_op == COLL_OP_MODE_MULTI_LAG ||
			in_params->coll_op == COLL_OP_MODE_MULTI_RANK ||
			in_params->coll_op == COLL_OP_MODE_MULTI_CONTEXT;

	first_sob = hltests_get_first_avail_sob(fd);
	/* We always work in 4 quarter cycle DB, when working without user_db, we will work with
	 * single SOB per port and each quarter will signal to that SOB. When using user_db,
	 * we will use SOBs as the amount of DB_ITER_PER_CYCLE. Each SOB will get completion from
	 * the corresponding iteration.
	 * Nevertheless, patcher mode uses user_db we don't apply on it the multiple SOBs per port.
	 */
	if (in_params->user_db && !in_params->coll_op) {
		sobs_per_port = DB_ITER_PER_CYCLE;
		iterations_db = in_params->iterations;
	} else {
		sobs_per_port = 1;
		iterations_db = in_params->iterations * DB_ITER_PER_CYCLE;
	}

	for (nic_idx = 0, port = 0 ; port < max_n_ports ; port++) {
		if (!(in_params->port_mask & BIT_ULL(port)) || !in_params->qps_per_port[port])
			continue;

		for (i = 0 ; i < sobs_per_port ; i++) {
			qps_per_port = in_params->qps_per_port[port];

			/* For each transfer type, we have different no. of SOBs.
			 * Wait on the correct SOB num.
			 * WR-RDV: Remote SOB gets updated when we receive ACK for the RDV WQE that
			 *	   is sent from receive side to send side.
			 *	   Remote SOB also gets incremented when the send side sends the
			 *	   LINEAR_WRITE transaction.
			 *	   Local SOB gets updated when Send side receives ack for the
			 *	   LINEAR_WRITE transaction.
			 * RD-RDV: Only Remote SOB gets updated as there is no wqe on the send
			 *	   side.
			 */
			if (!is_rd_rdv) {
				if (in_params->coll_op)
					sob_val = coll_op_get_sob_val(in_params, true);
				else if (is_wr_rdv)
					sob_val = (int)(nwq * (qps_per_port >> 1) / sobs_per_port);
				else
					sob_val = (int)(qps_per_port * iterations_db);

				rc = hltests_nic_wait_on_sob(fd,
							     (uint32_t)(first_sob + LOCAL_SOB_ID +
							     (nic_idx * sobs_per_port) + i),
							     tests_state, sob_val, in_params->eq);
				assert_int_equal(rc, 0);
			}

			/* For collective operations all ports signal completion
			 * over single local SOB.
			 */
			if (is_coll_op)
				break;
		}

		nic_idx++;

		if (is_coll_op)
			break;
	}

	hlthunk_get_time_sync_info(fd, end);

	for (nic_idx = 0, port = 0 ; port < max_n_ports ; port++) {
		if (!(in_params->port_mask & BIT_ULL(port)) || !in_params->qps_per_port[port])
			continue;

		for (i = 0 ; i < sobs_per_port ; i++) {
			qps_per_port = in_params->qps_per_port[port];

			if (in_params->coll_op)
				sob_val = coll_op_get_sob_val(in_params, false);

			else if (is_rdv)
				/* In RDV we keep this write style (>> 1) * 2 for SOB values, as in
				 * other places in code. In RDV we send DB only on half of the QPs,
				 * but we receive a double of CMPL signals for both sides.
				 */
				sob_val = (int)(nwq * (qps_per_port >> 1) * 2 / sobs_per_port);
			else if (is_fna && !i && in_params->fna_cmpl == AFA_REG_CMPL)
				/* When working with user_db on F&A where we have sobs_per_port > 1,
				 * we will get on the first SOBs of each port an additional
				 * completions. This is due to the F&A mechanism were we explicitly
				 * push DB for the first wqe and wait to receive a CMPL on it.
				 */
				sob_val = (int)
					(qps_per_port * (iterations_db + in_params->iterations));
			else
				sob_val = (int)(qps_per_port * iterations_db);

			rc = hltests_nic_wait_on_sob(fd, (uint32_t)
				(first_sob + REMOTE_SOB_ID + nic_idx * sobs_per_port + i),
				tests_state, sob_val, in_params->eq);
			assert_int_equal(rc, 0);

			/* For collective operations all ports signal completion over
			 * single remote SOB.
			 */
			if (is_coll_op)
				break;
		}

		nic_idx++;

		if (is_coll_op)
			break;
	}

	END_TEST;
}

static int nic_pre_setup_contexts(int fd, void *cfg, struct hltests_nic_contexts *nic_ctx,
					struct hltests_nic_in_params *in_params)
{
	switch (in_params->test) {
	case LPBK:
		nic_pre_setup_ctx_lpbk(fd, cfg, nic_ctx, in_params);
		break;
	case E2E:
		nic_pre_setup_ctx_e2e(fd, cfg, nic_ctx);
		break;
	default:
		printf("Unknown test: %d\n", in_params->test);
		return -EINVAL;
	}
	return 0;
}

static int nic_setup_contexts(void *cfg, struct hltests_state *tests_state,
				struct hltests_nic_conn_out *qp_conn,
				struct hltests_nic_contexts *nic_ctx,
				struct hltests_nic_in_params *in_params)
{
	int rc, fd = tests_state->fd;

	switch (in_params->test) {
	case LPBK:
		rc = nic_setup_ctx_lpbk(fd, cfg, tests_state, qp_conn, nic_ctx, in_params);
		break;
	case E2E:
		rc = nic_setup_ctx_e2e(fd, cfg, tests_state, qp_conn, nic_ctx, in_params);
		break;
	default:
		printf("Unknown test: %d\n", in_params->test);
		rc = -EINVAL;
	}
	return rc;
}

static void *get_swqe(int fd, void *swq, uint32_t offset)
{
	return hltests_nic_get_swqe(fd, swq, offset);
}

static void *get_rwqe(int fd, void *rwq, uint32_t offset)
{
	return hltests_nic_get_rwqe(fd, rwq, offset);
}

static void get_wqes(int fd, uint32_t port, uint32_t conn_id, uint32_t wq_nwq, uint32_t wqe_idx,
		     struct hltests_nic_in_params *in_params, void **swqe, void **rwqe)
{
	struct hltests_nic_conn_out *nic_conn;
	uint32_t offset;

	conn_id -= hltests_nic_get_wq_offset(fd, (int)port, conn_id);

	if (!in_params->wtd_en && !in_params->coll_op) {
		nic_conn = in_params->nic_conn;
		*swqe = get_swqe(fd, nic_conn->swq_buf[port][conn_id], wqe_idx);
		*rwqe = get_rwqe(fd, nic_conn->rwq_buf[port][conn_id], wqe_idx);
	} else {
		offset = wq_nwq * conn_id + wqe_idx;
		*swqe = get_swqe(fd, in_params->swqe_arr[port], offset);
		*rwqe = get_rwqe(fd, in_params->rwqe_arr[port], offset);
	}
}

static struct hltests_nic_db_fifo_data **alloc_user_db_fifo_ids(int fd, uint64_t port_mask,
								uint32_t n_db_fifos)
{
	struct hltests_nic_db_fifo_data **db_fifos;
	uint32_t port, max_n_ports, i;
	int rc;

	max_n_ports = hltests_nic_get_max_num_of_ports(fd);
	ALLOC_2D_ARR_RET_PTR(db_fifos, max_n_ports, n_db_fifos);

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		for (i = 0 ; i < n_db_fifos ; i++) {
			rc = hlthunk_nic_alloc_user_db_fifo(fd,
						port, &db_fifos[port][i].id);
			assert_int_equal_ret_ptr(rc, 0);
		}
	}

	return db_fifos;
}

static VOID config_user_db_fifos(int fd, uint64_t port_mask,
				struct hltests_nic_db_fifo_data **db_fifos, uint32_t n_db_fifos,
				enum hl_nic_db_fifo_type mode)
{
	struct hltests_nic_db_fifo_data *db_fifo;
	struct hlthunk_nic_user_db_fifo_set_out out;
	struct hlthunk_nic_user_db_fifo_set_in in;
	uint64_t sob_lbw_base_offset = 0;
	uint32_t port, max_n_ports, sob_id_base = 0, i;
	int rc;
	bool is_coll_op;

	is_coll_op = (mode == HL_NIC_DB_FIFO_TYPE_COLL_OPS_SHORT) ||
			(mode == HL_NIC_DB_FIFO_TYPE_COLL_OPS_LONG) ||
			(mode == HL_NIC_DB_FIFO_TYPE_COLL_DIR_OPS_SHORT) ||
			(mode == HL_NIC_DB_FIFO_TYPE_COLL_DIR_OPS_LONG);

	if (is_coll_op) {
		sob_lbw_base_offset = hltests_get_sob_base_addr(fd) - hltests_get_lbw_base_addr(fd);
		sob_id_base = DB_FIFO_SOB_ID + hltests_get_first_avail_sob(fd);
	}

	memset(&out, 0, sizeof(out));
	memset(&in, 0, sizeof(in));

	max_n_ports = hltests_nic_get_max_num_of_ports(fd);

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		for (i = 0 ; i < n_db_fifos ; i++) {
			db_fifo = &db_fifos[port][i];

			in.port = port;
			in.id = db_fifo->id;
			in.mode = mode;

			/* Per SW policy, collective operations are to be enabled
			 * with DB fifo LBW(SOB) CI and DUP interface.
			 */
			if (is_coll_op) {
				db_fifo->sob_id = sob_id_base + port;
				db_fifo->is_dup_enabled = true;

				in.base_sob_addr = (uint32_t)
					(sob_lbw_base_offset + (db_fifo->sob_id * 4));
				in.num_sobs = db_fifo->num_sobs = 1;
			}

			rc = hlthunk_nic_user_db_fifo_set(fd, &in, &out);
			assert_int_equal(rc, 0);

			db_fifo->ci_handle = out.ci_handle;
			db_fifo->regs_handle = out.regs_handle;
			db_fifo->regs_offset = out.regs_offset;
			db_fifo->fifo_size = out.fifo_size;
			db_fifo->fifo_bp_thresh = out.fifo_bp_thresh;
			db_fifo->pi = 0;
		}
	}

	END_TEST;
}

static VOID mmap_user_db_fifos(int fd, uint64_t port_mask,
				struct hltests_nic_db_fifo_data **db_fifos, uint32_t n_db_fifos)
{
	struct hltests_nic_db_fifo_data *db_fifo;
	uint32_t port, max_n_ports, i;

	max_n_ports = hltests_nic_get_max_num_of_ports(fd);

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		for (i = 0 ; i < n_db_fifos ; i++) {
			db_fifo = &db_fifos[port][i];
			/* DB_FIFOs descriptors on simulator are written directly to UMR registers
			 * as there is no MMIO on simulator. Therefore we should not mmap it
			 */
			if (!hltests_is_simulator(fd) && !db_fifo->is_dup_enabled) {
				db_fifo->regs_cpu_ptr = hltests_mmap(fd, SZ_4K,
								(off_t)db_fifo->regs_handle);
				assert_ptr_not_equal(db_fifo->regs_cpu_ptr, MAP_FAILED);
			}

			/* HW allows usage of either SOB(LBW) or memory(HBW) CI */
			if (!db_fifo->num_sobs) {
				db_fifo->ci_cpu_ptr = hltests_mmap(fd, SZ_4K,
								(off_t)db_fifo->ci_handle);
				assert_ptr_not_equal(db_fifo->ci_cpu_ptr, MAP_FAILED);
			}
		}
	}

	END_TEST;
}

static enum hbldv_usr_fifo_type
hl_to_ib_db_mode(enum hl_nic_db_fifo_type mode)
{
	switch (mode) {
	case HL_NIC_DB_FIFO_TYPE_DB:
		return HBLDV_USR_FIFO_TYPE_DB;
	case HL_NIC_DB_FIFO_TYPE_CC:
		return HBLDV_USR_FIFO_TYPE_CC;
	case HL_NIC_DB_FIFO_TYPE_COLL_OPS_SHORT:
		return HBLDV_USR_FIFO_TYPE_COLL_OPS_SHORT;
	case HL_NIC_DB_FIFO_TYPE_COLL_OPS_LONG:
		return HBLDV_USR_FIFO_TYPE_COLL_OPS_LONG;
	case HL_NIC_DB_FIFO_TYPE_DWQ_LIN:
		return HBLDV_USR_FIFO_TYPE_DWQ_LIN;
	case HL_NIC_DB_FIFO_TYPE_DWQ_MS:
		return HBLDV_USR_FIFO_TYPE_DWQ_MS;
	case HL_NIC_DB_FIFO_TYPE_COLL_DIR_OPS_SHORT:
		return HBLDV_USR_FIFO_TYPE_COLL_DIR_OPS_SHORT;
	case HL_NIC_DB_FIFO_TYPE_COLL_DIR_OPS_LONG:
		return HBLDV_USR_FIFO_TYPE_COLL_DIR_OPS_LONG;
	default:
		return HBLDV_USR_FIFO_TYPE_DB;
	}
}

static struct hltests_nic_db_fifo_data
**ibdev_create_user_db_fifos(int fd, struct hltests_nic_in_params *in_params, uint32_t n_db_fifos,
				enum hl_nic_db_fifo_type mode)
{
	struct hltests_nic_ib_in_params *ib_in_params = in_params->ib_in_params;
	struct hltests_nic_db_fifo_data **db_fifos, *db_fifo;
	struct hbldv_usr_fifo *hbldv_usr_fifo;
	enum hbldv_usr_fifo_type ib_db_mode;
	struct hbldv_usr_fifo_attr attr;
	uint32_t port, max_n_ports, sob_id_base = 0, i;
	uint64_t port_mask, sob_lbw_base_offset = 0;
	bool is_coll_op;

	ib_db_mode = hl_to_ib_db_mode(mode);

	port_mask = (ib_db_mode == HBLDV_USR_FIFO_TYPE_CC) ?
			in_params->cc_port_mask : in_params->port_mask;

	is_coll_op = (ib_db_mode == HBLDV_USR_FIFO_TYPE_COLL_OPS_SHORT) ||
			(ib_db_mode == HBLDV_USR_FIFO_TYPE_COLL_OPS_LONG) ||
			(ib_db_mode == HBLDV_USR_FIFO_TYPE_COLL_DIR_OPS_SHORT) ||
			(ib_db_mode == HBLDV_USR_FIFO_TYPE_COLL_DIR_OPS_LONG);

	if (is_coll_op) {
		sob_lbw_base_offset = hltests_get_sob_base_addr(fd) - hltests_get_lbw_base_addr(fd);
		sob_id_base = DB_FIFO_SOB_ID + hltests_get_first_avail_sob(fd);
	}

	max_n_ports = hltests_nic_get_max_num_of_ports(fd);
	ALLOC_2D_ARR_RET_PTR(db_fifos, max_n_ports, n_db_fifos);

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		for (i = 0 ; i < n_db_fifos ; i++) {
			db_fifo = &db_fifos[port][i];
			memset(&attr, 0, sizeof(attr));
			attr.port_num = hltests_nic_to_ibdev_port_num(fd, port);
			attr.usr_fifo_type = ib_db_mode;

			/* Per SW policy, collective operations are to be enabled with DB fifo
			 * LBW(SOB) CI and DUP interface.
			 */
			if (is_coll_op) {
				db_fifo->sob_id = sob_id_base + port;
				db_fifo->is_dup_enabled = true;

				attr.base_sob_addr = (uint32_t)(sob_lbw_base_offset +
							(db_fifo->sob_id * 4));
				attr.num_sobs = db_fifo->num_sobs = 1;
			}

			hbldv_usr_fifo = hbldv_create_usr_fifo(ib_in_params->ibctx, &attr);
			assert_non_null_ret_ptr(hbldv_usr_fifo);

			db_fifo->hbldv_usr_fifo = hbldv_usr_fifo;
			db_fifo->id = hbldv_usr_fifo->usr_fifo_num;
			db_fifo->fifo_size = hbldv_usr_fifo->size;
			db_fifo->fifo_bp_thresh = hbldv_usr_fifo->bp_thresh;
			db_fifo->regs_offset = hbldv_usr_fifo->regs_offset;
			db_fifo->ci_cpu_ptr = hbldv_usr_fifo->ci_cpu_addr;
			db_fifo->regs_cpu_ptr = hbldv_usr_fifo->regs_cpu_addr;
			db_fifo->pi = 0;
		}
	}

	return db_fifos;
}

static int ibdev_destroy_user_db_fifos(int fd, struct hltests_nic_in_params *in_params,
				uint64_t port_mask, struct hltests_nic_db_fifo_data **db_fifos,
				uint32_t n_db_fifos)
{
	uint32_t max_n_ports, i, port;
	int rc;

	max_n_ports = hltests_nic_get_max_num_of_ports(fd);

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		for (i = 0 ; i < n_db_fifos ; i++) {
			rc = hbldv_destroy_usr_fifo(db_fifos[port][i].hbldv_usr_fifo);
			assert_int_equal(rc, 0);
		}
	}

	FREE_2D_ARR(db_fifos, max_n_ports);

	return 0;
}

static struct hltests_nic_db_fifo_data
**create_user_db_fifo_ids(int fd, struct hltests_nic_in_params *in_params, uint32_t n_db_fifos,
				enum hl_nic_db_fifo_type mode)
{
	struct hltests_nic_db_fifo_data **db_fifos;
	uint64_t port_mask;

	if (hltests_nic_is_ibdev(fd))
		return ibdev_create_user_db_fifos(fd, in_params, n_db_fifos, mode);

	port_mask = (mode == HL_NIC_DB_FIFO_TYPE_CC) ?
			in_params->cc_port_mask : in_params->port_mask;

	db_fifos = alloc_user_db_fifo_ids(fd, port_mask, n_db_fifos);
	config_user_db_fifos(fd, port_mask, db_fifos, n_db_fifos, mode);
	mmap_user_db_fifos(fd, port_mask, db_fifos, n_db_fifos);

	return db_fifos;
}

static int destroy_user_db_fifos(int fd, struct hltests_nic_in_params *in_params,
				uint64_t port_mask, struct hltests_nic_db_fifo_data **db_fifos,
				uint32_t n_db_fifos)
{
	struct hltests_nic_db_fifo_data *db_fifo;
	uint32_t port, max_n_ports, i;
	int rc;

	if (hltests_nic_is_ibdev(fd))
		return ibdev_destroy_user_db_fifos(fd, in_params, port_mask, db_fifos, n_db_fifos);

	max_n_ports = hltests_nic_get_max_num_of_ports(fd);

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		for (i = 0 ; i < n_db_fifos ; i++) {
			db_fifo = &db_fifos[port][i];

			if (!db_fifo->num_sobs) {
				rc = hltests_munmap(fd, db_fifo->ci_cpu_ptr, SZ_4K);
				assert_int_equal(rc, 0);
			}

			if (!hltests_is_simulator(fd) && !db_fifo->is_dup_enabled) {
				rc = hltests_munmap(fd, db_fifo->regs_cpu_ptr, SZ_4K);
				assert_int_equal(rc, 0);
			}

			rc = hlthunk_nic_user_db_fifo_unset(fd, port, db_fifo->id);
			assert_int_equal(rc, 0);
		}
	}

	FREE_2D_ARR(db_fifos, max_n_ports);

	return 0;
}

/* Read given qp's completion register. We have up to 8 addresses that
 * we can provide to the HW to use as completion for the FnA operations.
 * Currently due to HW limitation, we support 2 addresses. This function
 * returns mmHD0_SYNC_MNGR_OBJS_MON_PAY_ADDRL_1_0 for the even QPs and
 * mmHD0_SYNC_MNGR_OBJS_MON_PAY_ADDRL_1_1 for the odd ones.
 *
 * @param tests_state
 * @param qp current QP.
 * @param blk DCOREX base.
 * @return uint32_t Completion register value.
 */
static uint32_t read_fna_mem_cmpl_reg(struct hltests_state *tests_state, uint32_t qp, uint8_t *blk)
{
	int fd = tests_state->fd;
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	return hdev->asic_funcs->nic_funcs->read_mem_cmpl(tests_state->fd, FNA_MON_ID +
							(qp % AFA_MAX_NUM_OF_CMPL_REGS), blk);
}

static void modify_wqe_size(int fd, uint32_t port, uint32_t qp,
				struct hltests_nic_user_fifo_params *fifo_params)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	uint32_t i, nwqs;
	void *swqe, *rwqe;

	nwqs = fifo_params->nwqs;

	for (i = 1 ; i < nwqs ; i++) {
		get_wqes(fd, port, qp, nwqs, i, fifo_params->test_params, &swqe, &rwqe);
		hdev->asic_funcs->nic_funcs->ovrd_wqes_data_size(swqe);
	}
}

/**
 * 1. Trigger fetch and add operation by sending the first WQE of the QP.
 * 2. Wait on SOB for the operation to complete.
 * 3. compare the counter value with the fna_thersh input parameter.
 *
 * This function manipulates a 2D array in size of MAX_PORTS * MAX_QPS.
 * If the value was below the threshold, mark this ports QP as
 * a send QP in the corresponding [port][qp] index of the array.
 * else, i.e. value returned by the FnA operation is above the
 * threshold, modify the rest of this QP WQEs to have data size 0.
 */
static VOID trigger_fna(struct hltests_nic_user_fifo_params *fifo_params, int fd, uint32_t port,
				uint32_t db_fifo_index, uint32_t db_fifo_entry_size)
{
	struct hltests_state *tests_state = fifo_params->tests_state;
	struct hltests_nic_db_fifo_packet db_fifo_packet;
	struct hltests_nic_db_fifo_data *db_fifo;
	struct hl_nic_cqe *cq_buf_out, *cqe;
	struct hltests_nic_cq *cq = fifo_params->test_params->cq;
	uint32_t qp, qp_id, pi_granularity, cmp_res = 0, prev = 0, retries, cq_buf_out_len,
		cq_buf_out_size, num_of_cqes, cqe_idx;
	uint8_t fna_cmpl = fifo_params->test_params->fna_cmpl;
	int rc;
	uint64_t cq_timeout_us;
	bool stop_cq_loop = false;

	/* There are 2 completions per QP.
	 * Reception of WQE on the responder
	 * Reception of ACK at the requestor
	 */
	cq_buf_out_len = 2;
	cq_buf_out_size = cq_buf_out_len * sizeof(struct hl_nic_cqe);
	cq_buf_out = hlthunk_malloc(cq_buf_out_size);
	assert_non_null(cq_buf_out);

	cq_timeout_us = hltests_is_pldm(fd) ?
			NIC_CQ_TIMEOUT_PLDM_USEC : NIC_CQ_TIMEOUT_USEC;

	for (qp = 0 ; qp < fifo_params->qps_per_port[port] ; qp++) {
		qp_id = fifo_params->qp_ids[port][qp];
		retries = AFA_READ_CMPL_MEM_RETRIES;
		if (hltests_is_pldm(fd))
			retries = AFA_READ_CMPL_MEM_RETRIES * 1000;

		if (fifo_params->test_params->fna_cmpl == AFA_REG_CMPL)
			prev = read_fna_mem_cmpl_reg(tests_state, qp_id,
						fifo_params->cmpl_mem_hdl);

		/* Create DB packet with PI = 1 which will send the first WQE
		 * in the QP. This WQE was configured to be a FnA WQE
		 */
		rc = hltests_nic_create_db_packet(&db_fifo_packet, 1, qp_id, port);
		assert_int_equal(rc, 0);

		db_fifo = &fifo_params->fifos[port][db_fifo_index];
		pi_granularity = db_fifo_packet.size / db_fifo_entry_size;

		/* Wait till there is enough free space available in the user
		 * db fifo before pushing new entry
		 */
		hltests_nic_user_db_wait_entry_consume(db_fifo, db_fifo_entry_size, pi_granularity,
							0);

		hltests_nic_write_descriptor_to_db_fifo(tests_state, db_fifo, &db_fifo_packet,
							port, false);

		if (fna_cmpl == AFA_REG_CMPL) {
			do
				cmp_res = read_fna_mem_cmpl_reg(fifo_params->tests_state, qp_id,
							fifo_params->cmpl_mem_hdl);
			while (--retries && (cmp_res <= prev) &&
				!((prev - cmp_res) == AFA_CTR_VAL_WRAP_VAL));

			if (!retries && (cmp_res <= prev)) {
				printf("Timeout reading from SM lbw register\n");
				assert_int_not_equal(retries, 0);
			}
		} else if (fna_cmpl == AFA_CQ_USR_CMPL) {
			stop_cq_loop = false;
			while (!stop_cq_loop) {
				rc = hltests_nic_cq_poll(fd, cq, cq_buf_out_len, cq_buf_out,
							&num_of_cqes,
							cq_timeout_us);
				assert_int_equal(rc, 0);

				for (cqe_idx = 0 ; cqe_idx < num_of_cqes ; cqe_idx++) {
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
		}

		if ((cmp_res & 0xff) > fifo_params->test_params->fna_thresh)
			/* QP above the threshold, should send its WQE with data size 0 */
			modify_wqe_size(fd, port, qp_id, fifo_params);
		else
			/* QP below the threshold, should be marked as a QP that sends its data */
			fifo_params->test_params->fna_qp_send_data[port][qp] = 1;

		db_fifo->pi = (db_fifo->pi + pi_granularity) & (DB_FIFO_CI_FREE_RUN - 1);

		free(db_fifo_packet.packet);
	}

	hlthunk_free(cq_buf_out);

	END_TEST;
}

static VOID bp_offs_wait_for_bp(struct hltests_nic_user_fifo_params *fifo_params,
				uint32_t  bp_offs_base_id, uint32_t num_bp_offs, uint8_t priority)
{
	uint32_t j, mask_bp_offs_triggered = 0, mask_bp_offs_done = 0,
			bp_offs_triggered;
	uint8_t priority_override;
	double timeout_secs;
	struct timespec base, now;
	int fd = fifo_params->tests_state->fd;
	struct hltests_device *hdev = get_hdev_from_fd(fd);

	timeout_secs = (uint64_t) (hltests_is_pldm(fd) ?	WAIT_FOR_BP_TIMEOUT_PLDM_SEC :
							WAIT_FOR_BP_TIMEOUT_SEC);

	/* W/A for HW BUG. We use only prio #0 for PFC related priorities. The real priority is
	 * still used for schedule queues.
	 */
	priority_override = hltests_is_gaudi2(fd) ? 0 : priority;

	clock_gettime(CLOCK_MONOTONIC_RAW, &base);
	clock_gettime(CLOCK_MONOTONIC_RAW, &now);
	while (get_timediff_sec(&base, &now) < timeout_secs) {
		for (j = 0 ; j < num_bp_offs; j++) {
			bp_offs_triggered = hdev->asic_funcs->nic_funcs->read_mem_cmpl(fd,
					BP_MON_ID + bp_offs_base_id + j, fifo_params->cmpl_mem_hdl);

			if (bp_offs_triggered & BIT(priority_override))
				mask_bp_offs_triggered |= u32_safe(BIT(j));
			else if (mask_bp_offs_triggered & BIT(j))
				mask_bp_offs_done |= u32_safe(BIT(j));
		}

		if (mask_bp_offs_done == BIT(num_bp_offs) - 1)
			break;

		usleep(100);
		clock_gettime(CLOCK_MONOTONIC_RAW, &now);
	}
	assert_int_equal(mask_bp_offs_done, BIT(num_bp_offs) - 1);

	END_TEST;
}

static int trigger_bp(struct hltests_nic_user_fifo_params *fifo_params, uint32_t port)
{
	uint32_t qp_id, pi_granularity, fifo_entries_amount, num_bp_offs = 0,
			extra_guard = 0, db_fifo_entry_size = 0, qps_per_port, hw_wq_pi,
			bp_offs_base_id = 0, qp, db_fifo_index, i, iterations_db;
	int rc, fd = fifo_params->tests_state->fd;
	struct hltests_state *tests_state = fifo_params->tests_state;
	struct hltests_nic_in_params *test_params = fifo_params->test_params;
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hltests_nic_asic_funcs *nic_funcs = hdev->asic_funcs->nic_funcs;
	struct hltests_nic_db_fifo_packet db_fifo_packet;
	struct hltests_nic_db_fifo_data *db_fifo;
	uint16_t cmpl;

	iterations_db = fifo_params->test_params->iterations;
	db_fifo_entry_size = nic_funcs->get_db_fifo_entry_size();
	cmpl = fifo_params->test_params->cmpl;
	db_fifo_index = 0;

	nic_funcs->fill_bp_offs_params(fd, port, &bp_offs_base_id, &num_bp_offs);

	for (i = 0 ; i < iterations_db ; i++) {
		hw_wq_pi = nic_funcs->get_hw_wq_pi((uint32_t)
						(test_params->data_size / test_params->wqe_size),
						test_params->nwq, i, cmpl, true);
		qps_per_port = test_params->qps_per_port[port];

		for (qp = 0 ; qp < qps_per_port ; qp++) {
			/* In case of RD-RDV, since there are no wqes for send ports, don't post
			 * doorbell on odd ports as they are the send ports.
			 */
			if ((fifo_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) && (qp & 1))
				continue;

			qp_id = fifo_params->qp_ids[port][qp];

			rc = hltests_nic_create_db_packet(&db_fifo_packet, hw_wq_pi, qp_id, port);
			assert_int_equal(rc, 0);

			db_fifo = &fifo_params->fifos[port][db_fifo_index];
			pi_granularity = db_fifo_packet.size / db_fifo_entry_size;

			/* Wait till there is enough free space available in the
			 * user db fifo before pushing new entry
			 */
			hltests_nic_user_db_wait_entry_consume(db_fifo, db_fifo_entry_size,
								pi_granularity, extra_guard);

			hltests_nic_write_descriptor_to_db_fifo(tests_state, db_fifo,
								&db_fifo_packet, port, false);

			bp_offs_wait_for_bp(fifo_params, bp_offs_base_id, num_bp_offs,
						fifo_params->nic_ctx->req_ctx[port][qp].priority);

			/* Update FIFO pi */
			if (hltests_is_gaudi2(fd)) {
				fifo_entries_amount = db_fifo->fifo_size / db_fifo_entry_size;
							db_fifo->pi = (db_fifo->pi + pi_granularity)
								& (fifo_entries_amount - 1);
			}
			/* In Gaudi3 the DB FIFO CI is a free run counter of 11 bits */
			else
				db_fifo->pi = (db_fifo->pi + pi_granularity) &
						(DB_FIFO_CI_FREE_RUN - 1);

			free(db_fifo_packet.packet);
		}
	}
	return 0;
}

static VOID trigger_user_db(struct hltests_nic_user_fifo_params *fifo_params)
{
	uint32_t qp_id, port, max_n_ports, pi_granularity, fifo_entries_amount, extra_guard = 0,
		 db_fifo_entry_size = 0, qps_per_port, hw_wq_pi, nic_idx, db_fifo_index, qp, i,
		 iterations_db;
	int rc, fd = fifo_params->tests_state->fd;
	struct hltests_state *tests_state = fifo_params->tests_state;
	struct hltests_nic_in_params *test_params = fifo_params->test_params;
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hltests_nic_asic_funcs *nic_funcs = hdev->asic_funcs->nic_funcs;
	struct hltests_nic_db_fifo_packet db_fifo_packet;
	uint64_t sob_base_addr = 0;
	struct hltests_nic_db_fifo_data *db_fifo;
	uint16_t first_sob = 0, cmpl;
	bool is_wr_rdv = false, is_rd_rdv = false, is_rdv, port_has_qp;
	uint32_t nwqs = (uint32_t)(test_params->data_size / test_params->wqe_size);

	iterations_db = fifo_params->test_params->iterations;
	max_n_ports = hltests_nic_get_max_num_of_ports(fd);
	db_fifo_entry_size = nic_funcs->get_db_fifo_entry_size();
	cmpl = fifo_params->test_params->cmpl;
	db_fifo_index = 0;

	if (test_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
		is_wr_rdv = true;
	else if (test_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ)
		is_rd_rdv = true;

	is_rdv = is_wr_rdv || is_rd_rdv;

	/* In gaudi2 there was a HW bug where the CI lag by 1 entry, hence total delta PI-CI
	 * should be 2.
	 */
	if (hltests_is_gaudi2(fd))
		extra_guard = 1;

	if (cmpl == SOB && !is_rdv) {
		sob_base_addr = hltests_get_sob_base_addr(fd);
		first_sob = hltests_get_first_avail_sob(fd);
		if (!test_params->bp_offs)
			iterations_db = test_params->iterations * DB_ITER_PER_CYCLE;
	}

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(fifo_params->port_mask & BIT_ULL(port)))
			continue;

		/* In FnA we trigger a one WQE iteration for all the QPs of the current port */
		if (test_params->test_opcode == TEST_OPCODE_ATOMIC_FETCH_ADD)
			trigger_fna(fifo_params, fd, port, db_fifo_index, db_fifo_entry_size);

		if (test_params->bp_offs) {
			rc = trigger_bp(fifo_params, port);
			assert_int_equal(rc, 0);
		}
	}

	if (test_params->bp_offs) {
		/* for bp_offs we do not parallelize ports */
		EXIT_FROM_TEST;
	}

	for (i = 0 ; i < iterations_db ; i++) {
		for (qp = 0, port_has_qp = true ; (qp < MAX_NUM_OF_QPS) && port_has_qp; qp++) {
			/* of no port has a QP in that index - no more QPs. */
			port_has_qp = false;

			for (port = 0, nic_idx = 0 ; port < max_n_ports ; port++) {
				/* ignore disabled ports (and do not increment nic_idx) */
				if (!(fifo_params->port_mask & BIT_ULL(port)))
					continue;

				qps_per_port = test_params->qps_per_port[port];

				/* skip ports with less QPs */
				if (qp >= qps_per_port)
					goto skip_port;

				port_has_qp = true;

				/* In case of RD-RDV, since there are no wqes for send ports,
				 * don't post doorbell on odd ports as they are the send ports.
				 */
				if ((fifo_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ)
						&& (qp & 1))
					goto skip_port;

				if (is_rdv && cmpl == SOB)
					hw_wq_pi = nwqs;
				else
					hw_wq_pi = nic_funcs->get_hw_wq_pi(nwqs, test_params->nwq,
										i, cmpl, false);

				qp_id = fifo_params->qp_ids[port][qp];

				rc = hltests_nic_create_db_packet(&db_fifo_packet, hw_wq_pi, qp_id,
									port);
				assert_int_equal(rc, 0);

				/*
				 * For quarter cycle doorbell ensure DBs sent 3 cycles back
				 * is consumed before continuing.
				 * Note: Rendezvous flow does not enable quarter cycle doorbell.
				 */
				if (!is_rdv && cmpl == SOB && (i >= DB_ITER_PER_CYCLE - 1)) {
					int next_sob_val;
					uint32_t second_last_idx, curr_sob_offset;

					second_last_idx = i - (DB_ITER_PER_CYCLE - 1);
					curr_sob_offset = second_last_idx % DB_ITER_PER_CYCLE;

					next_sob_val = (int)(qps_per_port *
						(1 + second_last_idx / DB_ITER_PER_CYCLE));

					rc = hltests_nic_wait_on_sob(fd, (uint32_t)
								     (first_sob + LOCAL_SOB_ID +
								     (nic_idx * DB_ITER_PER_CYCLE) +
								     curr_sob_offset),
								     tests_state, next_sob_val,
								     test_params->eq);
					assert_int_equal(rc, 0);
				}

				db_fifo = &fifo_params->fifos[port][db_fifo_index];
				pi_granularity = db_fifo_packet.size / db_fifo_entry_size;

				/* Wait till there is enough free space available in the user
				 * db fifo before pushing new entry
				 */
				hltests_nic_user_db_wait_entry_consume(db_fifo, db_fifo_entry_size,
									pi_granularity,
									extra_guard);

				hltests_nic_write_descriptor_to_db_fifo(tests_state, db_fifo,
									&db_fifo_packet, port,
									false);

				/* Update FIFO pi */
				if (hltests_is_gaudi2(fd)) {
					fifo_entries_amount = db_fifo->fifo_size /
							db_fifo_entry_size;
					db_fifo->pi = (db_fifo->pi + pi_granularity)
							& (fifo_entries_amount - 1);
				}
				/* In Gaudi3 the DB FIFO CI is a free run counter of 11 bits */
				else
					db_fifo->pi = (db_fifo->pi + pi_granularity)
							& (DB_FIFO_CI_FREE_RUN - 1);

				free(db_fifo_packet.packet);
skip_port:
				nic_idx++;
			}
		}

	}

	END_TEST;
}

static VOID push_dwq_to_fifo(struct hltests_nic_user_fifo_params *fifo_params)
{
	uint32_t cnt_wqe_pushed, qp_id, port, max_n_ports, pi_granularity,
		 db_fifo_entry_size = 0, i;
	int rc = 0, fd = fifo_params->tests_state->fd;
	struct hltests_state *tests_state = fifo_params->tests_state;
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hltests_nic_db_fifo_packet wtd_packet;
	uint32_t *ci_ptr, qp, nwq;
	struct hltests_nic_db_fifo_data *db_fifo;
	void *swqe, *rwqe;

	nwq = fifo_params->nwqs;

	max_n_ports = hltests_nic_get_max_num_of_ports(fd);
	db_fifo_entry_size = hdev->asic_funcs->nic_funcs->get_db_fifo_entry_size();
	cnt_wqe_pushed = 0;

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(fifo_params->port_mask & BIT_ULL(port)))
			continue;

		for (qp = 0 ; qp < fifo_params->qps_per_port[port] ; qp++) {

			if ((fifo_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) && (qp & 1))
				continue;

			db_fifo = &fifo_params->fifos[port][0];
			qp_id = fifo_params->qp_ids[port][qp];
			ci_ptr = (uint32_t *) db_fifo->ci_cpu_ptr;

			for (i = 0 ; i < nwq ; i++) {
				get_wqes(fd, port, qp_id, nwq, i, fifo_params->test_params,
						&swqe, &rwqe);

				rc = hdev->asic_funcs->nic_funcs->create_dwq_packet(&wtd_packet,
										    swqe, rwqe,
										    (int)qp_id);
				assert_int_equal(rc, 0);

				pi_granularity = wtd_packet.size / db_fifo_entry_size;

				/* Wait till there is enough free space available in the user
				 * db fifo before pushing new entry
				 */
				hltests_nic_user_db_wait_entry_consume(db_fifo, db_fifo_entry_size,
									pi_granularity, 0);

				hltests_nic_write_descriptor_to_db_fifo(tests_state, db_fifo,
									&wtd_packet, port, false);

				cnt_wqe_pushed++;

				/* DWQ feature is present from Gaudi3, in Gaudi3 the DB FIFO CI
				 * is a free run 11 bits counter
				 */
				db_fifo->pi = (db_fifo->pi + pi_granularity)
						& (DB_FIFO_CI_FREE_RUN - 1);

				free(wtd_packet.packet);
			}
		}
	}

	END_TEST;
}

static uint64_t user_db_popped(int fd, uint64_t port_mask,
			       struct hltests_nic_db_fifo_data **db_fifos,
			       uint32_t n_db_fifos)
{
	struct hltests_nic_db_fifo_data *db_fifo;
	uint32_t port, max_n_ports, i;
	uint64_t n_db_popped;

	max_n_ports = hltests_nic_get_max_num_of_ports(fd);

	n_db_popped = 0;
	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		for (i = 0 ; i < n_db_fifos ; i++) {
			db_fifo = &db_fifos[port][i];
			n_db_popped += *(uint64_t *) db_fifo->ci_cpu_ptr;
		}
	}

	return n_db_popped;
}

static VOID get_restore_cb(int fd, struct hltests_cs_chunk *cs,
				struct hltests_nic_in_params *in_params)
{
	void *cb;
	uint32_t cb_size = 0, dma_size, port, qp, n_qps, qps_till_now = 0, port_idx,
		pdma_qid;
	struct hltests_pkt_info pkt_info;
	uint64_t src_buf_va, local_conn_base, data_size,
		dst_buf_va, remote_conn_base, local_base, remote_base, dst_size, total_dma_size;
	uint16_t first_sob;
	int rc;

	first_sob = hltests_get_first_avail_sob(fd);
	data_size = in_params->data_size;
	dst_size = in_params->dst_data_size;
	pdma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	cb = hltests_create_cb(fd, HL_MAX_CB_SIZE, EXTERNAL, 0);
	assert_non_null(cb);
	rc = hltests_nic_cb_list_push(cb);
	assert_int_equal(rc, 0);

	for (port = 0, port_idx = 0; port < MAX_NIC_NUMBER_OF_PORTS ; port++) {
		if (!(in_params->port_mask & BIT_ULL(port)))
			continue;

		/* Clear doorbell SOB (used also when using CQ) */
		memset(&pkt_info, 0, sizeof(pkt_info));
		pkt_info.qid = pdma_qid;
		pkt_info.eb = EB_FALSE;
		pkt_info.mb = MB_TRUE;
		pkt_info.write_to_sob.sob_id = (uint16_t)(first_sob + DB_SOB_ID + port);
		pkt_info.write_to_sob.value = 0;
		pkt_info.write_to_sob.mode = SOB_SET;
		cb_size = hltests_add_write_to_sob_pkt(fd, cb, cb_size, &pkt_info);
		n_qps = in_params->qps_per_port[port];

		for (qp = 0 ; qp < n_qps ; qp++) {
			if ((in_params->is_dram || in_params->is_sram) &&
					!(in_params->single_alloc && qp)) {
				src_buf_va = hltests_get_device_va_for_host_ptr(fd,
							in_params->src_buf[port][qp]);

				local_base = in_params->is_dram ?
						in_params->local_dram_addr :
						in_params->local_sram_addr;

				if (in_params->single_alloc)
					local_conn_base = local_base + port_idx * data_size;
				else
					local_conn_base = local_base + (qps_till_now + qp) *
							data_size;

				/* Down phase */
				memset(&pkt_info, 0, sizeof(pkt_info));
				pkt_info.qid = pdma_qid;
				pkt_info.eb = EB_FALSE;
				pkt_info.mb = MB_TRUE;
				pkt_info.dma.dma_dir = in_params->is_dram ? DMA_DIR_HOST_TO_DRAM :
								DMA_DIR_HOST_TO_SRAM;
				/*
				 * the copy-to-dram is done with restore CB in
				 * order to ensure that it will be done prior
				 * to the nic operation.
				 */
				total_dma_size = 0;
				while (total_dma_size < data_size) {
					/* Split DMA into chunks of UINT32_MAX
					 * i.e. max supported size in PDMA CB packet.
					 */
					dma_size = MIN(UINT32_MAX,
						       (uint32_t)(data_size - total_dma_size));

					pkt_info.dma.src_addr = src_buf_va + total_dma_size;
					pkt_info.dma.dst_addr = local_conn_base + total_dma_size;
					pkt_info.dma.size = dma_size;
					cb_size = hltests_add_dma_pkt(fd, cb, cb_size, &pkt_info);

					total_dma_size += dma_size;
				}

				/* In case of reduction, push the random data on to the HBM
				 * dest buffer
				 */
				if (in_params->reduction_cfg) {
					dst_buf_va = hltests_get_device_va_for_host_ptr(fd,
								in_params->dst_buf[port][qp]);

					remote_base = in_params->is_dram ?
							in_params->remote_dram_addr :
							in_params->remote_sram_addr;

					remote_conn_base = remote_base +
								   ((qps_till_now + qp) *
								   dst_size);

					memset(&pkt_info, 0, sizeof(pkt_info));
					pkt_info.qid = pdma_qid;
					pkt_info.eb = EB_FALSE;
					pkt_info.mb = MB_TRUE;
					pkt_info.dma.src_addr = dst_buf_va;
					pkt_info.dma.dst_addr = remote_conn_base;
					pkt_info.dma.size = (uint32_t)dst_size;
					pkt_info.dma.dma_dir = in_params->is_dram ?
								DMA_DIR_HOST_TO_DRAM :
								DMA_DIR_HOST_TO_SRAM;

					cb_size = hltests_add_dma_pkt(fd, cb, cb_size, &pkt_info);
				}
			}
		}
		qps_till_now += n_qps;
		port_idx++;
	}

	cs->cb_ptr = cb;
	cs->cb_size = cb_size;
	cs->queue_index = pdma_qid;

	END_TEST;
}

static VOID get_execute_cbs(int fd, struct hltests_cs_chunk *execute_cs,
				struct hltests_nic_in_params *in_params)
{
	struct hltests_pkt_info pkt_info;
	struct hltests_monitor_and_fence mon_and_fence_info;
	void *db_cb, *int_db_cb, *db_release_cb;
	uint64_t db_cb_va;
	uint32_t db_cb_size, db_release_cb_size = 0, pdma_qid, nic_base_qid,
		 conn_id, nwqs, i, nic_idx = 0, n_qps, port, qp;
	uint16_t first_mon, first_sob;
	bool is_wr_rdv = false, is_rd_rdv = false, is_rdv = false;
	int rc;

	pdma_qid = hltests_get_dma_down_qid(fd, STREAM0);
	nic_base_qid = hltests_nic_get_base_qid(fd);
	first_mon = hltests_get_first_avail_mon(fd);
	first_sob = hltests_get_first_avail_sob(fd);
	nwqs = (uint32_t)(in_params->data_size / in_params->wqe_size);

	if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
		is_wr_rdv = true;
	else if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ)
		is_rd_rdv = true;

	is_rdv = is_wr_rdv || is_rd_rdv;

	/*
	 * This is the CB for releasing the DB fences via QMAN.
	 * In case we are going to release them by direct registers write, we
	 * will place NOP packet on that CB.
	 */
	db_release_cb = hltests_create_cb(fd, HL_MAX_CB_SIZE, EXTERNAL, 0);
	assert_non_null(db_release_cb);
	rc = hltests_nic_cb_list_push(db_release_cb);
	assert_int_equal(rc, 0);

	for (port = 0 ; port < MAX_NIC_NUMBER_OF_PORTS ; port++) {
		if (!(in_params->port_mask & BIT_ULL(port)))
			continue;

		db_cb_size = 0;

		db_cb = hltests_allocate_host_mem(fd, HL_MAX_CB_SIZE, NOT_HUGE_MAP);
		assert_non_null(db_cb);
		rc = hltests_nic_hmem_list_push(db_cb);
		assert_int_equal(rc, 0);

		memset(db_cb, 0, HL_MAX_CB_SIZE);

		db_cb_va = hltests_get_device_va_for_host_ptr(fd, db_cb);

		int_db_cb = hltests_create_cb(fd, HL_MAX_CB_SIZE, INTERNAL, db_cb_va);
		assert_non_null(int_db_cb);
		rc = hltests_nic_cb_list_push(int_db_cb);
		assert_int_equal(rc, 0);

		memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
		mon_and_fence_info.queue_id = (uint8_t)(nic_base_qid + port * 4);
		mon_and_fence_info.cmdq_fence = false;
		mon_and_fence_info.sob_id = (uint16_t)(first_sob + DB_SOB_ID + port);
		mon_and_fence_info.mon_id = (uint16_t)(first_mon + CS_MON_ID + port);
		mon_and_fence_info.mon_address = 0;
		mon_and_fence_info.sob_val = 1;
		mon_and_fence_info.dec_fence = true;
		mon_and_fence_info.mon_payload = 1;
		mon_and_fence_info.mon_mode = SOB_EQUAL;
		/* wait for initial SW doorbell before processing WQEs */
		db_cb_size = hltests_add_monitor_and_fence(fd, db_cb,
					db_cb_size, &mon_and_fence_info);

		n_qps = in_params->qps_per_port[port];

		/* add NIC doorbells for processing WQEs
		 * we are doing the doorbell same way in case of RDV transfers irrespective
		 * of the completion being CQs or SOBs to keep things simple for now
		 */
		if ((in_params->cmpl & CQ_USR) || is_rdv) {
			for (qp = 0 ; qp < n_qps ; qp++) {
				conn_id = in_params->nic_conn->conn_id[port][qp];

				/* For RD-RDV, there is no WQE for the send side. As per
				 * our configuration, odd qps are the send ports. So we skip
				 * the doorbell for the send side qps
				 */
				if (is_rd_rdv && (qp & 1))
					continue;

				db_cb_size = hltests_nic_add_bulk_doorbell_pkt(fd, db_cb,
									       db_cb_size,
									       (int)port, conn_id,
									       nwqs);
			}
		} else {
			/*
			 * SW-35814: add two half cycle doorbells for each
			 * iteration.
			 */
			memset(&mon_and_fence_info, 0, sizeof(mon_and_fence_info));
			mon_and_fence_info.queue_id = (uint8_t)(nic_base_qid + port * 4);
			mon_and_fence_info.cmdq_fence = false;
			mon_and_fence_info.sob_id = (uint16_t)(first_sob + LOCAL_SOB_ID + nic_idx);
			mon_and_fence_info.mon_id = (uint16_t)(first_mon + CS_MON_ID + port);
			mon_and_fence_info.mon_address = 0;
			mon_and_fence_info.dec_fence = true;
			mon_and_fence_info.mon_payload = 1;
			mon_and_fence_info.mon_mode = SOB_EQUAL;

			/*
			 * Running iterations using QMANs is modified to use
			 * 4 quarter cycle as in user DB.
			 * The loop below will push a doorbell for 1/4 of the WQ
			 * per iteration.
			 */
			for (i = 0 ; i < (in_params->iterations * 4) ; i++) {
				uint32_t curr_nwq;

				mon_and_fence_info.sob_val = n_qps * i;
				curr_nwq = ((i + 1) * (nwqs >> 2)) & (nwqs - 1);
				db_cb_size = hltests_add_monitor_and_fence(fd,
							db_cb,
							db_cb_size,
							&mon_and_fence_info);

				for (qp = 0 ; qp < n_qps ; qp++) {
					conn_id = in_params->nic_conn->conn_id[port][qp];

					db_cb_size = hltests_nic_add_bulk_doorbell_pkt(fd, db_cb,
							db_cb_size, (int)port, conn_id, curr_nwq);
				}
			}
		}

		execute_cs[nic_idx].cb_ptr = int_db_cb;
		execute_cs[nic_idx].cb_size = db_cb_size;
		execute_cs[nic_idx].queue_index = nic_base_qid + port * 4;
		nic_idx++;

		if (in_params->db_qman) {
			/* release initial doorbell fence */
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.qid = pdma_qid;
			pkt_info.eb = EB_TRUE;
			pkt_info.mb = MB_TRUE;
			pkt_info.write_to_sob.sob_id = (uint16_t)(first_sob + DB_SOB_ID + port);
			pkt_info.write_to_sob.value = 1;
			pkt_info.write_to_sob.mode = SOB_SET;
			db_release_cb_size = hltests_add_write_to_sob_pkt(fd, db_release_cb,
							db_release_cb_size, &pkt_info);
		} else {
			/* the CB can't be empty */
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.qid = pdma_qid;
			pkt_info.eb = EB_TRUE;
			pkt_info.mb = MB_TRUE;
			db_release_cb_size = hltests_add_nop_pkt(fd, db_release_cb,
							db_release_cb_size, &pkt_info);
		}
	}

	execute_cs[nic_idx].cb_ptr = db_release_cb;
	execute_cs[nic_idx].cb_size = db_release_cb_size;
	execute_cs[nic_idx].queue_index = pdma_qid;

	END_TEST;
}

static int32_t get_max_supported_wqs_per_port(int fd, struct hltests_nic_in_params *in_params,
					      bool is_coll_wq)
{
	uint32_t port, max_n_ports, max_supported_wqs_per_port = 0, val = 0;
	int rc;

	max_n_ports = hltests_nic_get_max_num_of_ports(fd);

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(in_params->port_mask & BIT_ULL(port)))
			continue;

		if (hltests_nic_is_ibdev(fd)) {
			struct hbldv_query_port_attr port_attr = {};

			rc = hbldv_query_port(in_params->ib_in_params->ibctx,
					      hltests_nic_to_ibdev_port_num(fd, port),
					      &port_attr);
			assert_int_equal(rc, 0);

			val = is_coll_wq ?
					port_attr.max_num_of_scale_out_coll_qps :
					port_attr.max_num_of_qps;
		} else {
			struct hlthunk_nic_user_get_app_params_out get_app_params_out = {};

			rc = hlthunk_nic_user_get_app_params(fd, port, &get_app_params_out);
			assert_int_equal(rc, 0);

			val = is_coll_wq ?
					get_app_params_out.max_num_of_scale_out_coll_qps :
					get_app_params_out.max_num_of_qps;
		}

		if (max_supported_wqs_per_port < val)
			max_supported_wqs_per_port = val;
	}

	return (int32_t)max_supported_wqs_per_port;
}

static int nic_wq_array_create_on_dram(int fd, struct hltests_nic_in_params *in_params,
				       uint32_t nic, uint32_t wq_nwq)
{
	struct hlthunk_nic_wq_arr_set_in wq_arr_set_in = {};
	struct hlthunk_nic_wq_arr_set_out wq_arr_set_out;
	bool is_coll_wq;
	int rc = 0;

	is_coll_wq = in_params->coll_type == COLL_TYPE_DIRECT;

	wq_arr_set_in.port = nic;
	wq_arr_set_in.addr = 0;
	wq_arr_set_in.num_of_wqs = in_params->qps_per_port[nic] + (is_coll_wq ? 0 : 1);
	wq_arr_set_in.num_of_wq_entries = wq_nwq;
	wq_arr_set_in.mem_id = HL_NIC_MEM_DEVICE;
	wq_arr_set_in.swq_granularity = !!(in_params->rdv_type == HLTESTS_NIC_RDV_MS);

	wq_arr_set_in.type = is_coll_wq ?
			HL_NIC_USER_COLL_SCALE_OUT_WQ_SEND : HL_NIC_USER_WQ_SEND;

	rc = hlthunk_nic_wq_arr_set(fd, &wq_arr_set_in, &wq_arr_set_out);
	assert_int_equal(rc, 0);

	wq_arr_set_in.type = is_coll_wq ?
			HL_NIC_USER_COLL_SCALE_OUT_WQ_RECV : HL_NIC_USER_WQ_RECV;

	rc = hlthunk_nic_wq_arr_set(fd, &wq_arr_set_in, &wq_arr_set_out);
	assert_int_equal(rc, 0);

	return rc;
}

/*
 * Each QP is assigned with a single work queue, the mapping of work queues and
 * QPs is according to the QP number (for example WQ number 15 is assigned to QP
 * number 15).
 * All work queues are virtually-contiguous in the memory, and sharing the same
 * max size and base address.
 * Each WQE has two parts, one that the TX is using (SWQ) and one that RX is
 * using (RWQ). Each part of the WQE is posted on different WQ table.
 */
static int nic_wq_array_create(int fd, struct hltests_nic_in_params *in_params)
{
	struct hlthunk_nic_wq_arr_set_in wq_arr_set_in = {};
	struct hlthunk_nic_wq_arr_set_out wq_arr_set_out;
	struct hltests_device *hdev;
	uint64_t test_port_mask;
	uint32_t wq_nwq, max_n_ports, nic;
	bool is_coll_wq;
	int rc = 0;

	/* for IB device this is done implicitly as part of ibdev_set_ports_ex function */
	if (hltests_nic_is_ibdev(fd))
		return 0;

	test_port_mask = in_params->port_mask;
	max_n_ports = hltests_nic_get_max_num_of_ports(fd);

	nic_get_wq_arr_nwqe(fd, in_params, &wq_nwq);

	is_coll_wq = in_params->coll_type == COLL_TYPE_DIRECT;

	for (nic = 0 ; nic < max_n_ports ; nic++) {
		if (!(test_port_mask & BIT_ULL(nic)))
			continue;

		hdev = get_hdev_from_fd(fd);

		/* Create WQs */
		if (in_params->wq_loc == HL_NIC_MEM_DEVICE) {
			rc = nic_wq_array_create_on_dram(fd, in_params, nic, wq_nwq);
		} else {/* wq_loc == HL_NIC_MEM_HOST */
			wq_arr_set_in.port = nic;
			wq_arr_set_in.addr = 0;

			/* To force MMU approach, the WQ array will be allocated with the max
			 * number of WQs.
			 */
			if (in_params->force_wq_with_pmmu)
				wq_arr_set_in.num_of_wqs = (uint32_t)
					get_max_supported_wqs_per_port(fd, in_params, is_coll_wq);
			else
				wq_arr_set_in.num_of_wqs =
						in_params->qps_per_port[nic] + (is_coll_wq ? 0 : 1);

			in_params->num_of_wqs = wq_arr_set_in.num_of_wqs;
			wq_arr_set_in.num_of_wq_entries = wq_nwq;
			wq_arr_set_in.mem_id = HL_NIC_MEM_HOST;
			wq_arr_set_in.swq_granularity =
						!!(in_params->rdv_type == HLTESTS_NIC_RDV_MS);

			wq_arr_set_in.type = is_coll_wq ?
					HL_NIC_USER_COLL_SCALE_OUT_WQ_SEND : HL_NIC_USER_WQ_SEND;

			rc = hlthunk_nic_wq_arr_set(fd, &wq_arr_set_in, &wq_arr_set_out);
			assert_int_equal(rc, 0);

			wq_arr_set_in.type = is_coll_wq ?
					HL_NIC_USER_COLL_SCALE_OUT_WQ_RECV : HL_NIC_USER_WQ_RECV;

			rc = hlthunk_nic_wq_arr_set(fd, &wq_arr_set_in, &wq_arr_set_out);
			assert_int_equal(rc, 0);
		}
	}

	return rc;
}

static int nic_wq_array_destroy(int fd, struct hltests_nic_in_params *in_params)
{
	int rc = 0;
	uint32_t nwq, wq_nwq, type, num_of_ports, i;
	bool is_coll_wq;

	/* for IB device this is done implicitly when closing the device */
	if (hltests_nic_is_ibdev(fd))
		return 0;

	nwq = in_params->nwq;
	wq_nwq = nwq < WQES_MIN ? WQES_MIN : nwq;
	num_of_ports = hltests_nic_get_max_num_of_ports(fd);

	is_coll_wq = in_params->coll_type == COLL_TYPE_DIRECT;

	for (i = 0 ; i < num_of_ports ; i++) {
		if (!(in_params->port_mask & BIT_ULL(i)))
			continue;

		type = is_coll_wq ? HL_NIC_USER_COLL_SCALE_OUT_WQ_SEND : HL_NIC_USER_WQ_SEND;

		rc = hlthunk_nic_wq_arr_unset(fd, i, type);
		assert_int_equal(rc, 0);

		type = is_coll_wq ? HL_NIC_USER_COLL_SCALE_OUT_WQ_RECV : HL_NIC_USER_WQ_RECV;

		rc = hlthunk_nic_wq_arr_unset(fd, i, type);
		assert_int_equal(rc, 0);
	}

	return 0;
}

static int nic_cqs_create(int fd, struct hltests_nic_in_params *in_params)
{
	struct hltests_nic_cq *cqs = in_params->cqs;
	int i;

	if (!cqs)
		return 0;

	i = -1;
	do {
		i++;

		if (hltests_nic_is_ibdev(fd))
			cqs[i].ibctx = in_params->ib_in_params->ibctx;

		assert_int_equal(hltests_nic_cq_create(fd, &cqs[i]), 0);
	} while (&cqs[i] != in_params->cq);

	return 0;
}

static int nic_cqs_destroy(int fd, struct hltests_nic_in_params *in_params)
{
	struct hltests_nic_cq *cqs = in_params->cqs;
	int i;

	/* for IB device, the CQ is created and destroyed per test iteration */
	if (hltests_nic_is_ibdev(fd) || !cqs)
		return 0;

	i = -1;
	do {
		i++;
		assert_int_equal(hltests_nic_cq_destroy(fd, &cqs[i]), 0);
	} while (&cqs[i] != in_params->cq);

	return 0;
}

static enum hltests_nic_cmpl config_sobs(uint32_t wqe_num, uint32_t nwq, bool is_rdv, bool is_fna,
					 enum hltests_nic_afa_cmpl_mode fna_cmpl)
{
	/* For RDV transfer, we are not doing the half-doorbell hence SOB is needed for all the
	 * WQEs
	 */
	if (is_rdv)
		return SOB;

	/* Configure the SOB to increment at first WQE once, to be able to trigger the FnA WQE.
	 * We use the USER_CQ completion in case of AFA_CQ_USR_CMPL
	 */
	if (is_fna && wqe_num == 1 && (fna_cmpl == AFA_REG_CMPL))
		return SOB;

	/* quarter cycle doorbell */
	return ((((wqe_num) == nwq) || ((wqe_num) == (nwq >> 2)) || ((wqe_num) == (nwq >> 1)) ||
		((wqe_num) == ((nwq >> 2) + (nwq >> 1)))) ? SOB : NONE);
}

/**
 * dma_reset_fna_op_mem - Reset Fetch and Add operation memory.
 *
 * @fd: Device file descriptor.
 * @dst_addr: Destination SRAM address to reset.
 * @size: SRAM memory block size.
 * Return: int
 *
 * Fetch and Add operates against the SRAM or the DRAM.
 * This routine will memset the relevant memory of the FnA operation location to 0.
 */
static int dma_reset_fna_op_mem(int fd, uint64_t dst_addr, uint32_t size)
{
	uint32_t fna_cb_size = 0, pdma_qid;
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info hw_ip;
	void *fna_cb;
	int rc;

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

	return hltests_submit_and_wait_cs(fd, fna_cb, fna_cb_size, pdma_qid,
			DESTROY_CB_TRUE, HL_WAIT_CS_STATUS_COMPLETED);
}

static int32_t config_wqes(int fd, struct hltests_nic_in_params *in_params)
{
	struct hltests_nic_conn_out *nic_conn;
	struct hltests_device *hdev;
	struct hltests_nic_wqe_params wqe_param = {0};
	struct hlthunk_hw_ip_info hw_ip;
	void *swqe, *rwqe;
	uint64_t data_size, local_addr, remote_addr, **src_buf_va, **dst_buf_va,
		local_conn_base, remote_conn_base, port_mask, reduction_cfg, qp_base,
		temp_local_addr = 0, temp_rem_addr = 0, local_base, remote_base, dst_size, offset;
	uint32_t wqe_size, wq_nwq, nwq, rand = 0, qps_per_port, qps_till_now = 0,
		iterations, tag_mask, max_n_ports, i, nic, nic_idx, qp_idx, qp,
		tag_idx, conn_id, local_sob_id, remote_sob_id, sob_inc, sobs_per_port;

	uint16_t first_sob;
	enum hltests_nic_cmpl cmpl, curr_cmpl;
	enum hl_nic_mem_id wq_loc;
	bool ackreq, is_dram, single_alloc, is_rdv = false, is_wr_rdv = false, is_rd_rdv = false,
		is_fna = false;
	int rc;

	is_dram = in_params->is_dram;
	single_alloc = in_params->single_alloc;
	cmpl = in_params->cmpl;
	iterations = in_params->iterations;
	port_mask = in_params->port_mask;
	wqe_size = in_params->wqe_size;
	data_size = in_params->data_size;
	nic_conn = in_params->nic_conn;
	wq_loc = in_params->wq_loc;
	nwq = in_params->nwq;
	wq_nwq = nwq < WQES_MIN ? WQES_MIN : nwq;
	ALLOC_2D_ARR(src_buf_va, MAX_NIC_NUMBER_OF_PORTS, MAX_NUM_OF_QPS);
	ALLOC_2D_ARR(dst_buf_va, MAX_NIC_NUMBER_OF_PORTS, MAX_NUM_OF_QPS);
	first_sob = hltests_get_first_avail_sob(fd);
	max_n_ports = hltests_nic_get_max_num_of_ports(fd);
	dst_size = in_params->dst_data_size;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	assert_int_equal(rc, 0);

	reduction_cfg = in_params->reduction_cfg;
	sob_inc = nwq / DB_ITER_PER_CYCLE;
	/* We use more than single SOB in case we submit with user_db
	 * and it is not patcher operation mode. As in patcher the way
	 * SOBs are managed is different and hence we leave the
	 * configuration as is.
	 */
	sobs_per_port = in_params->user_db && !in_params->coll_op ? DB_ITER_PER_CYCLE : 1;

	tag_mask = ~(next_pow2(in_params->max_qps_per_port) - 1);

	if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
		is_wr_rdv = true;
	else if (in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ)
		is_rd_rdv = true;

	is_rdv = is_wr_rdv || is_rd_rdv;

	if (in_params->test_opcode == TEST_OPCODE_ATOMIC_FETCH_ADD)
		is_fna = true;

	local_base = is_dram ? in_params->local_dram_addr :
				in_params->local_sram_addr;
	remote_base = is_dram ? in_params->remote_dram_addr :
				in_params->remote_sram_addr;

	for (nic = 0, nic_idx = 0 ; nic < max_n_ports ; nic++) {
		if (!(port_mask & BIT_ULL(nic)))
			continue;

		hdev = get_hdev_from_fd(fd);
		qps_per_port = in_params->qps_per_port[nic];
		for (qp = 0 ; qp < qps_per_port ; qp++) {
			if (single_alloc && qp) {
				src_buf_va[nic][qp] = src_buf_va[nic][0];
				dst_buf_va[nic][qp] = dst_buf_va[nic][0];
				continue;
			}

			src_buf_va[nic][qp] = hltests_get_device_va_for_host_ptr(fd,
								in_params->src_buf[nic][qp]);

			dst_buf_va[nic][qp] = hltests_get_device_va_for_host_ptr(fd,
								in_params->dst_buf[nic][qp]);
		}

		for (qp = 0 ; qp < qps_per_port ; qp++) {
			/* For RD-RDV, there is no WQE to be posted for the send side */
			if (is_rd_rdv && (qp & 1))
				continue;

			conn_id = nic_conn->conn_id[nic][qp];
			qp_idx = qps_till_now + qp;

			/* To support 4 quarter DB and prevent situation where we think that
			 * the all the ports have finished the first chunk we will allocate for
			 * each port, 4 SOBs. This way we will promise that each port will signal
			 * each SOB only once per iteration DB
			 */
			local_sob_id = first_sob + nic_idx * sobs_per_port;

			if (in_params->remote_sob_idx)
				remote_sob_id = first_sob + in_params->remote_sob_idx[qp_idx];
			else
				remote_sob_id = first_sob + nic_idx * sobs_per_port;

			if (in_params->verbose == VERBOSE_DEBUG) {
				printf("port: %d, QP: %d\n", nic, conn_id);
				printf("local_sob_id: %d, remote_sob_id: %d\n",
					local_sob_id, remote_sob_id);
			}

			if (is_dram || in_params->is_sram) {
				/* For single_alloc, all the qps should be sharing the same base
				 * address that of qp 0
				 */
				if (single_alloc && qp) {
					local_conn_base = temp_local_addr;
					remote_conn_base = temp_rem_addr;
				} else {
					local_conn_base = local_base + (single_alloc ? nic_idx :
									qp_idx) * data_size;

					/* In case there is an upscale, the dest size is twice
					 * the src data size or if downscale, the dest size is
					 * half of src size. Hence we calculate the remote address
					 * correspondingly
					 */
					if (in_params->remote_addr_idx)
						qp_base = in_params->remote_addr_idx[qp_idx]
										* dst_size;
					else
						qp_base = (single_alloc ? nic_idx : qp_idx) *
								dst_size;

					remote_conn_base = remote_base + qp_base;

					if (in_params->verbose == VERBOSE_DEBUG)
						printf("remote_conn_base: 0x%lx\n",
									 remote_conn_base);

					temp_local_addr = local_conn_base;
					temp_rem_addr = remote_conn_base;
				}
			} else {
				local_conn_base = src_buf_va[nic][qp];
				remote_conn_base = dst_buf_va[nic][qp];
			}

			/* Push WQ */
			for (i = 0 ; i < nwq ; i++) {
				/* Cast to span offset beyond 32bit address space. */
				offset = i * (uint64_t) wqe_size;

				local_addr = local_conn_base + offset;

				if (in_params->upscale_en)
					remote_addr = remote_conn_base + (offset << 1);
				else if (in_params->downscale_en)
					remote_addr = remote_conn_base + (offset >> 1);
				else
					remote_addr = remote_conn_base + offset;

				get_wqes(fd, nic, conn_id, wq_nwq, i, in_params, &swqe, &rwqe);
				ackreq = !(i % 64);

				if (cmpl == SOB) {
					curr_cmpl = config_sobs((i + 1),
								(uint32_t)(data_size / wqe_size),
								is_rdv, is_fna,
								in_params->fna_cmpl);
				} else {
					if (in_params->test == LPBK) {
						tag_idx = (nic * MAX_NUM_OF_QPS + qp) * nwq + i;
						 /* embed the QP idx in the tag for the CQE */
						in_params->tag[tag_idx] &= tag_mask;
						in_params->tag[tag_idx] |= qp;
						rand = in_params->tag[tag_idx];

						curr_cmpl = in_params->single_cmpl ?
							(((i + 1) == nwq) ? cmpl : NONE) : cmpl;
					} else {
						rand = in_params->seed[nic_idx] +
							(in_params->dst_conn_ids[qp_idx] &
							((uint32_t)hltests_get_max_num_of_qps
							(fd, nic) - 1));
						curr_cmpl = ((i + 1) == nwq) ? cmpl : NONE;
					}
				}

				wqe_param.sq_wqe = swqe;
				wqe_param.rq_wqe = rwqe;
				wqe_param.size = wqe_size;
				wqe_param.ackreq = ackreq;
				wqe_param.wqe_index = (int)i;
				wqe_param.tag = (int)rand;
				/* We use more than single SOB in case we submit with user_db
				 * and it is not patcher operation mode. As in patcher the way
				 * SOBs are managed is different and hence we leave the
				 * configuration as is.
				 */
				if (in_params->user_db && !in_params->coll_op) {
					wqe_param.local_sob_id = (int)(local_sob_id + i / sob_inc);
					wqe_param.remote_sob_id = (int)
								(remote_sob_id + i / sob_inc);
				} else {
					wqe_param.local_sob_id = (int)local_sob_id;
					wqe_param.remote_sob_id = (int)remote_sob_id;
				}
				wqe_param.cmpl = curr_cmpl;
				wqe_param.test_opcode = in_params->test_opcode;
				wqe_param.local_address = local_addr;
				wqe_param.remote_address = remote_addr;
				wqe_param.reduction_cfg = reduction_cfg;
				wqe_param.downscale_en = in_params->downscale_en;
				wqe_param.qp = qp;
				wqe_param.cache_en = in_params->cache_en;
				wqe_param.fna_cmpl = in_params->fna_cmpl;
				wqe_param.fna_op_addr = in_params->fna_op_addr;
				wqe_param.compression_en = in_params->compression_en;
				wqe_param.upscale_en = in_params->upscale_en;
				wqe_param.rdv_remote_pi = i;

				if (is_wr_rdv)
					wqe_param.is_wr_rdv_send = qp & 1;

				hltests_nic_fill_wqe(fd, &wqe_param);
			}
		}
		qps_till_now += qps_per_port;
		nic_idx++;
	}

	FREE_2D_ARR(src_buf_va, MAX_NIC_NUMBER_OF_PORTS);
	FREE_2D_ARR(dst_buf_va, MAX_NIC_NUMBER_OF_PORTS);

	return (int32_t)nic_idx;
}

static int coll_op_comm_group_init(struct hltests_nic_coll_comm_group *comm_group)
{
	struct hltests_nic_in_params *in_params;
	struct hltests_nic_coll_comm_node *comm_node;
	uint32_t port, max_n_ports;

	assert_non_null(comm_group->tests_state);
	assert_non_null(comm_group->in_params);
	assert_non_null(comm_group->nodes_mask);

	in_params = comm_group->in_params;
	max_n_ports = hltests_nic_get_max_num_of_ports(comm_group->tests_state->fd);

	comm_group->allocated = 1;

	if (in_params->coll_op == COLL_OP_MODE_LEGACY) {
		comm_group->n_ranks = 1;
		comm_group->nodes_per_rank = 1;
	} else if (in_params->coll_op == COLL_OP_MODE_MULTI_LAG) {
		comm_group->n_ranks = 1;
		comm_group->nodes_per_rank = in_params->n_ports;
	} else if (in_params->coll_op == COLL_OP_MODE_MULTI_RANK ||
			in_params->coll_op == COLL_OP_MODE_MULTI_CONTEXT) {
		if (comm_group->in_params->rdv_type == HLTESTS_NIC_RDV_V_OP)
			/*  V operations supports only 1 rank */
			comm_group->n_ranks = 1;
		else
			comm_group->n_ranks = comm_group->in_params->number_of_ranks ?
				comm_group->in_params->number_of_ranks : MAX_COLL_COMM_RANKS;

		comm_group->nodes_per_rank = in_params->n_ports;
	} else {
		printf("Unsupported coll op %d\n", in_params->coll_op);
		return -1;
	}

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(in_params->port_mask & comm_group->nodes_mask & BIT_ULL(port)))
			continue;

		comm_node = &comm_group->nodes[port];

		comm_node->conn_id = in_params->nic_conn->conn_id[port][comm_group->id];
		comm_node->port_id = port;
		comm_node->comm_group = comm_group;
		comm_node->db_fifo = &in_params->db_fifos[port][0];
	}

	return 0;
}

static void coll_op_comm_group_destroy(struct hltests_nic_coll_comm_group *comm_group)
{
	memset(comm_group, 0, sizeof(struct hltests_nic_coll_comm_group));
}

static void coll_op_comm_group_destroy_all(struct hltests_nic_in_params *in_params)
{
	struct hltests_nic_coll_comm_group *comm_group;
	int i;

	for (i = 0 ; i < in_params->max_coll_comm_groups ; i++) {
		comm_group = &in_params->comm_group[i];
		if (comm_group->allocated)
			coll_op_comm_group_destroy(comm_group);
	}
}

static int run_coll_op(struct hltests_nic_coll_comm_group *comm_group)
{
	int rc;

	rc = coll_op_comm_group_init(comm_group);
	assert_int_equal(rc, 0);

	rc = hltests_nic_run_coll_op(comm_group->tests_state->fd, comm_group);
	assert_int_equal(rc, 0);

	return 0;
}

static int run_coll_op_legacy(struct hltests_state *tests_state,
				struct hltests_nic_in_params *in_params, uint32_t max_n_ports)
{
	struct hltests_nic_coll_comm_group *comm_group;
	uint32_t port;
	int rc;

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(in_params->port_mask & BIT_ULL(port)))
			continue;

		/* We coalesce communication group clean-up at end of
		 * the test. To track allocated resources, use a new entry
		 * for each port.
		 */
		comm_group = &in_params->comm_group[0];
		memset(comm_group, 0, sizeof(*comm_group));

		comm_group->tests_state = tests_state;
		comm_group->in_params = in_params;
		comm_group->id = 0;
		comm_group->nodes_mask = BIT_ULL(port);

		rc = run_coll_op(comm_group);
		assert_int_equal(rc, 0);
	}

	return 0;
}

static int run_coll_op_multi_lag_rank(struct hltests_state *tests_state,
					struct hltests_nic_in_params *in_params)
{
	struct hltests_nic_coll_comm_group *comm_group;

	/* We coalesce communication group clean-up at end of
	 * the test. To track allocated resources, use a new entry
	 * for each port.
	 */
	comm_group = &in_params->comm_group[0];
	memset(comm_group, 0, sizeof(*comm_group));

	comm_group->tests_state = tests_state;
	comm_group->in_params = in_params;
	comm_group->id = 0;
	comm_group->nodes_mask = in_params->port_mask;

	return run_coll_op(comm_group);
}

/* There is no concept of multi-context in direct patcher since all the descriptors are tied to
 * a QP. But we want to leveraging on the existing infra to get the qp id via the comm_group->id,
 * so this function is being used by direct patcher to run the Rendezvous tests.
 */
static int run_coll_op_multi_context(struct hltests_state *tests_state,
					struct hltests_nic_in_params *in_params,
					uint32_t max_n_ports)
{
	struct hltests_nic_coll_comm_group *comm_group;
	struct hltests_device *hdev;
	uint32_t port, qp;
	int rc = 0, fd;

	for (qp = 0 ; qp < in_params->max_qps_per_port ; qp++) {
		/* No packets are send on requester side for rd-rdv */
		if ((in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) &&
				(qp & 1))
			continue;

		/* Each context uses the same QP index(note, not ID)
		 * on all ports.
		 */
		comm_group = &in_params->comm_group[qp];
		memset(comm_group, 0, sizeof(*comm_group));

		if ((in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE) &&
			((qp & 1) == 0)) {
			for (port = 0 ; port < max_n_ports ; port++) {
				if (!(in_params->port_mask & BIT_ULL(port)))
					continue;

				comm_group->tests_state = tests_state;
				comm_group->in_params = in_params;
				comm_group->id = qp;
				comm_group->nodes_mask = BIT_ULL(port);
				rc = run_coll_op(comm_group);
				assert_int_equal(rc, 0);
			}

			/* skip the below call to run_coll_op */
			continue;
		}

		comm_group->tests_state = tests_state;
		comm_group->in_params = in_params;
		comm_group->id = qp;

		/* V-OP requires two coll op messages. one for lower half of the ports and one
		 * for the upper part.
		 */
		if (in_params->rdv_type == HLTESTS_NIC_RDV_V_OP &&
			in_params->coll_type == COLL_TYPE_CONTEXT) {
			fd = tests_state->fd;
			hdev = get_hdev_from_fd(fd);

			/* lower half */
			comm_group->nodes_mask = hdev->asic_funcs->nic_funcs->get_half_port_mask(fd,
								in_params->port_mask, false);
			if (comm_group->nodes_mask)
				rc = run_coll_op(comm_group);

			/* upper half */
			comm_group->nodes_mask = hdev->asic_funcs->nic_funcs->get_half_port_mask(fd,
								in_params->port_mask, true);
			if (comm_group->nodes_mask)
				rc = run_coll_op(comm_group);
		} else {
			comm_group->nodes_mask = in_params->port_mask;
			rc = run_coll_op(comm_group);
		}
		assert_int_equal(rc, 0);
	}

	return 0;
}

static int nic_run_coll_op(struct hltests_nic_user_fifo_params *fifo_params)
{
	struct hltests_nic_in_params *in_params;
	struct hltests_state *tests_state;
	uint32_t max_n_ports;
	int rc, fd;

	fd = fifo_params->tests_state->fd;
	in_params = fifo_params->test_params;
	tests_state = fifo_params->tests_state;
	max_n_ports = hltests_nic_get_max_num_of_ports(fd);

	if (in_params->coll_op == COLL_OP_MODE_LEGACY) {
		rc = run_coll_op_legacy(tests_state, in_params, max_n_ports);
		assert_int_equal(rc, 0);
	} else if (in_params->coll_op == COLL_OP_MODE_MULTI_LAG ||
			in_params->coll_op == COLL_OP_MODE_MULTI_RANK) {
		rc = run_coll_op_multi_lag_rank(tests_state, in_params);
		assert_int_equal(rc, 0);
	} else if (in_params->coll_op == COLL_OP_MODE_MULTI_CONTEXT) {
		rc = run_coll_op_multi_context(tests_state, in_params, max_n_ports);
		assert_int_equal(rc, 0);
	}

	return 0;
}

/*
 * Gaudi2 has CQ also on the internal queues (in opposite to Gaudi1 which could
 * get completions only for the external CBs), so if we wait for the CS to
 * complete before signaling the SOBs which release the NIC DB fences, we might
 * get stuck.
 * In case we signal these SOBs via QMAN, there is no problem, because it will
 * be done as part of the CS execution phase.
 * However, in case we do it by writing to the SOBs directly (registers write),
 * we must do it before waiting for the CS to complete.
 * In case we work in dram mode (when the data is located in the device),
 * writing to the SOBs directly via the registers before waiting for the CS to
 * complete might cause us to ring the DB before the DMA host->DRAM finished.
 * Therefore, we moved the DMA operation to be part of the restore CB.
 */
static int nic_operation(struct hltests_state *tests_state,
			struct hltests_nic_in_params *in_params, uint64_t *seq,
			struct hlthunk_time_sync_info *begin)
{
	struct hltests_cs_chunk restore_arr[1], execute_arr[1 + MAX_NIC_NUMBER_OF_PORTS];
	uint32_t n_ports;
	int rc, fd;

	fd = tests_state->fd;

	if (in_params->wtd_en && hltests_is_gaudi2(fd))
		return hltests_nic_run_wtd(fd, in_params);

	rc = config_wqes(fd, in_params);
	assert_false(rc <= 0);

	n_ports = (uint32_t)rc;

	get_restore_cb(fd, &restore_arr[0], in_params);

	hlthunk_get_time_sync_info(fd, begin);

	if (in_params->user_db) {
		rc = hltests_submit_cs(fd, NULL, 0, restore_arr, 1,
						HL_CS_FLAGS_FORCE_RESTORE, seq);
	} else {
		get_execute_cbs(fd, &execute_arr[0], in_params);

		rc = hltests_submit_cs(fd, restore_arr, 1, execute_arr, n_ports + 1,
						HL_CS_FLAGS_FORCE_RESTORE, seq);
	}
	assert_int_equal(rc, 0);

	return rc;
}

static int nic_copy_devmem_to_host(struct hltests_state *tests_state,
					struct hltests_nic_in_params *in_params)
{
	uint64_t data_size, **dst_buf_va, seq, timeout, total_dma_size;
	uint64_t remote_data_base, remote_conn_base;
	uint32_t dma_cb_size = 0, qps_till_now = 0, dma_size, nic,
		 nic_idx, qp_idx, qp, pdma_qid;
	struct hltests_cs_chunk execute_arr;
	struct hltests_pkt_info pkt_info;
	struct hlthunk_hw_ip_info *hw_ip;
	void *dma_cb;
	int fd, rc;

	fd = tests_state->fd;
	hw_ip = &tests_state->hw_ip;

	timeout = hltests_is_pldm(fd) ? NIC_PDMA_TIMEOUT_PLDM_USEC : NIC_PDMA_TIMEOUT_USEC;
	data_size = in_params->data_size;
	pdma_qid = hltests_get_dma_up_qid(fd, STREAM0);

	assert_true(hw_ip->dram_enabled);
	remote_data_base = in_params->is_dram ?
				in_params->remote_dram_addr :
				in_params->remote_sram_addr;

	if (in_params->upscale_en || in_params->downscale_en)
		data_size = in_params->dst_data_size;

	dma_cb = hltests_create_cb(fd, HL_MAX_CB_SIZE, EXTERNAL, 0);
	assert_non_null(dma_cb);

	rc = hltests_nic_cb_list_push(dma_cb);
	assert_int_equal(rc, 0);

	ALLOC_2D_ARR(dst_buf_va, MAX_NIC_NUMBER_OF_PORTS, MAX_NUM_OF_QPS);

	for (nic = 0, nic_idx = 0 ; nic < MAX_NIC_NUMBER_OF_PORTS ; nic++) {
		if (!(in_params->port_mask & BIT_ULL(nic)))
			continue;

		for (qp = 0 ; qp < in_params->qps_per_port[nic] ; qp++) {
			if (in_params->single_alloc && qp)
				continue;

			qp_idx = qps_till_now + qp;

			if (in_params->single_alloc)
				remote_conn_base = remote_data_base + nic_idx * data_size;
			else
				remote_conn_base = remote_data_base + qp_idx * data_size;

			if (in_params->verbose == VERBOSE_DEBUG)
				printf(
					"copy DRAM to host, port: %u, QP: %u, remote_conn_base: 0x%lx\n",
					nic, in_params->nic_conn->conn_id[nic][qp],
					remote_conn_base);

			dst_buf_va[nic][qp] = hltests_get_device_va_for_host_ptr(fd,
								in_params->dst_buf[nic][qp]);

			/* Prepare CB on DMA 1.0 */
			memset(&pkt_info, 0, sizeof(pkt_info));
			pkt_info.qid = pdma_qid;
			pkt_info.eb = EB_FALSE;
			pkt_info.mb = MB_TRUE;
			pkt_info.dma.dma_dir = in_params->is_dram ?
						DMA_DIR_DRAM_TO_HOST :
						DMA_DIR_SRAM_TO_HOST;

			total_dma_size = 0;
			while (total_dma_size < data_size) {

				/* Split DMA into chunks of UINT32_MAX
				 * i.e. max supported size in PDMA CB packet.
				 */
				dma_size = MIN(UINT32_MAX, (uint32_t)(data_size - total_dma_size));

				pkt_info.dma.src_addr = remote_conn_base + total_dma_size;
				pkt_info.dma.dst_addr = dst_buf_va[nic][qp] + total_dma_size;
				pkt_info.dma.size = dma_size;
				dma_cb_size = hltests_add_dma_pkt(fd, dma_cb,
									dma_cb_size, &pkt_info);

				total_dma_size += dma_size;
			}
		}
		qps_till_now += in_params->qps_per_port[nic];
		nic_idx++;
	}

	execute_arr.cb_ptr = dma_cb;
	execute_arr.cb_size = dma_cb_size;
	execute_arr.queue_index = pdma_qid;

	rc = hltests_submit_cs(fd, NULL, 0, &execute_arr, 1,
				HL_CS_FLAGS_FORCE_RESTORE, &seq);
	assert_int_equal(rc, 0);

	rc = hltests_wait_for_cs(fd, seq, timeout);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	FREE_2D_ARR(dst_buf_va, MAX_NIC_NUMBER_OF_PORTS);

	return rc;
}

static int nic_cleanup(int fd, struct hltests_nic_in_params *in_params)
{
	void *cb, *host_buf;
	int rc = 0;

	rc = nic_cqs_destroy(fd, in_params);
	assert_int_equal(rc, 0);

	rc = nic_wq_array_destroy(fd, in_params);
	assert_int_equal(rc, 0);

	while (1) {
		host_buf = hltests_nic_hmem_list_pop();
		if (!host_buf)
			break;

		rc = hltests_free_host_mem(fd, host_buf);
		assert_int_equal(rc, 0);
	}

	while (1) {
		cb = hltests_nic_cb_list_pop();
		if (!cb)
			break;

		rc = hltests_destroy_cb(fd, cb);
		assert_int_equal(rc, 0);
	}

	return rc;
}

int ibdev_alloc_coll_conn(struct hltests_nic_in_params *in_params, bool is_scale_out,
				uint32_t *conn)
{
	struct hbldv_coll_qp_attr coll_qp_attr = {};
	struct hbldv_coll_qp coll_qp = {};
	int rc;

	coll_qp_attr.is_scale_out = is_scale_out;

	rc = hbldv_reserve_coll_qps(in_params->ib_in_params->ibpd, &coll_qp_attr, &coll_qp);
	if (!rc)
		*conn = coll_qp.qp_num;

	return rc;
}

static int nic_create_coll_qps(struct hltests_state *tests_state,
				struct hltests_nic_conn_in *conn_in,
				struct hltests_nic_in_params *in_params, uint64_t test_port_mask,
				bool is_scale_out)
{
	struct hlthunk_nic_alloc_coll_conn_in coll_conn_in;
	uint32_t max_n_ports, coll_conn, min_coll_conn_id, max_coll_conn_id, qp_id_hint, off,
		 i, first_en_port, port, conn;
	struct hltests_nic_conn_out *conn_out;
	int fd, rc = 0;

	fd = tests_state->fd;
	max_n_ports = hltests_nic_get_max_num_of_ports(fd);
	first_en_port = (uint32_t)__builtin_ffsll((int64_t)test_port_mask) - 1;
	conn_out = in_params->nic_conn;

	coll_conn_in.is_scale_out = is_scale_out;

	min_coll_conn_id = hltests_nic_get_min_coll_conn_id(fd, is_scale_out);
	max_coll_conn_id = hltests_nic_get_max_coll_conn_id(fd, is_scale_out);

	/* get the collective QP id using the first enabled port */
	for (conn = 0 ; conn < (uint32_t)conn_in->conn_per_port[first_en_port] ; conn++) {
		for (i = 1 ; i < QP_ALLOC_RETRIES ; i++) {
			if (hltests_nic_is_ibdev(fd))
				rc = ibdev_alloc_coll_conn(in_params, is_scale_out, &coll_conn);
			else
				rc = hlthunk_alloc_coll_conn(fd, &coll_conn_in, &coll_conn);

			if (rc != -EBUSY)
				break;

			/* we may be facing a graceful QP release by the driver, so lets retry */
			sleep(i);
		}

		assert_int_equal(rc, 0);
		assert_in_range(coll_conn, min_coll_conn_id, max_coll_conn_id);

		conn_out->conn_id[first_en_port][conn] = coll_conn;
	}

	/* Go over all the ports and duplicate the collective QP id among them.
	 * For odd ports in 200G, an offset should be added.
	 */
	for (conn = 0 ; conn < (uint32_t)conn_in->conn_per_port[first_en_port] ; conn++) {
		coll_conn = conn_out->conn_id[first_en_port][conn];

		for (port = 0 ; port < max_n_ports ; port++) {
			if (!(test_port_mask & BIT_ULL(port)))
				continue;

			off = hltests_nic_get_coll_qps_offset(fd, port);
			if (hltests_nic_is_ibdev(fd)) {
				qp_id_hint = coll_conn + off;
				for (i = 1 ; i < QP_ALLOC_RETRIES ; i++) {
					rc = ibdev_alloc_conn(port, conn, in_params->ib_in_params,
								true, qp_id_hint);
					if (rc != -EBUSY)
						break;

					/*
					 * we may be facing a graceful QP release by the driver,
					 * so lets retry
					 */
					sleep(i);
				}
				assert_int_equal(rc, 0);
			} else {
				conn_out->conn_id[port][conn] = coll_conn + off;
			}
		}
	}

	return rc;
}

static int ibdev_alloc_conn(uint32_t port, uint32_t conn_idx,
			    struct hltests_nic_ib_in_params *ib_in_params,
			    bool is_coll, uint32_t qp_id_hint)
{
	struct ibv_pd *pd;
	struct ibv_qp_init_attr qp_init_attr = {};
	struct hbldv_query_qp_attr dv_qp_attr = {};
	struct hbldv_qp_attr dv_qp_init_attr = {};
	struct hltests_nic_conn_out *conn_out;
	struct ibv_qp *ibqp;
	struct ibv_qp_attr qp_attr = {};
	struct hltests_nic_in_params *nic_in_params;
	int rc;
	void *cfg = ib_in_params->cfg;
	struct hltests_nic_cq *cqs = ib_in_params->cqs;
	uint32_t user_cq_idx;
	struct hltests_nic_port_cq *port_cq;
	enum hltests_nic_cmpl cmpl;
	struct hltests_nic_requester_conn_ctx *req_ctx;
	bool is_rdv, force_nwq;

	nic_in_params = ib_in_params->in_params;

	user_cq_idx = (nic_in_params->test == LPBK) ?
			((struct hltests_nic_lpbk_cfg *) cfg)->user_cq_idx :
				((struct hltests_nic_e2e_cfg *) cfg)->user_cq_idx;

	cmpl = (nic_in_params->test == LPBK) ?
			((struct hltests_nic_lpbk_cfg *) cfg)->cmpl :
				((struct hltests_nic_e2e_cfg *) cfg)->cmpl;

	is_rdv = (nic_in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE) ||
			(nic_in_params->test_opcode == TEST_OPCODE_RENDEZVOUS_READ);

	conn_out = nic_in_params->nic_conn;
	pd = ib_in_params->ibpd;
	port_cq = &cqs[user_cq_idx].user_cq.port_cq[port];
	req_ctx = &nic_in_params->nic_ctx->req_ctx[port][conn_idx];
	force_nwq = is_rdv ? false : !!nic_in_params->bp_offs;

	nic_setup_ctx_wqe_index(ib_in_params->fd, req_ctx, cmpl, nic_in_params->nwq, is_rdv,
				is_rdv ? conn_idx & 1 : false, force_nwq);

	/* 1. Create QP in RESET state. */

	/* Set requestor and responder CQ. Note, test configures
	 * same CQ for both.
	 */
	qp_init_attr.send_cq = port_cq->ibvcq;
	qp_init_attr.recv_cq = port_cq->ibvcq;

	/* Reliable connection. */
	qp_init_attr.qp_type = IBV_QPT_RC;

	qp_init_attr.cap.max_send_wr = req_ctx->wq_size;

	ibqp = hlibv_create_qp(pd, &qp_init_attr);
	assert_non_null(ibqp);

	/* 2. Transition QP from RESET to INIT state. */

	qp_attr.qp_state = IBV_QPS_INIT;
	qp_attr.port_num = (uint8_t)hltests_nic_to_ibdev_port_num(ib_in_params->fd, port);

	/* Check if the requested QP is of collective type */
	if (is_coll) {
		dv_qp_init_attr.caps |= HBLDV_QP_CAP_COLL;
		dv_qp_init_attr.qp_num_hint = qp_id_hint;
	}

	dv_qp_init_attr.wq_type = req_ctx->wq_type;
	dv_qp_init_attr.wq_granularity = req_ctx->swq_granularity;

	/* Partition key. Though we support only one partition,
	 * it's a mandatory field for IB QP RESET to INIT transition.
	 */
	qp_attr.pkey_index = 0;

	qp_attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE;
	rc = hbldv_modify_qp(ibqp, &qp_attr,
			IBV_QP_STATE | IBV_QP_PKEY_INDEX |
			IBV_QP_PORT | IBV_QP_ACCESS_FLAGS,
			&dv_qp_init_attr);

	conn_out->ibqp[port][conn_idx] = ibqp;

	hbldv_query_qp(ibqp, &dv_qp_attr);
	conn_out->conn_id[port][conn_idx] = dv_qp_attr.qp_num;

	return rc;
}

static int nic_create_qps(struct hltests_state *tests_state, struct hltests_nic_conn_in *conn_in,
				struct hltests_nic_in_params *in_params, uint64_t test_port_mask)
{
	struct hltests_nic_conn_out *conn_out;
	uint32_t max_n_ports, min_conn_id, max_conn_id, i, port, conn;
	int fd, rc = 0;

	fd = tests_state->fd;
	max_n_ports = hltests_nic_get_max_num_of_ports(fd);
	conn_out = in_params->nic_conn;

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(test_port_mask & BIT_ULL(port)))
			continue;

		min_conn_id = (uint32_t)hltests_nic_get_min_conn_id(fd, port);
		max_conn_id = (uint32_t)hltests_nic_get_max_conn_id(fd, port);

		for (conn = 0 ; conn < (uint32_t)conn_in->conn_per_port[port] ; conn++) {
			for (i = 1 ; i < QP_ALLOC_RETRIES ; i++) {
				if (hltests_nic_is_ibdev(fd))
					rc = ibdev_alloc_conn(port, conn, in_params->ib_in_params,
								false, 0);
				else
					rc = hlthunk_alloc_conn(fd, port,
								&conn_out->conn_id[port][conn]);

				if (rc != -EBUSY)
					break;

				/* we may be facing a graceful QP release by the driver
				 * so lets retry
				 */
				sleep(i);
			}

			assert_int_equal(rc, 0);
			assert_in_range(conn_out->conn_id[port][conn], min_conn_id, max_conn_id);
		}
	}

	return rc;
}

static int ibdev_destroy_conn(uint32_t port, uint32_t conn_idx,
			      struct hltests_nic_ib_in_params *ib_in_params)
{
	struct ibv_qp *ibqp;
	struct hltests_nic_in_params *nic_in_params;
	struct hltests_nic_conn_out *nic_conn;

	nic_in_params = ib_in_params->in_params;
	nic_conn = nic_in_params->nic_conn;
	ibqp = nic_conn->ibqp[port][conn_idx];

	return hlibv_destroy_qp(ibqp);
}

static int nic_destroy_qps(struct hltests_state *tests_state, struct hltests_nic_conn_in *conn_in,
				struct hltests_nic_contexts *nic_ctx,
				struct hltests_nic_in_params *in_params, uint64_t port_mask)
{
	struct hltests_nic_conn_out *conn_out;
	uint32_t max_n_ports, conn_id, conn_id_offset, wq_nwq, nwq, munmap_num_wqes, swq_size,
		rwq_size, port, conn, max_conn = 0;
	int fd, rc = 0;

	fd = tests_state->fd;
	conn_out = in_params->nic_conn;
	max_n_ports = hltests_nic_get_max_num_of_ports(fd);
	nwq = in_params->nwq;
	wq_nwq = nwq < WQES_MIN ? WQES_MIN : nwq;

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		if (max_conn < (uint32_t)conn_in->conn_per_port[port])
			max_conn = (uint32_t)conn_in->conn_per_port[port];
	}

	for (conn = 0 ; conn < max_conn ; conn++) {
		for (port = 0 ; port < max_n_ports ; port++) {
			if (!(port_mask & BIT_ULL(port)) || conn >=
			     (uint32_t)conn_in->conn_per_port[port])
				continue;

			conn_id = conn_out->conn_id[port][conn];

			if (!in_params->wtd_en && !in_params->coll_op) {
				munmap_num_wqes = hltests_is_gaudi(fd) ?
						nic_ctx->req_ctx[port][conn].last_index + 1 :
						nic_ctx->req_ctx[port][conn].wq_size;

				swq_size = munmap_num_wqes * hltests_nic_get_swqe_size(fd);
				conn_id_offset = conn_id -
						hltests_nic_get_wq_offset(fd, (int)port, conn_id);

				if (!hltests_nic_is_ibdev(fd)) {
					rc = hltests_munmap(fd,
							conn_out->swq_buf[port][conn_id_offset],
							swq_size);
					assert_int_equal(rc, 0);
				}

				rwq_size = munmap_num_wqes * hltests_nic_get_rwqe_size(fd);

				if (!hltests_nic_is_ibdev(fd)) {
					rc = hltests_munmap(fd,
							conn_out->rwq_buf[port][conn_id_offset],
							rwq_size);
					assert_int_equal(rc, 0);
				}
			}

			if (hltests_nic_is_ibdev(fd))
				rc = ibdev_destroy_conn(port, conn, in_params->ib_in_params);
			else
				rc = hlthunk_destroy_conn(fd, port, conn_id);
			assert_int_equal(rc, 0);
		}
	}

	return rc;
}

static union hltests_nic_encap **alloc_encap_ids(void **state,
						struct hltests_nic_config_encap_params *cfg)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd;
	union hltests_nic_encap **encap_data;
	uint32_t i, j, port;
	int rc;

	ALLOC_2D_ARR_RET_PTR(encap_data, MAX_NIC_NUMBER_OF_PORTS, cfg->max_qps_per_port);

	if (hltests_nic_is_ibdev(fd))
		/* For IBV only allocate empty array, IDs will be populated by
		 * hbldv_create_encap().
		 */
		goto ret;

	for (i = 0 ; i < cfg->ports_num ; i++) {
		port = cfg->ports[i];
		if (!(cfg->port_mask & BIT_ULL(port)))
			continue;

		for (j = 0 ; j < cfg->qps_per_port[i] ; j++) {
			rc = hlthunk_nic_user_encap_alloc(fd, port, &encap_data[port][j].id);
			assert_int_equal_ret_ptr(rc, 0);
		}
	}

ret:
	return encap_data;
}

static union hltests_nic_encap **alloc_encap_ids_lpbk(void **state,
							struct hltests_nic_lpbk_cfg *cfg,
							uint64_t port_mask)
{
	struct hltests_nic_config_encap_params encap_cfg;

	encap_cfg.qps_per_port = cfg->qps_per_port;
	encap_cfg.ports = cfg->ports;
	encap_cfg.max_qps_per_port = cfg->max_qps_per_port;
	encap_cfg.port_mask = port_mask;
	encap_cfg.ports_num = cfg->ports_num;
	encap_cfg.src_ip_addr = cfg->src_ip_addr;
	encap_cfg.encap_type = cfg->encap_type;

	return alloc_encap_ids(state, &encap_cfg);
}

static union hltests_nic_encap **alloc_encap_ids_e2e(void **state, struct hltests_nic_e2e_cfg *cfg,
							uint64_t port_mask)
{
	struct hltests_nic_config_encap_params encap_cfg;

	encap_cfg.qps_per_port = cfg->qps_per_port;
	encap_cfg.ports = cfg->ports;
	encap_cfg.max_qps_per_port = cfg->max_qps_per_port;
	encap_cfg.port_mask = port_mask;
	encap_cfg.ports_num = cfg->ports_num;
	encap_cfg.src_ip_addr = cfg->src_ip_addr;
	encap_cfg.encap_type = cfg->encap_type;

	return alloc_encap_ids(state, &encap_cfg);
}

static VOID config_encap(void **state, union hltests_nic_encap **encap_data,
				struct hltests_nic_contexts *nic_ctx,
				struct hltests_nic_config_encap_params *cfg,
				struct hltests_nic_in_params *in_params)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hbldv_encap_attr encap_attr = {};
	struct hlthunk_encap_cfg encap_cfg;
	struct hltests_nic_vxlan_header vxlan_hdr;
	struct hltests_nic_gre_header gre_hdr;
	uint32_t vxlan_hdr_size;
	int fd = tests_state->fd, rc;
	uint32_t i, j, port;

	vxlan_hdr_size = hltests_is_gaudi2(fd) ? NIC_MAX_TNL_HDR_SIZE : sizeof(vxlan_hdr);

	for (i = 0 ; i < cfg->ports_num ; i++) {
		port = cfg->ports[i];
		if (!(cfg->port_mask & BIT_ULL(port)))
			continue;

		for (j = 0 ; j < cfg->qps_per_port[i] ; j++) {
			memset(&encap_cfg, 0, sizeof(encap_cfg));
			memset(&vxlan_hdr, 0, sizeof(vxlan_hdr));
			memset(&gre_hdr, 0, sizeof(gre_hdr));

			encap_cfg.port = port;
			encap_cfg.id = encap_data[port][j].id;
			encap_cfg.encap_type = cfg->encap_type;

			if (hltests_nic_is_ibdev(fd)) {
				encap_attr.port_num = hltests_nic_to_ibdev_port_num(fd, port);
				encap_attr.encap_type = cfg->encap_type;
			}

			switch (encap_cfg.encap_type) {
			case HL_NIC_ENCAP_NONE:
				if (hltests_nic_is_ibdev(fd))
					encap_attr.ipv4_addr = cfg->src_ip_addr;
				else
					encap_cfg.src_ipv4_addr = cfg->src_ip_addr;
				break;

			case HL_NIC_ENCAP_OVER_UDP:
			case HL_NIC_ENCAP_OVER_IPV4:
				if (encap_cfg.encap_type == HL_NIC_ENCAP_OVER_UDP) {
					hltests_nic_build_vxlan_header(&vxlan_hdr);

					if (hltests_nic_is_ibdev(fd)) {
						encap_attr.udp_dst_port = VXLAN_PORT_NUM;
						encap_attr.tnl_hdr_size = vxlan_hdr_size;
						encap_attr.tnl_hdr_ptr = (uint64_t) &vxlan_hdr;
					} else {
						encap_cfg.udp_dst_port = VXLAN_PORT_NUM;
						encap_cfg.tnl_hdr_size = vxlan_hdr_size;
						encap_cfg.tnl_hdr_ptr = (uint64_t) &vxlan_hdr;
					}
				} else if (encap_cfg.encap_type == HL_NIC_ENCAP_OVER_IPV4) {
					hltests_nic_build_gre_header(&gre_hdr);

					if (hltests_nic_is_ibdev(fd)) {
						encap_attr.ip_proto = GRE_PROTOCOL_NUMBER;
						encap_attr.tnl_hdr_size = sizeof(gre_hdr);
						encap_attr.tnl_hdr_ptr = (uint64_t) &gre_hdr;
					} else {
						encap_cfg.ip_proto = GRE_PROTOCOL_NUMBER;
						encap_cfg.tnl_hdr_size = sizeof(gre_hdr);
						encap_cfg.tnl_hdr_ptr = (uint64_t) &gre_hdr;
					}
				}
				break;

			default:
				break;
			}

			if (hltests_nic_is_ibdev(fd)) {
				encap_data[port][j].hbl_encap =
					hbldv_create_encap(in_params->ib_in_params->ibctx,
								&encap_attr);
				assert_non_null(encap_data[port][j].hbl_encap);
			} else {
				rc = hlthunk_nic_user_encap_set(fd, &encap_cfg);
				assert_int_equal(rc, 0);
			}

			/* Encapsulation at QP level should be enabled if its either an UDP/IP
			 * encap, if no encap is needed just set the src IP addr
			 */

			if (hltests_nic_is_ibdev(fd)) {
				nic_ctx->req_ctx[port][j].encap_id = (uint8_t)
							encap_data[port][j].hbl_encap->encap_num;
				nic_ctx->res_ctx[port][j].encap_id = (uint8_t)
							encap_data[port][j].hbl_encap->encap_num;
			} else {
				nic_ctx->req_ctx[port][j].encap_id = (uint8_t)
									encap_data[port][j].id;
				nic_ctx->res_ctx[port][j].encap_id = (uint8_t)
									encap_data[port][j].id;
			}

			if (cfg->encap_type != HL_NIC_ENCAP_NONE) {
				nic_ctx->req_ctx[port][j].encap_en = 1;
				nic_ctx->res_ctx[port][j].encap_en = 1;
			}
		}
	}

	END_TEST;
}

static VOID config_encap_lpbk(void **state, union hltests_nic_encap **encap_data,
				struct hltests_nic_contexts *nic_ctx,
				struct hltests_nic_lpbk_cfg *cfg,
				struct hltests_nic_in_params *in_params, uint64_t port_mask)
{
	struct hltests_nic_config_encap_params encap_cfg;

	encap_cfg.qps_per_port = cfg->qps_per_port;
	encap_cfg.ports = cfg->ports;
	encap_cfg.port_mask = port_mask;
	encap_cfg.ports_num = cfg->ports_num;
	encap_cfg.src_ip_addr = cfg->src_ip_addr;
	encap_cfg.encap_type = cfg->encap_type;

	config_encap(state, encap_data, nic_ctx, &encap_cfg, in_params);
	END_TEST;
}

static VOID config_encap_e2e(void **state, union hltests_nic_encap **encap_data,
				struct hltests_nic_contexts *nic_ctx,
				struct hltests_nic_e2e_cfg *cfg,
				struct hltests_nic_in_params *in_params, uint64_t port_mask)
{
	struct hltests_nic_config_encap_params encap_cfg;

	encap_cfg.qps_per_port = cfg->qps_per_port;
	encap_cfg.ports = cfg->ports;
	encap_cfg.max_qps_per_port = cfg->max_qps_per_port;
	encap_cfg.port_mask = port_mask;
	encap_cfg.ports_num = cfg->ports_num;
	encap_cfg.src_ip_addr = cfg->src_ip_addr;
	encap_cfg.encap_type = cfg->encap_type;

	config_encap(state, encap_data, nic_ctx, &encap_cfg, in_params);
	END_TEST;
}

static VOID destroy_encap(void **state, union hltests_nic_encap **encap_data,
				struct hltests_nic_config_encap_params *cfg,
				struct hltests_nic_in_params *in_params)
{
	uint32_t i, j, port;
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	int fd = tests_state->fd, rc;

	for (i = 0 ; i < cfg->ports_num ; i++) {
		port = cfg->ports[i];
		if (!(cfg->port_mask & BIT_ULL(port)))
			continue;

		for (j = 0 ; j < cfg->qps_per_port[i] ; j++) {
			if (hltests_nic_is_ibdev(fd))
				rc = hbldv_destroy_encap(encap_data[port][j].hbl_encap);
			else
				rc = hlthunk_nic_user_encap_unset(fd, port, encap_data[port][j].id);

			assert_int_equal(rc, 0);
		}
	}

	FREE_2D_ARR(encap_data, MAX_NIC_NUMBER_OF_PORTS);

	END_TEST;
}

static VOID destroy_encap_lpbk(void **state, union hltests_nic_encap **encap_data,
				struct hltests_nic_lpbk_cfg *cfg,
				struct hltests_nic_in_params *in_params, uint64_t port_mask)
{
	struct hltests_nic_config_encap_params encap_cfg;

	encap_cfg.qps_per_port = cfg->qps_per_port;
	encap_cfg.ports = cfg->ports;
	encap_cfg.max_qps_per_port = cfg->max_qps_per_port;
	encap_cfg.port_mask = port_mask;
	encap_cfg.ports_num = cfg->ports_num;
	encap_cfg.src_ip_addr = cfg->src_ip_addr;
	encap_cfg.encap_type = cfg->encap_type;

	destroy_encap(state, encap_data, &encap_cfg, in_params);

	END_TEST;
}

static VOID destroy_encap_e2e(void **state, union hltests_nic_encap **encap_data,
				struct hltests_nic_e2e_cfg *cfg,
				struct hltests_nic_in_params *in_params, uint64_t port_mask)
{
	struct hltests_nic_config_encap_params encap_cfg;

	encap_cfg.qps_per_port = cfg->qps_per_port;
	encap_cfg.ports = cfg->ports;
	encap_cfg.max_qps_per_port = cfg->max_qps_per_port;
	encap_cfg.port_mask = port_mask;
	encap_cfg.ports_num = cfg->ports_num;
	encap_cfg.src_ip_addr = cfg->src_ip_addr;
	encap_cfg.encap_type = cfg->encap_type;

	destroy_encap(state, encap_data, &encap_cfg, in_params);

	END_TEST;
}

static void *ibdev_create_cc_cqs(struct hltests_nic_in_params *in_params,
					struct hltests_nic_ccq ccqs[], uint32_t ccq_buf_len,
					uint32_t max_n_ports, uint64_t port_mask,
					struct hltests_nic_db_fifo_data **db_fifos)
{
	struct hltests_nic_ib_in_params *ib_in_params = in_params->ib_in_params;
	struct hbldv_query_cq_attr cq_query_attr = {};
	struct hbldv_cq_attr cq_attr = {};
	struct ibv_cq *ibvcq;
	uint32_t port;
	int rc;

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		cq_attr.port_num = (uint8_t)hltests_nic_to_ibdev_port_num(ib_in_params->fd,
				   port);
		cq_attr.cq_type = HBLDV_CQ_TYPE_CC;

		ibvcq = hbldv_create_cq(ib_in_params->ibctx, (int)ccq_buf_len, NULL, 0, &cq_attr);
		assert_non_null_ret_ptr(ibvcq);

		rc = hbldv_query_cq(ibvcq, &cq_query_attr);
		assert_int_equal_ret_ptr(rc, 0);

		ccqs[port].ibvcq = cq_query_attr.ibvcq;
		ccqs[port].cc_sq = db_fifos[port];
		ccqs[port].ccq_buf = cq_query_attr.mem_cpu_addr;
		ccqs[port].ccq_buf_len = ccq_buf_len;
		ccqs[port].ccq_pi_mem = cq_query_attr.pi_cpu_addr;
	}

	return NULL;
}

static int ibdev_destroy_cc_cqs(struct hltests_nic_ccq ccqs[],
				uint32_t max_n_ports, uint64_t port_mask)
{
	uint32_t port;
	int rc;

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		if (!ccqs[port].ccq_buf)
			continue;

		rc = hlibv_destroy_cq(ccqs[port].ibvcq);
		assert_int_equal(rc, 0);
	}

	return 0;
}

static void nic_cc_cqs_create(int fd, struct hltests_nic_in_params *in_params,
			      struct hltests_nic_ccq ccqs[], uint32_t ccq_buf_len,
			      uint32_t max_n_ports, uint64_t port_mask,
			      struct hltests_nic_db_fifo_data **db_fifos)
{
	if (hltests_nic_is_ibdev(fd))
		ibdev_create_cc_cqs(in_params, ccqs, ccq_buf_len, max_n_ports, port_mask,
					db_fifos);
	else
		hltests_nic_ccqs_create(fd, ccqs, ccq_buf_len, (int)max_n_ports, port_mask,
					db_fifos);
}

void nic_cc_cqs_destroy(int fd, struct hltests_nic_ccq ccqs[], uint32_t max_n_ports,
			uint64_t port_mask)
{
	if (hltests_nic_is_ibdev(fd))
		ibdev_destroy_cc_cqs(ccqs, max_n_ports, port_mask);
	else
		hltests_nic_ccqs_destroy(fd, ccqs, (int)max_n_ports, port_mask);
}

static int nic_post_cc(struct hltests_state *tests_state, struct hltests_nic_ccqs_poll_info *info,
			bool add_swift_msg, struct hltests_nic_conn_out *qp_conn)
{
	uint32_t port;

	for (port = 0 ; port < (int)info->max_n_ports ; port++) {
		if (!(info->port_mask & BIT_ULL(port)))
			continue;

		/* Only 1 QP is used in CC test */
		assert_int_equal(hltests_nic_post_cc(tests_state, info, port, add_swift_msg,
							qp_conn->conn_id[port][0]), 0);
	}

	return 0;
}

int nic_ccqs_poll(int fd, struct hltests_nic_ccqs_poll_info *info,
			struct hltests_nic_conn_out *qp_conn,
			struct hltests_nic_in_params *in_params)
{
	struct hltests_nic_ccq *ccqs = info->ccqs;
	uint32_t poll_ccqes_retries = 10;
	uint64_t run_over_ports_mask = 0;
	uint64_t got_cqe_port_mask = 0;
	uint64_t missing_cqe_port_mask;
	uint32_t port;
	int rc;

	while ((got_cqe_port_mask != info->port_mask) && poll_ccqes_retries) {
		/* Don't run over ports which already got CQE */
		run_over_ports_mask = (info->port_mask ^ (got_cqe_port_mask)) & info->port_mask;
		for (port = 0 ; port < (uint32_t)info->max_n_ports ; port++) {
			if (!(run_over_ports_mask & BIT_ULL(port)))
				continue;

			rc = hltests_nic_ccq_poll(&ccqs[port], qp_conn->conn_id[port][0],
							in_params->qps_per_port[port]);
			/* ENOENT - no new element was polled, this is the only valid rc */
			if (rc == -ENOENT)
				continue;

			if (rc)
				return rc;

			got_cqe_port_mask = (got_cqe_port_mask) | BIT_ULL(port);
		}

		sleep(1);
		poll_ccqes_retries--;
	}

	missing_cqe_port_mask = got_cqe_port_mask ^ info->port_mask;
	assert_int_equal(missing_cqe_port_mask, 0);

	return 0;
}

static uint32_t calc_nwq(int fd, uint64_t data_size, uint32_t wqe_size, uint32_t max_qps_per_port,
				enum hltests_nic_cmpl cmpl, uint8_t user_db)
{
	uint32_t nwq = (uint32_t)(data_size / wqe_size);

	/* Workaround for [SW-86679] - Multiply wq size by 2 if the conditions below apply.
	 * Root cause:
	 *
	 * When using SOBs with multiple QPs, we use 1 SOB for all QPs in the port. This means we
	 * have no way of telling how many SOBs came from each QP, as 1 QP may produce several SOBs,
	 * while the other QP didn't produce any SOBs in the same time.
	 * When the WQ size is exactly 'data_size/wqe_size', the last PI updated would be 0. This
	 * can cause a case where WQ PI is updated to 0, before any progress has been made in this
	 * QP. This will result in CI==PI==0, meaning no WQE will be taken from the WQ, as it seems
	 * to be empty.
	 * In order to overcome this, the WQ size is increased (multiplied by 2). Then, the last PI
	 * updated will not be 0, but rather 'data_size/wqe_size'. This will ensure the WQ does not
	 * appear as empty.
	 *
	 * Please note that the above is correct only when the number of iterations is 1.
	 */
	if (hltests_is_gaudi2(fd) && (max_qps_per_port > 1) && (cmpl == SOB) && user_db)
		nwq *= 2;

	return nwq;
}

VOID test_nic_e2e_lpbk_aux(void **state, struct hltests_nic_in_params *in_params,
				struct hltests_nic_lpbk_cfg *cfg)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_nic_get_ports_masks_out ports_masks;
	struct hlthunk_time_sync_info begin, end;
	struct hltests_nic_conn_in *conn_in = NULL;
	struct hltests_nic_conn_out *conn_out = NULL;
	struct hltests_nic_contexts *nic_ctx = NULL;
	struct hltests_nic_coll_comm_group *comm_group = NULL;
	struct hltests_nic_ccqs_poll_info ccq_poll_info = {};
	struct hltests_nic_asic_funcs *nic_funcs;
	struct hltests_nic_user_fifo_params fifo_params;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	struct hltests_device *hdev;
	union hltests_nic_encap **encap_data = NULL;
	void ***src_buf, ***dst_buf, ***dst_buf_ref, ***dwq_swqe = NULL, ***dwq_rwqe = NULL,
		*local_fna_op_addr = NULL;
	uint64_t data_size = 1ull << cfg->data_size_shift, sob_addr,
		sob_base_addr, seq, reduction_cfg = 0, test_port_mask = in_params->port_mask,
		cc_port_mask = 0, swq_size, rwq_size;
	double bw;
	int rc, fd = tests_state->fd;
	uint32_t max_n_ports = hltests_nic_get_max_num_of_ports(fd),
		max_n_qps = MAX_NUM_OF_QPS, wqe_size = 1 << cfg->wqe_size_shift,
		nwq = in_params->nwq, *tag, num_of_tags = nwq * max_n_ports * max_n_qps,
		qps_per_port = 0, wq_nwq, sm_obj_size, max_coll_comm_groups, used_sobs, i, j,
		n_db_fifos = 1, iterations_db = cfg->iterations_db, port_idx;

	uint16_t first_sob;
	enum hltests_nic_cmpl cmpl = cfg->cmpl;
	enum hltests_nic_verbose_level verbose = cfg->verbose;
	bool data_cmp = cfg->data_cmp, single_alloc = cfg->single_alloc, cleanup = cfg->cleanup,
		wait_for_cleanup = cfg->wait_for_cleanup, db_qman = cfg->db_qman,
		wtd_en = cfg->wtd_en, is_rdv = false, is_wr_rdv = false,
		is_rd_rdv = false, encap_en = false, upscale_en, downscale_en, odp;
	struct hltests_nic_ccq ccqs[max_n_ports];
	struct hltests_nic_db_fifo_data **db_fifos = NULL, **ccq_db_fifos = NULL;
	uint8_t send_wqe_size, rcv_wqe_size;
	uint8_t *sm_obj_base = NULL;

	clock_gettime(CLOCK_MONOTONIC_RAW, &in_params->base);

	hdev = get_hdev_from_fd(fd);
	nic_funcs = hdev->asic_funcs->nic_funcs;

	upscale_en = (cfg->red_dt == HLTESTS_NIC_REDUCTION_UPSCALING_BF16);
	downscale_en = (cfg->red_dt == HLTESTS_NIC_REDUCTION_DOWNSCALING_TO_BF16);
	if (cfg->reduction_en) {
		rc = hltests_nic_config_reduction(fd, cfg->red_op, cfg->red_dt, &reduction_cfg);
		assert_int_equal(rc, 0);
	}

	ALLOC_2D_ARR(src_buf, max_n_ports, max_n_qps);
	ALLOC_2D_ARR(dst_buf, max_n_ports, max_n_qps);
	ALLOC_2D_ARR(dst_buf_ref, max_n_ports, max_n_qps);

	nic_ctx = hlthunk_malloc(sizeof(*nic_ctx));
	assert_non_null(nic_ctx);
	conn_in = hlthunk_malloc(sizeof(*conn_in));
	assert_non_null(conn_in);
	conn_out = hlthunk_malloc(sizeof(*conn_out));
	assert_non_null(conn_out);
	tag = hlthunk_malloc(sizeof(*tag) * num_of_tags);
	assert_non_null(tag);

	max_coll_comm_groups = (cfg->coll_type == COLL_TYPE_DIRECT) ?
					MAX_COLL_COMM_GROUPS_DIRECT : MAX_COLL_COMM_GROUPS;
	comm_group = hlthunk_malloc(sizeof(*comm_group) * max_coll_comm_groups);
	assert_non_null(comm_group);

	if (cfg->test_opcode == TEST_OPCODE_ATOMIC_FETCH_ADD) {
		uint64_t fna_val_alloc_size = 0;

		if (cfg->atomic_val_loc == AFA_OP_DRAM) {
			fna_val_alloc_size = hltests_get_cache_line_size(fd);
			local_fna_op_addr = hltests_allocate_device_mem(fd, fna_val_alloc_size, 0,
										CONTIGUOUS);
			assert_non_null(local_fna_op_addr);

			in_params->fna_op_addr = (uint64_t) ((uint64_t *) local_fna_op_addr);
		} else if (cfg->atomic_val_loc == AFA_OP_SRAM) {
			in_params->fna_op_addr = hw_ip->sram_base_address;
			fna_val_alloc_size = sizeof(uint32_t);
		}

		rc = dma_reset_fna_op_mem(fd, in_params->fna_op_addr,
					  (uint32_t)fna_val_alloc_size);
		assert_int_equal(rc, 0);
	}

	if ((cfg->test_opcode == TEST_OPCODE_ATOMIC_FETCH_ADD && cfg->fna_cmpl == AFA_REG_CMPL) ||
		cfg->bp_offs) {
		sm_obj_base = nic_funcs->map_lbw_block(fd, &sm_obj_size);
		assert_non_null(sm_obj_base);

		if (cfg->fna_cmpl == AFA_REG_CMPL)
			nic_funcs->clear_lbw_memory(fd, sm_obj_base, FNA_MON_ID,
							AFA_MAX_NUM_OF_CMPL_REGS);

		if (cfg->bp_offs)
			nic_funcs->clear_lbw_memory(fd, sm_obj_base, BP_MON_ID,
							MAX_NUM_OF_BP_OFFSETS);
	}

	if (cfg->db_fifo_mode == HL_NIC_DB_FIFO_TYPE_DWQ_LIN || cfg->coll_op) {
		uint32_t max_wqs_per_port = in_params->max_qps_per_port + 1;

		/* We enter here only if user_db and wtd_en enabled which is possible only in G3 */
		wq_nwq = nwq < WQES_MIN ? WQES_MIN : nwq;
		send_wqe_size = hltests_nic_get_swqe_size(fd);
		rcv_wqe_size = hltests_nic_get_rwqe_size(fd);

		swq_size = max_wqs_per_port * ((uint64_t) wq_nwq) * send_wqe_size;
		rwq_size = max_wqs_per_port * ((uint64_t) wq_nwq) * rcv_wqe_size;

		ALLOC_2D_ARR(dwq_swqe, max_n_ports, swq_size);
		ALLOC_2D_ARR(dwq_rwqe, max_n_ports, rwq_size);

		in_params->swqe_arr = dwq_swqe;
		in_params->rwqe_arr = dwq_rwqe;
	}

	if (cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
		is_wr_rdv = true;
	else if (cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ)
		is_rd_rdv = true;

	is_rdv = is_wr_rdv || is_rd_rdv;

	encap_en = cfg->encap_type || cfg->src_ip_addr;

	odp = cfg->odp;

	hltests_fill_rand_values(tag, sizeof(uint32_t) * num_of_tags);

	hltests_nic_print_time_elapsed(&in_params->base, "initial setup", verbose);

	sob_base_addr = hltests_get_sob_base_addr(fd);
	first_sob = hltests_get_first_avail_sob(fd);

	for (i = 0 ; i < cfg->ports_num ; i++) {
		port_idx = cfg->ports[i];
		qps_per_port = in_params->qps_per_port[port_idx];

		for (j = 0 ; j < qps_per_port ; j++) {
			if (single_alloc && j) {
				src_buf[port_idx][j] = src_buf[port_idx][0];
				dst_buf[port_idx][j] = dst_buf[port_idx][0];

				in_params->src_buf[port_idx][j] = src_buf[port_idx][j];
				in_params->dst_buf[port_idx][j] = dst_buf[port_idx][j];
				continue;
			}
			conn_in->conn_per_port[port_idx] = (int)qps_per_port;

			if (odp)
				src_buf[port_idx][j] = hltests_allocate_host_mem_aligned_flags(fd,
							data_size, NOT_HUGE_MAP, 0, HL_MEM_ODP);
			else
				src_buf[port_idx][j] = hltests_allocate_host_mem(fd, data_size,
										NOT_HUGE_MAP);

			assert_non_null(src_buf[port_idx][j]);
			rc = hltests_nic_hmem_list_push(src_buf[port_idx][j]);
			assert_int_equal(rc, 0);

			if (cfg->red_dt == HLTESTS_NIC_REDUCTION_BF16 || upscale_en)
				fill_buffer_bfloat16(src_buf[port_idx][j], data_size);
			else if (cfg->red_dt == HLTESTS_NIC_REDUCTION_FP32 || downscale_en ||
					cfg->red_dt == HLTESTS_NIC_REDUCTION_BF16_DOWN_AND_UP)
				fill_buffer_fp32(src_buf[port_idx][j], data_size);
			else {
				hltests_fill_rand_values(src_buf[port_idx][j], data_size);
				if (cfg->plain_rdma) {
					uint64_t *src_guard = (uint64_t *)
							((uint8_t *) src_buf[port_idx][j] +
							(data_size - PLAIN_RDMA_MAGIC_SIZE));

					*src_guard = PLAIN_RDMA_MAGIC;
				}
			}


			if (odp)
				dst_buf[port_idx][j] = hltests_allocate_host_mem_aligned_flags(fd,
							in_params->dst_data_size, NOT_HUGE_MAP, 0,
							HL_MEM_ODP);
			else
				dst_buf[port_idx][j] = hltests_allocate_host_mem(fd,
							in_params->dst_data_size, NOT_HUGE_MAP);

			assert_non_null(dst_buf[port_idx][j]);
			rc = hltests_nic_hmem_list_push(dst_buf[port_idx][j]);
			assert_int_equal(rc, 0);

			if (reduction_cfg == 0) {
				memset(dst_buf[port_idx][j], 0xFF, in_params->dst_data_size);
			} else {
				if (cfg->red_dt == HLTESTS_NIC_REDUCTION_BF16)
					fill_buffer_bfloat16(dst_buf[port_idx][j], data_size);
				else if (cfg->red_dt == HLTESTS_NIC_REDUCTION_FP32 ||
					cfg->red_dt == HLTESTS_NIC_REDUCTION_BF16_DOWN_AND_UP)
					fill_buffer_fp32(dst_buf[port_idx][j], data_size);
				else if (upscale_en)
					fill_buffer_fp32(dst_buf[port_idx][j],
								in_params->dst_data_size);
				else if (downscale_en)
					/* we are filling to half the size because upon downscale
					 * the total data size would be halved
					 */
					fill_buffer_bfloat16(dst_buf[port_idx][j],
								in_params->dst_data_size);
				else
					hltests_fill_rand_values(dst_buf[port_idx][j], data_size);

				dst_buf_ref[port_idx][j] = hltests_allocate_host_mem(fd,
									in_params->dst_data_size,
									NOT_HUGE_MAP);

				rc = hltests_nic_hmem_list_push(dst_buf_ref[port_idx][j]);
				assert_int_equal(rc, 0);

				assert_non_null(dst_buf_ref[port_idx][j]);
				memset(dst_buf_ref[port_idx][j], 0x0, in_params->dst_data_size);

				if (is_wr_rdv && j)
					calc_reduction_reference(src_buf[port_idx][j],
							dst_buf[port_idx][j - 1],
							dst_buf_ref[port_idx][j - 1],
							data_size, cfg->red_dt,
							cfg->red_op);
				else
					calc_reduction_reference(src_buf[port_idx][j],
								dst_buf[port_idx][j],
								dst_buf_ref[port_idx][j],
								data_size, cfg->red_dt,
								cfg->red_op);
			}

			in_params->src_buf[port_idx][j] = src_buf[port_idx][j];
			in_params->dst_buf[port_idx][j] = dst_buf[port_idx][j];
			in_params->dst_buf_ref[port_idx][j] = dst_buf_ref[port_idx][j];
		}
	}

	/* H6-3280: Set the port mask for CC - in Gaudi2 the CC test should run only on the
	 * external ports as congestion window is disabled on internal ports.
	 */
	cc_port_mask = test_port_mask;

	if (hltests_is_gaudi2(fd)) {
		rc = hlthunk_nic_get_ports_masks(fd, &ports_masks);
		assert_int_equal(rc, 0);

		cc_port_mask &= ports_masks.ext_ports_mask;
	}

	/* Set input parameters */
	in_params->cc_port_mask = cc_port_mask;
	in_params->nic_conn = conn_out;
	in_params->tag = tag;
	in_params->tag_buf_size = (sizeof(uint32_t) * num_of_tags);
	in_params->data_size = data_size;
	in_params->wqe_size = wqe_size;
	in_params->iterations = iterations_db;
	in_params->seed = 0;
	in_params->cmpl = cmpl;
	in_params->single_alloc = single_alloc;
	in_params->db_qman = db_qman;
	in_params->wtd_en = wtd_en;
	in_params->user_db = cfg->user_db;
	in_params->verbose = verbose;
	in_params->reduction_cfg = reduction_cfg;
	in_params->upscale_en = upscale_en;
	in_params->downscale_en = downscale_en;
	in_params->coll_op = cfg->coll_op;
	in_params->n_ports = (uint32_t)__builtin_popcountll(in_params->port_mask);
	in_params->fna_thresh = cfg->fna_thresh;
	in_params->comm_group = comm_group;
	in_params->max_coll_comm_groups = max_coll_comm_groups;
	in_params->compression_en = cfg->compression_en;
	in_params->coll_dt = cfg->coll_dt;
	in_params->sack_en = cfg->sack_en;
	in_params->single_cmpl = cfg->single_cmpl;
	in_params->axis_rank = cfg->axis_rank;
	in_params->number_of_ranks = cfg->number_of_ranks;
	in_params->nic_ctx = nic_ctx;
	in_params->is_plain_rdma = cfg->plain_rdma;
	in_params->disregard_rank = cfg->disregard_rank;

	hltests_nic_print_time_elapsed(&in_params->base, "alloc data", verbose);

	/*
	 * In contrary to the e2e test, here the other side is us so we don't
	 * really need to zero the SOBs before opening the QPs but we do it as a
	 * good practice.
	 * We don't apply multi SOBs on patcher mode.
	 */
	used_sobs = in_params->user_db && !in_params->coll_op
				? max_n_ports * DB_ITER_PER_CYCLE : max_n_ports;

	if (cmpl == SOB) {
		hltests_clear_sobs_offset(fd, (uint16_t)used_sobs, LOCAL_SOB_ID);
		hltests_clear_sobs_offset(fd, (uint16_t)used_sobs, REMOTE_SOB_ID);
	}

	/* DB fifo in collective mode updates CI via LBW SOBs. */
	if (in_params->coll_type)
		hltests_clear_sobs_offset(fd, (uint16_t)used_sobs, DB_FIFO_SOB_ID);

	rc = nic_wq_array_create(fd, in_params);
	assert_int_equal(rc, 0);

	rc = nic_cqs_create(fd, in_params);
	assert_int_equal(rc, 0);

	rc = nic_pre_setup_contexts(fd, cfg, nic_ctx, in_params);
	assert_int_equal(rc, 0);

	if (cfg->coll_type == COLL_TYPE_DIRECT)
		rc = nic_create_coll_qps(tests_state, conn_in, in_params, test_port_mask, true);
	else
		rc = nic_create_qps(tests_state, conn_in, in_params, test_port_mask);

	assert_int_equal(rc, 0);

	if (encap_en) {
		encap_data = alloc_encap_ids_lpbk(state, cfg, test_port_mask);
		config_encap_lpbk(state, encap_data, nic_ctx, cfg, in_params, test_port_mask);
	}

	rc = nic_setup_contexts(cfg, tests_state, conn_out, nic_ctx, in_params);
	assert_int_equal(rc, 0);

	if (cfg->coll_op) {
		db_fifos = create_user_db_fifo_ids(fd, in_params, 1, cfg->db_fifo_mode);
		in_params->db_fifos = db_fifos;
		in_params->n_db_fifos = 1;
	} else if (cfg->user_db) {
		db_fifos = create_user_db_fifo_ids(fd, in_params, n_db_fifos, cfg->db_fifo_mode);
		in_params->db_fifos = db_fifos;
		in_params->n_db_fifos = n_db_fifos;
	}

	if (cfg->cc_cq) {
		memset(ccqs, 0, sizeof(struct hltests_nic_ccq) * max_n_ports);

		ccq_db_fifos = create_user_db_fifo_ids(fd, in_params, 1, HL_NIC_DB_FIFO_TYPE_CC);

		nic_cc_cqs_create(fd, in_params, ccqs, USER_CCQ_MAX_ENTRIES, max_n_ports,
					cc_port_mask, ccq_db_fifos);
	}

	hltests_nic_print_time_elapsed(&in_params->base, "QP setup", verbose);

	rc = nic_operation(tests_state, in_params, &seq, &begin);
	assert_int_equal(rc, 0);

	hltests_nic_print_time_elapsed(&in_params->base, "send job", verbose);

	/* If we are running WTD we should skip this as we didn't create
	 * doorbell packets and we don't have pending CS.
	 */
	if (!wtd_en && !cfg->user_db) {
		if (!db_qman) {

			for (i = 0 ; i < max_n_ports ; i++) {
				if (!(test_port_mask & BIT_ULL(i)))
					continue;

				sob_addr = sob_base_addr +
						(first_sob + DB_SOB_ID + i) * 4;
				WRITE32(sob_addr, 1);
			}
		}

		/*
		 * See comment above the nic_operation function which explains
		 * why we call this function here.
		 */
		rc = hltests_wait_for_cs_until_not_busy(fd, seq);
		assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

		hltests_nic_print_time_elapsed(&in_params->base, "wait for CS", verbose);
	} else if (cfg->user_db) {
		if (cfg->data_loc != DATA_LOC_HOST) {
			uint64_t timeout = hltests_is_pldm(fd) ?
						NIC_PDMA_TIMEOUT_PLDM_USEC : NIC_PDMA_TIMEOUT_USEC;
			rc = hltests_wait_for_cs(fd, seq, timeout);
			assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);
		}

		memset(&fifo_params, 0, sizeof(struct hltests_nic_user_fifo_params));
		fifo_params.tests_state = tests_state;
		fifo_params.fifos = db_fifos;
		fifo_params.test_params = in_params;
		fifo_params.port_mask = test_port_mask;
		fifo_params.qp_ids = conn_out->conn_id;
		fifo_params.qps_per_port = in_params->qps_per_port;
		fifo_params.nwqs = nwq;
		fifo_params.max_qps_per_port = in_params->max_qps_per_port;
		fifo_params.n_fifos = (int)n_db_fifos;
		fifo_params.test_opcode = in_params->test_opcode;
		fifo_params.test_params->fna_thresh = in_params->fna_thresh;
		fifo_params.cmpl_mem_hdl = sm_obj_base;
		fifo_params.fna_op_addr = in_params->fna_op_addr;
		fifo_params.test_params->atomic_val_loc = in_params->atomic_val_loc;
		fifo_params.nic_ctx = nic_ctx;

		if (cfg->wtd_en)
			push_dwq_to_fifo(&fifo_params);
		else if (cfg->coll_op)
			nic_run_coll_op(&fifo_params);
		else
			trigger_user_db(&fifo_params);

		hltests_nic_print_time_elapsed(&in_params->base, "push data to user FIFOs",
						verbose);
	}

	if (cfg->cc_cq) {
		ccq_poll_info.ccqs = ccqs;
		ccq_poll_info.max_n_ports = (int)max_n_ports;
		ccq_poll_info.qps_per_port = qps_per_port;
		ccq_poll_info.port_mask = cc_port_mask;

		assert_int_equal(nic_post_cc(tests_state, &ccq_poll_info,
						cfg->cc_cq == CC_MODE_SWIFT, conn_out), 0);

		assert_int_equal(nic_ccqs_poll(fd, &ccq_poll_info, conn_out, in_params), 0);
	}

	if (cfg->cmpl & CQ_USR) {
		hl_nic_cq_process(state, cfg, &end, in_params);
	} else if (cmpl == SOB) {
		hl_nic_process_sob(state, cfg, &end, in_params);
	} else {
		/* don't print BW , as end time wasn't taken */
		cfg->print_bw = false;
	}

	if (in_params->is_dram || in_params->is_sram) {
		rc = nic_copy_devmem_to_host(tests_state, in_params);
		assert_int_equal(rc, 0);
	}

	hltests_nic_print_time_elapsed(&in_params->base, cmpl & CQ_USR ? "CQ" : "SOB", verbose);

	if (data_cmp) {
		nic_data_cmp(fd, in_params, max_n_ports);
		hltests_nic_print_time_elapsed(&in_params->base, "data cmp", verbose);
	}

	if (!cleanup)
		goto out;

	if (wait_for_cleanup)
		hltests_nic_wait_for_cleanup();

	/* Cleanup */
	if (cfg->cc_cq) {
		nic_cc_cqs_destroy(fd, ccqs, max_n_ports, cc_port_mask);
		destroy_user_db_fifos(fd, in_params, cc_port_mask, ccq_db_fifos, 1);
	}

	if (cfg->coll_op) {
		coll_op_comm_group_destroy_all(in_params);
		destroy_user_db_fifos(fd, in_params, test_port_mask, db_fifos, 1);
	} else if (cfg->user_db) {
		user_db_popped(fd, test_port_mask, db_fifos, n_db_fifos);
		destroy_user_db_fifos(fd, in_params, test_port_mask, db_fifos, n_db_fifos);
	}

	if (encap_en)
		destroy_encap_lpbk(state, encap_data, cfg, in_params, test_port_mask);

	rc = nic_destroy_qps(tests_state, conn_in, nic_ctx, in_params, test_port_mask);
	assert_int_equal(rc, 0);

	rc = nic_cleanup(fd, in_params);
	assert_int_equal(rc, 0);

	if (cfg->db_fifo_mode == HL_NIC_DB_FIFO_TYPE_DWQ_LIN || cfg->coll_op) {
		FREE_2D_ARR(dwq_rwqe, max_n_ports);
		FREE_2D_ARR(dwq_swqe, max_n_ports);
	}

	if ((cfg->test_opcode == TEST_OPCODE_ATOMIC_FETCH_ADD && cfg->fna_cmpl == AFA_REG_CMPL) ||
		cfg->bp_offs) {
		rc = hltests_unmap_hw_block(fd, sm_obj_base, sm_obj_size);
		assert_int_equal(rc, 0);

		if (local_fna_op_addr)
			assert_int_equal(hltests_free_device_mem(fd, local_fna_op_addr), 0);
	}

	FREE_2D_ARR(src_buf, max_n_ports);
	FREE_2D_ARR(dst_buf, max_n_ports);
	FREE_2D_ARR(dst_buf_ref, max_n_ports);
	hlthunk_free(nic_ctx);
	hlthunk_free(conn_in);
	hlthunk_free(conn_out);
	hlthunk_free(tag);
	hlthunk_free(comm_group);

	hltests_nic_print_time_elapsed(&in_params->base, "cleanup", verbose);

out:
	if (cfg->print_bw) {
		bw = get_bw_gigabit_from_timesync(data_size * qps_per_port, &begin, &end);

		printf("%sB/W: %.02lf Gb/s%s\n", KRED, bw, KNRM);
	}

	END_TEST;
}

static void print_port_mask(int fd, uint64_t port_mask)
{
	char port_mask_str[64] = {};
	uint32_t max_ports, p;
	int s = 0;

	max_ports = hltests_nic_get_max_num_of_ports(fd);
	for (p = 0 ; p < max_ports ; p++) {
		if (port_mask & BIT_ULL(p))
			s += sprintf(port_mask_str + s, "%d ", p);
	}

	printf("port-mask: %s\n", port_mask_str);
}

static void nic_fill_port_app_params(int fd, uint32_t port, enum hltests_nic_afa_cmpl_mode fna_cmpl,
					enum hltests_nic_test_opcode test_opcode,
					uint8_t plain_rdma, bool bp_offs,
					struct hlthunk_nic_user_set_app_params_in *in)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hltests_nic_asic_funcs *nic_funcs = hdev->asic_funcs->nic_funcs;
	uint32_t bp_offs_base_id, num_bp_offs, i;

	in->advanced = !plain_rdma;

	if ((fna_cmpl < AFA_CMPL_MODE_MAX) && (test_opcode == TEST_OPCODE_ATOMIC_FETCH_ADD)) {
		if (fna_cmpl == AFA_REG_CMPL) {
			for (i = 0 ; i < AFA_MAX_NUM_OF_CMPL_REGS ; i++)
				in->fna_fifo_offs[i] = nic_funcs->get_mem_cmpl_addr(fd,
										    FNA_MON_ID + i);
		}

		in->fna_mask_size = AFA_MASK_SIZE;
	}

	if (in->advanced && bp_offs) {
		nic_funcs->fill_bp_offs_params(fd, port, &bp_offs_base_id, &num_bp_offs);

		for (i = 0 ; i < num_bp_offs ; i++)
			in->bp_offs[i] =
				nic_funcs->get_mem_cmpl_addr(fd, BP_MON_ID + bp_offs_base_id + i);
	}
}

static int nic_set_app_params_all_ports(int fd, uint64_t port_mask,
					enum hltests_nic_afa_cmpl_mode fna_cmpl,
					enum hltests_nic_test_opcode test_opcode,
					uint8_t plain_rdma, bool bp_offs)
{
	struct hlthunk_nic_user_set_app_params_in app_params_in = {};
	uint32_t port, max_ports;
	int rc;

	/* Gaudi1 doesn't support advanced ioctl */
	if (hltests_is_gaudi(fd))
		return 0;

	/* For IB device, this will be done implicitly as part of ibdev_set_port_ex */
	if (hltests_nic_is_ibdev(fd))
		return 0;

	max_ports = hltests_nic_get_max_num_of_ports(fd);

	for (port = 0 ; port < max_ports ; port++) {
		if (!(port_mask & BIT_ULL(port)))
			continue;

		memset(&app_params_in, 0, sizeof(app_params_in));

		nic_fill_port_app_params(fd, port, fna_cmpl, test_opcode, plain_rdma, bp_offs,
						&app_params_in);

		rc = hlthunk_nic_user_set_app_params(fd, port, &app_params_in);
		assert_int_equal(rc, 0);
	}

	return 0;
}

static int test_nic_lpbk_cc_cfg(int fd, struct hltests_nic_lpbk_cfg *cfg)
{
	/* cc not supported for gaudi */
	assert_false(hltests_is_gaudi(fd));

	/* cc not supported for simulator */
	assert_false(hltests_is_simulator(fd));

	/* SWIFT mode supported for gaudi3 and up */
	assert_true(cfg->cc_cq != CC_MODE_SWIFT || hltests_is_gaudi3(fd));

	return 0;
}

static int ibdev_open_device(struct hltests_nic_ib_in_params *ib_in_params)
{
	struct hltests_nic_in_params *in_params = ib_in_params->in_params;
	struct hbldv_ucontext_attr attr = {};
	struct ibv_device_attr_ex attrx;
	struct hltests_device *hdev;
	struct ibv_context *ibctx;
	struct ibv_pd *ibpd;
	int rc, fd = ib_in_params->fd;
	bool eq_poll, is_lpbk;
	enum hl_pci_ids device_id = hlthunk_get_device_id_from_fd(fd);

	if (!hltests_nic_is_ibdev(fd))
		return 0;

	hdev = get_hdev_from_fd(fd);
	is_lpbk = in_params->test == LPBK;

	eq_poll = is_lpbk ? ((struct hltests_nic_lpbk_cfg *) ib_in_params->cfg)->eq_poll : 0;

	attr.ports_mask = hltests_nic_to_ibdev_port_mask(fd, in_params->port_mask);
	attr.core_fd = fd;

	ibctx = hbldv_open_device(hdev->ibdev, &attr);
	assert_non_null(ibctx);

	assert_int_equal(hlibv_query_device_ex(ibctx, NULL, &attrx), 0);
	assert_int_equal(attrx.orig_attr.vendor_part_id, device_id);

	ib_in_params->ibctx = ibctx;

	ibpd = hlibv_alloc_pd(ibctx);
	assert_non_null(ibpd);

	ib_in_params->ibpd = ibpd;

	rc = hdev->asic_funcs->nic_funcs->asic_priv_init(hdev, ibctx, in_params->port_mask);
	if (rc)
		return rc;

	if (eq_poll)
		assert_int_equal(
			nic_eq_poll(ib_in_params->fd, ib_in_params->eq, ib_in_params->ibctx), 0);

	return 0;
}

static int ibdev_close_device(struct hltests_nic_ib_in_params *ib_in_params)
{
	struct hltests_nic_cq *cqs = ib_in_params->cqs;
	struct hltests_nic_lpbk_cfg *cfg = ib_in_params->cfg;
	int fd = ib_in_params->fd;
	bool eq_poll;
	uint32_t user_cq_idx, i;

	if (!hltests_nic_is_ibdev(fd))
		return 0;

	eq_poll = (ib_in_params->in_params->test == LPBK) ?
			((struct hltests_nic_lpbk_cfg *) cfg)->eq_poll : 0;

	user_cq_idx = (ib_in_params->in_params->test == LPBK) ?
			((struct hltests_nic_lpbk_cfg *) cfg)->user_cq_idx :
				((struct hltests_nic_e2e_cfg *) cfg)->user_cq_idx;

	if (eq_poll)
		assert_int_equal(nic_eq_poll_stop(ib_in_params->eq), 0);

	for (i = 0 ; i <= user_cq_idx ; i++)
		assert_int_equal(hltests_nic_cq_destroy(fd, &cqs[i]), 0);

	assert_int_equal(hlibv_dealloc_pd(ib_in_params->ibpd), 0);
	assert_int_equal(hlibv_close_device(ib_in_params->ibctx), 0);

	return 0;
}

static void nic_fill_ib_port_app_params(int fd, uint32_t port,
					enum hltests_nic_afa_cmpl_mode fna_cmpl,
					enum hltests_nic_test_opcode test_opcode,
					uint8_t plain_rdma, bool bp_offs,
					struct hltests_nic_ib_app_params *in)
{
	struct hltests_device *hdev = get_hdev_from_fd(fd);
	struct hltests_nic_asic_funcs *nic_funcs = hdev->asic_funcs->nic_funcs;
	uint32_t bp_offs_base_id, num_bp_offs, i;

	in->advanced = !plain_rdma;

	if ((fna_cmpl < AFA_CMPL_MODE_MAX) && (test_opcode == TEST_OPCODE_ATOMIC_FETCH_ADD)) {
		if (fna_cmpl == AFA_REG_CMPL) {
			for (i = 0 ; i < AFA_MAX_NUM_OF_CMPL_REGS ; i++)
				in->fna_fifo_offs[i] = nic_funcs->get_mem_cmpl_addr(fd,
										    FNA_MON_ID + i);
		}

		in->fna_mask_size = AFA_MASK_SIZE;
	}

	if (in->advanced && bp_offs) {
		nic_funcs->fill_bp_offs_params(fd, port, &bp_offs_base_id, &num_bp_offs);

		for (i = 0 ; i < num_bp_offs ; i++)
			in->bp_offs[i] =
				nic_funcs->get_mem_cmpl_addr(fd, BP_MON_ID + bp_offs_base_id + i);
	}
}

static int ibdev_set_ports_ex(struct hltests_nic_ib_in_params *ib_in_params)
{
	struct hltests_nic_ib_app_params *app_params_in = &ib_in_params->ib_app_params;
	struct hltests_nic_in_params *in_params = ib_in_params->in_params;
	struct ibv_context *ibctx = ib_in_params->ibctx;
	struct hbldv_wq_array_attr *wq_arr_attr;
	struct hbldv_port_ex_attr attr;
	uint32_t port, max_n_ports, max_num_of_qps, max_qp_num_wqes;
	int fd = ib_in_params->fd, rc;
	bool is_coll_wq;

	if (!hltests_nic_is_ibdev(fd))
		return 0;

	max_n_ports = hltests_nic_get_max_num_of_ports(fd);
	is_coll_wq = in_params->coll_type == COLL_TYPE_DIRECT;

	nic_get_wq_arr_nwqe(fd, in_params, &max_qp_num_wqes);

	for (port = 0 ; port < max_n_ports ; port++) {
		if (!(in_params->port_mask & BIT_ULL(port)))
			continue;

		memset(app_params_in, 0, sizeof(*app_params_in));

		nic_fill_ib_port_app_params(fd, port, in_params->fna_cmpl, in_params->test_opcode,
						in_params->plain_rdma, in_params->bp_offs,
						app_params_in);

		memset(&attr, 0, sizeof(attr));

		attr.port_num = hltests_nic_to_ibdev_port_num(fd, port);
		attr.caps |= app_params_in->advanced ? HBLDV_PORT_CAP_ADVANCED : 0;
		memcpy(attr.qp_wq_bp_offs, app_params_in->bp_offs, sizeof(attr.qp_wq_bp_offs));
		memcpy(attr.atomic_fna_fifo_offs, app_params_in->fna_fifo_offs,
			sizeof(attr.atomic_fna_fifo_offs));
		attr.atomic_fna_mask_size = app_params_in->fna_mask_size;

		if (in_params->force_wq_with_pmmu) {
			rc = get_max_supported_wqs_per_port(fd, in_params, is_coll_wq);
			if (rc < 0) {
				errno = EINVAL;
				E("Invalid Work-queues per port for port");

				return -errno;
			}

			max_num_of_qps = (uint32_t)rc;
		} else {
			max_num_of_qps = in_params->qps_per_port[port] + (is_coll_wq ? 0 : 1);
		}

		if (is_coll_wq)
			wq_arr_attr = &attr.wq_arr_attr[HBLDV_WQ_ARRAY_TYPE_SCALE_OUT_COLLECTIVE];
		else
			wq_arr_attr = &attr.wq_arr_attr[HBLDV_WQ_ARRAY_TYPE_GENERIC];

		wq_arr_attr->max_num_of_wqs = max_num_of_qps;
		wq_arr_attr->max_num_of_wqes_in_wq = max_qp_num_wqes;
		wq_arr_attr->mem_id = (enum hbldv_mem_id) in_params->wq_loc;
		wq_arr_attr->swq_granularity = (in_params->rdv_type == HLTESTS_NIC_RDV_MS) ?
					HBLDV_SWQE_GRAN_64B : HBLDV_SWQE_GRAN_32B;

		rc = hbldv_set_port_ex(ibctx, &attr);
		assert_int_equal(rc, 0);
	}

	return 0;
}

VOID test_nic_lpbk_atomic_fna(void **state)
{
	int rc;

	rc = nic_common_lpbk_flow(state, NIC_TEST_TYPE_ATOMIC_FNA);
	if (rc == -ENOTSUP)
		skip();

	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_nic_lpbk_basic(void **state)
{
	int rc;

	rc = nic_common_lpbk_flow(state, NIC_TEST_TYPE_BASIC);
	if (rc == -ENOTSUP)
		skip();

	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_nic_lpbk_bp_offs(void **state)
{
	int rc;

	rc = nic_common_lpbk_flow(state, NIC_TEST_TYPE_BP_OFFS);
	if (rc == -ENOTSUP)
		skip();

	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_nic_lpbk_collective(void **state)
{
	int rc;

	rc = nic_common_lpbk_flow(state, NIC_TEST_TYPE_COLL);
	if (rc == -ENOTSUP)
		skip();

	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_nic_lpbk_lag(void **state)
{
	int rc;

	rc = nic_common_lpbk_flow(state, NIC_TEST_TYPE_LAG);
	if (rc == -ENOTSUP)
		skip();

	assert_int_equal(rc, 0);

	END_TEST;
}

VOID test_nic_lpbk_dna(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *)*state;

	nic_dna_run(tests_state->fd);

	END_TEST;
}

VOID test_nic_e2e_lpbk(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_nic_cq *cq = NULL, *cqs = NULL;
	struct hltests_nic_eq eq = {0};
	void *dram_addr = NULL;
	const char *config_filename = hltests_get_config_filename();
	struct hltests_nic_lpbk_cfg cfg;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	struct hltests_nic_in_params *in_params;
	size_t cq_buf_len;
	int rc, fd = tests_state->fd;
	uint64_t local_dram_data_base = 0, remote_dram_data_base = 0, data_size,
		nic_ports_mask = tests_state->nic_ports_mask, total_size,
		loopback_mask = 0, test_ports_mask = 0, lcl_sram_base = 0, rem_sram_base = 0,
		dst_size;
	uint32_t wqe_size, nwq, max_n_ports = hltests_nic_get_max_num_of_ports(fd),
		num_of_buffers = 0, i, j, num_of_conn, port, port_idx;
	bool even_port_up, odd_port_up, is_rdv = false, is_wr_rdv = false, encap_en = false,
		is_rd_rdv = false, upscale_en = false, downscale_en = false, fna = false,
		print_wq_iteration = false;
	struct hlthunk_nic_get_ports_masks_out ports_masks;
	struct hltests_nic_ib_in_params *ib_in_params;

	/* The test is applicable for NIC supported ASICs only */
	assert_true(hltests_is_gaudi_family(fd));

	/* The test can't run if all NIC ports are disabled */
	assert_true(nic_ports_mask & hltests_nic_get_port_mask(fd));

	rc = hltests_nic_get_mac_loopback_mask(fd, &loopback_mask);
	assert_int_equal(rc, 0);

	/* clear config prior of filling it */
	memset(&cfg, 0, sizeof(cfg));
	cfg.iterations_wq = 1;

	if (config_filename) {
		if (ini_parse(config_filename, lpbk_parser, &cfg) < 0)
			fail_msg("Can't load %s\n", config_filename);
	} else {
		printf("no cfg file was provided\n");

		rc = hltests_nic_get_default_cfg(fd, &cfg, HLTESTS_NIC_E2E_LPBK);
		assert_int_equal(rc, 0);
	}

	if (cfg.test_opcode == TEST_OPCODE_ATOMIC_FETCH_ADD && hw_ip->dram_enabled == 0 &&
	    cfg.atomic_val_loc == AFA_OP_DRAM) {
		printf("DRAM must be enabled for FnA tests, skipping test\n");
		skip();
	}

	if (cfg.atomic_val_loc == AFA_OP_SRAM && cfg.test_opcode == TEST_OPCODE_ATOMIC_FETCH_ADD &&
			!hw_ip->sram_size) {
		printf("FnA operation on SRAM is N/A when cache is enabled, skipping test\n");
		skip();
	}

	if (cfg.reduction_en && hw_ip->dram_enabled == 0) {
		printf("DRAM must be enabled for tests with reduction, skipping test\n");
		skip();
	}

	if (cfg.ports_num) {
		for (i = 0 ; i < cfg.ports_num ; i++) {
			port_idx = cfg.ports[i];
			assert_int_not_equal(nic_ports_mask & (1ULL << port_idx), 0);
			test_ports_mask |= (1ULL << port_idx);
		}
	} else {
		for (i = 0, port_idx = 0 ; i < max_n_ports ; i++) {
			if (!(nic_ports_mask & (1ULL << i)))
				continue;

			cfg.ports[port_idx++] = i;
			cfg.ports_num++;
		}
		test_ports_mask = nic_ports_mask;
	}

	assert_int_not_equal(cfg.qps_per_port[0], 0);
	if (cfg.qps_per_port_num_elements > 1) {
		/* there are only two valid options: set a single qps_per_port for all ports, or set
		 * a unique qps_per_port for each port. in case of the latter, the numbers of the
		 * values should be equal to the number of the given ports.
		 */
		assert_int_equal(cfg.ports_num, cfg.qps_per_port_num_elements);
	} else {
		/*
		 * For the case when port list is not given, use same first qps_per_port for all
		 * enabled ports.
		 */
		for (port = 0, port_idx = 0 ; port < max_n_ports ; port++) {
			if (!(test_ports_mask & (1ULL << port)))
				continue;

			cfg.qps_per_port[port_idx++] = cfg.qps_per_port[0];
		}
	}

	if (cfg.cc_cq)
		assert_int_equal(test_nic_lpbk_cc_cfg(fd, &cfg), 0);

	/* Only encap over UDP test is supported in Gaudi2 meaning that src_ip_addr must not be set
	 * and the encap type can't be over IPV4.
	 */
	assert_false(hltests_is_gaudi2(fd) &&
			(cfg.src_ip_addr || cfg.encap_type == HL_NIC_ENCAP_OVER_IPV4));
	/* Encap tests are not supported in Gaudi3 */
	assert_false(hltests_is_gaudi3(fd) && (cfg.src_ip_addr || cfg.encap_type));

	encap_en = cfg.encap_type || cfg.src_ip_addr;

	/* For collective operations, non multi-context cases, HW supports max 1 QP per port for
	 * linear write, and 2 ports for RDV tests.
	 */
	assert_true(!cfg.coll_op || (cfg.max_qps_per_port == 1) ||
			(cfg.coll_op == COLL_OP_MODE_MULTI_CONTEXT  &&
					((cfg.test_opcode == TEST_OPCODE_LINEAR_WRITE) ||
							(cfg.max_qps_per_port % 2 == 0))));

	if (cfg.verbose) {
		printf("iterations_mem: %d, iterations_db: %d\n", cfg.iterations_mem,
			cfg.iterations_db);
		print_port_mask(fd, test_ports_mask);

		if (cfg.qps_per_port_num_elements > 1) {
			printf("qps_per_port:");
			for (i = 0 ; i < cfg.ports_num ; i++)
				printf(" %d", cfg.qps_per_port[cfg.ports[i]]);
			printf("\n");
		} else {
			printf("qps_per_port: %d\n", cfg.qps_per_port[0]);
		}

		printf("data_size: 1 << %d, wqe_size: 1 << %d, cq_buf_size: 1 << %d\n",
			cfg.data_size_shift, cfg.wqe_size_shift, cfg.cq_buf_len_shift);
		printf("data_loc: %d, wq_loc: %d cmpl: %d, data_cmp: %d, single_alloc: %d\n",
			cfg.data_loc, cfg.wq_loc, cfg.cmpl, cfg.data_cmp, cfg.single_alloc);
		printf("cleanup: %d, wait_for_cleanup: %d, mtu: %d%s, verbose: %d\n",
			cfg.cleanup, cfg.wait_for_cleanup, cfg.mtu, (!cfg.mtu ? "(default)":""),
			cfg.verbose);
		printf("db_qman: %d, wtd_en: %d, user_db: %d, coll_op: %d, encap_type: %d\n",
			cfg.db_qman, cfg.wtd_en, cfg.user_db, cfg.coll_op, cfg.encap_type);
		printf("test_opcode: %d, reduction_en: %d, red_dt: %d, eq_poll: %d\n",
			cfg.test_opcode, cfg.reduction_en, cfg.red_dt, cfg.eq_poll);
		printf("reduction_operation: %d, cc_cq: %d, rdv_type: %d, coll_type: %d\n",
			cfg.red_op, cfg.cc_cq, cfg.rdv_type, cfg.coll_type);
		printf("compression_en: %d, bp_offs: %d, fna_thresh: %d, fna_cmpl: %d\n",
			cfg.compression_en, cfg.bp_offs, cfg.fna_thresh, cfg.fna_cmpl);
		printf("fna_val_loc: %d, coll_dt: %d, sack_en: %d, err_inject_percent: %d\n",
			cfg.atomic_val_loc, cfg.coll_dt, cfg.sack_en, cfg.err_inject_percent);
		printf("force_wq_with_pmmu: %d, odp: %d, single_cmpl: %d\n",
			cfg.force_wq_with_pmmu, cfg.odp, cfg.single_cmpl);
		printf("axis_rank: %d, number_of_ranks: %d, disregard_rank: %d\n",
			cfg.axis_rank, cfg.number_of_ranks, cfg.disregard_rank);
	}

	/* Notify the user that loopback is not set. The test may still continue, as external
	 * loopback might be used.
	 */
	if (((test_ports_mask & loopback_mask) != test_ports_mask) &&
		!(cfg.qp_loopback && hltests_is_gaudi3(fd)))
		printf("\nMAC loopback and QP loopback are not set.\n");

	nic_set_app_params_all_ports(fd, test_ports_mask, cfg.fna_cmpl, cfg.test_opcode,
					cfg.plain_rdma, !!cfg.bp_offs);

	if (cfg.test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
		is_wr_rdv = true;
	else if (cfg.test_opcode == TEST_OPCODE_RENDEZVOUS_READ)
		is_rd_rdv = true;

	is_rdv = is_wr_rdv || is_rd_rdv;

	assert_int_not_equal(cfg.iterations_mem, 0);
	assert_int_not_equal(cfg.iterations_db, 0);
	assert_true(cfg.data_size_shift < sizeof(data_size) * CHAR_BIT);
	assert_true(cfg.wqe_size_shift < sizeof(wqe_size) * CHAR_BIT);
	assert_true(!cfg.mtu || cfg.mtu == SZ_1K ||
			cfg.mtu == SZ_2K || cfg.mtu == SZ_4K || cfg.mtu == SZ_8K);
	data_size = 1ull << cfg.data_size_shift;
	wqe_size = 1 << cfg.wqe_size_shift;
	dst_size = data_size;
	/* When using SOBs with multiple QPs, we use 1 SOB for all QPs in the port. This means we
	 * have no way of telling how many SOBs came from each QP, as 1 QP may produce several SOBs,
	 * while the other QP didn't produce any SOBs in the same time.
	 * When the WQ size is exactly 'data_size/wqe_size', the last PI updated would be 0. This
	 * can cause a case where WQ PI is updated to 0, before any progress has been made in this
	 * QP. This will result in CI==PI==0, meaning no WQE will be taken from the WQ, as it seems
	 * to be empty.
	 *
	 * There is a workaround for when 'cfg.iterations_db == 1', which is described in calc_nwq.
	 */
	assert_false(hltests_is_gaudi2(fd) && (cfg.max_qps_per_port > 1) && (cfg.cmpl == SOB)
			&& cfg.user_db && cfg.iterations_db > 1);

	nwq = (uint32_t)(data_size / wqe_size);

	/* Num of WQEs must be greater than 4 */
	assert_true(nwq > 4);

	/* half cycle doorbell requires at least two WQEs. To keep the test simple, we are not
	 * using half-cycle doorbell for RDV transfers. So we are not restricted by the number of
	 * WQEs for RDV transfers
	 */
	if (!is_rdv)
		assert_true(nwq > 1 || cfg.cmpl != SOB);

	/* doorbell iterations are supported only when using SOB with CS */
	assert_true(cfg.iterations_db == 1 || (cfg.cmpl == SOB && !cfg.wtd_en));
	/* Currently WTD on Gaudi2 is not supported using SOB */
	assert_true(cfg.wtd_en == 0 || cfg.cmpl != SOB || hltests_is_gaudi3(fd));
	/* if WQ resides on dram, WTD or collective operation must be enabled */
	assert_true(cfg.wq_loc == WQ_LOC_HOST || cfg.wtd_en == 1 || cfg.coll_op);

	/* running with multiple memory iterations requires doing full cleanup so we won't fail in
	 * the next initialization phase.
	 */
	assert_true(cfg.iterations_mem == 1 || cfg.cleanup);
	/* eq_poll is not supported for Gaudi1 */
	assert_true(!cfg.eq_poll || !hltests_is_gaudi(fd));
	/* We can force WQ access using PMMU only if WQ resides on HOST */
	assert_true(!cfg.force_wq_with_pmmu || cfg.wq_loc == WQ_LOC_HOST);
	/* DWQ is available only for G3 and above, it uses DB_FIFO and WTD_EN flags to mark this
	 * mode of operation.
	 */
	assert_true(!cfg.wtd_en || (cfg.wtd_en && !cfg.user_db && !hltests_is_gaudi3(fd)) ||
			(cfg.wtd_en && cfg.user_db && hltests_is_gaudi3(fd)));
	/* TODO: SW-87756 QMAN is not supported yet in Gaudi3. Remove once it is supported */
	assert_true(cfg.user_db || !hltests_is_gaudi3(fd));
	/* Collective operation conflict with WTD, requires user_db and supported on gaudi3 only */
	assert_true(!cfg.coll_op ||
		(cfg.coll_op && !cfg.wtd_en && cfg.user_db && hltests_is_gaudi3(fd)));
	/* FnA test is currently supported only for gaudi3, user_db, SOB completion.
	 * Also, both FnA CQ Completion and the Test CQ completion cannot be enabled together
	 * as we are overloading the wqe_index field of the cqe_sw to retrieve the F&A data.
	 */
	assert_true(cfg.test_opcode != TEST_OPCODE_ATOMIC_FETCH_ADD || (hltests_is_gaudi3(fd)
			&& cfg.user_db && cfg.cmpl == SOB && !(cfg.fna_cmpl == AFA_CQ_USR_CMPL
			&& (cfg.cmpl & CQ_USR))));

	assert_true(!cfg.plain_rdma || (cfg.cmpl == CQ_USR &&
			cfg.test_opcode == TEST_OPCODE_LINEAR_WRITE));

	/* BP offset tests must be executed with user_db enabled. Supported on gaudi2 and up */
	assert_true(!cfg.bp_offs || (!hltests_is_gaudi(fd) && cfg.user_db &&
					cfg.iterations_db == 1));

	/* WQ location should be either Host or DRAM */
	assert_true(cfg.wq_loc == WQ_LOC_HOST || cfg.wq_loc == WQ_LOC_DEVICE ||
			cfg.wq_loc == WQ_LOC_ALL);

	/*
	 * The number of signals should be less than the max value of the SOB.
	 * So, one start doorbell plus four quarter cycle doorbells for each QP of
	 * each port should be lte 2^15.
	 */
	assert_true((1 + cfg.max_qps_per_port * cfg.iterations_db * 4) <= BIT_ULL(15));

	/* disregard_rank may only be used with direct patcher. When disregard_rank is used, 1 rank
	 * is used multiple times. Meaning reduction cannot be used, as reduction operations will be
	 * done on the same buffer more than once.
	 */
	assert_true(!cfg.disregard_rank ||
		    (cfg.coll_type == COLL_TYPE_DIRECT && !cfg.reduction_en));

	if (hltests_is_gaudi3(fd) && cfg.coll_type == COLL_TYPE_DIRECT) {
		rc = hlthunk_nic_get_ports_masks(fd, &ports_masks);
		assert_int_equal(rc, 0);

		/* Assuming only scale out ports are used */
		test_ports_mask  &= ports_masks.ext_ports_mask;
		printf("\nRun scaleout ports only: updated port mask = 0x%lx\n", test_ports_mask);
	}

	if (cfg.compression_en) {
		/* Compression not support on ASICs preceding Gaudi3 */
		assert_true(!hltests_is_gaudi(fd) && !hltests_is_gaudi2(fd));

		/* HW limitation. Data size must be:
		 * 1. Bigger than 128 bytes.
		 * 2. In chunks of 128 bytes.
		 */
		assert_true(BIT(cfg.data_size_shift) >= SZ_128);

		/* In Gaudi3, compression and QP loopback are not supported together */
		assert_false(hltests_is_gaudi3(fd) && cfg.qp_loopback);
	}

	if (is_rdv) {
		/* For Rendezvous test, there should be a remote qp and a local qp.
		 * So the number of qps should always be even
		 */
		for (i = 0 ; i < cfg.ports_num ; i++)
			assert_true((cfg.qps_per_port[i] & 1) == 0);
		assert_true(!hltests_is_gaudi(fd));
		/* The number of WQEs should always be a multiple of 2 */
		assert_true(__builtin_popcountll(nwq) == 1);
		/* we are not using the half-doorbell in RDV transfer */
		assert_true(cfg.iterations_db == 1);
	}

	assert_true(hw_ip->dram_enabled || hltests_is_gaudi2(fd) || hltests_is_gaudi3(fd));

	for (i = 0, num_of_conn = 0 ; i < cfg.ports_num ; i++)
		if (test_ports_mask & (1ULL << cfg.ports[i]))
			num_of_conn += cfg.qps_per_port[i];

	/* We can perform reduction/upscale only on HBM memory in Gaudi2 and in SRAM/HBM in Gaudi3
	 * and above
	 */
	if (cfg.reduction_en) {
		assert_true((cfg.data_loc == DATA_LOC_DRAM && !hltests_is_gaudi(fd)) ||
				(cfg.data_loc == DATA_LOC_SRAM &&
				!hltests_is_gaudi(fd) && !hltests_is_gaudi2(fd)));
		assert_true((cfg.red_op != HLTESTS_NIC_REDUCTION_OP_INVALID) &&
				(cfg.red_dt != HLTESTS_NIC_REDUCTION_DT_INVALID));
		assert_true(!cfg.single_alloc);

		/* 'sub' operation isn't supported in Gaudi3 (H9-5261) */
		assert_false(hltests_is_gaudi3(fd) &&
				(cfg.red_op == HLTESTS_NIC_REDUCTION_OP_SUBTRACTION));

		upscale_en = (cfg.red_dt == HLTESTS_NIC_REDUCTION_UPSCALING_BF16);
		downscale_en = (cfg.red_dt == HLTESTS_NIC_REDUCTION_DOWNSCALING_TO_BF16);
		/* Upscale: Destination buffer(fp32) is twice the size of source buffer(bf16)
		 * Downscale: Destination buffer(bf16) is half the size of source buffer(fp32)
		 */
		if (upscale_en)
			dst_size = data_size * 2;
		else if (downscale_en)
			dst_size = data_size / 2;
	}

	/* ODP is supported from kernel version 5.5 and above. */
	if (cfg.odp && !hw_ip->odp_supported) {
		printf("ODP tests requires kernel version >= v5.5\n");
		skip();
	}

	if (cfg.data_loc != DATA_LOC_HOST) {
		num_of_buffers = cfg.single_alloc ? cfg.ports_num : num_of_conn;
		/* data_size: source buffer size. This is constant across tests.
		 * dst_size: dest buffer size. By default this is same as data_size. Based on some
		 * tests, this is manipulated. See above for calculation.
		 */
		total_size = num_of_buffers * (data_size + dst_size);

		/* ignore when dram is disabled, as the tests themselves will be skipped later on */
		if (hw_ip->dram_enabled &&
			(cfg.data_loc == DATA_LOC_ALL || cfg.data_loc == DATA_LOC_DRAM)) {
			/* Compression: Source and destination address should be 128 bytes
			 * aligned. Allocate extra to align the addresses later.
			 */
			if (cfg.compression_en)
				total_size += 2 * SZ_128;

			assert_true(total_size <= hw_ip->dram_size);

			dram_addr = hltests_allocate_device_mem(fd, total_size, 0, CONTIGUOUS);
			assert_non_null(dram_addr);

			local_dram_data_base = (uint64_t) (uintptr_t) dram_addr;
			remote_dram_data_base = local_dram_data_base + num_of_buffers * data_size;

			/* HW limitation. HBM address must be 128 bytes aligned with compression. */
			if (cfg.compression_en) {
				local_dram_data_base = ALIGN_UP(local_dram_data_base, SZ_128);
				remote_dram_data_base = ALIGN_UP(local_dram_data_base +
								num_of_buffers * data_size, SZ_128);
			}
		} else if (cfg.data_loc == DATA_LOC_SRAM) {
			assert_true(total_size <= hw_ip->sram_size);

			lcl_sram_base = hw_ip->sram_base_address;
			rem_sram_base = hw_ip->sram_base_address + (num_of_buffers * data_size);
		}
	}

	/* We use USER_CQ completion for the FnA WQE if the completion is AFA_CQ_USR_CMPL */
	fna = ((cfg.test_opcode == TEST_OPCODE_ATOMIC_FETCH_ADD) &&
			(cfg.fna_cmpl == AFA_CQ_USR_CMPL));

	if ((cfg.cmpl & CQ_USR) || fna || hltests_nic_is_ibdev(fd)) {
		if (hltests_is_gaudi(fd)) {
			/*
			 * The responder CQE of the even port is pushed to the odd port CQ. Hence if
			 * the even port is up, its odd port should be up as well.
			 */
			for (i = 0 ; i < max_n_ports ; i += 2) {
				even_port_up = (nic_ports_mask & BIT_ULL(i));
				odd_port_up = (nic_ports_mask & (1 << (i + 1)));

				assert_true(!even_port_up || odd_port_up);
			}
		}

		assert_true(cfg.cq_buf_len_shift <
				member_size(struct hltests_nic_cq, cq_buf_len) * CHAR_BIT);

		cq_buf_len = 1 << cfg.cq_buf_len_shift;


		/* In WTD test, we post a dedicated doorbell for each WQE.
		 * Therefore, we will start to receive completions a long before we start polling
		 * the CQ, and in case the CQ size isn't sufficient, we will get CQ overflow.
		 * There should be 2 CQEs (req/resp) per each WQE, when the total number of
		 * WQEs = num_ports * num_qps * wqes_per_qp = num_of_conn * wqes_per_qp.
		 */
		assert_true(!cfg.wtd_en || ((nwq * num_of_conn * 2) <= cq_buf_len));

		cqs = calloc(cfg.user_cq_idx + 1, sizeof(*cqs));
		assert_non_null(cqs);
		cq = &cqs[cfg.user_cq_idx];

		for (i = 0 ; i <= cfg.user_cq_idx ; i++) {
			memcpy(cqs[i].user_cq.port_mask, &test_ports_mask,
				sizeof(test_ports_mask));

			cqs[i].fna = fna;
			cqs[i].tests_state = tests_state;
			cqs[i].cq_buf_len = cq_buf_len;
			cqs[i].user_cq.cq_buf_len = 1 << cfg.user_cq_buf_len_shift;
		}
	}

	eq.ports_mask = nic_ports_mask;
	if (cfg.eq_poll && !hltests_nic_is_ibdev(fd))
		assert_int_equal(nic_eq_poll(fd, &eq, NULL), 0);

	if (cfg.wtd_en && cfg.user_db)
		cfg.db_fifo_mode = HL_NIC_DB_FIFO_TYPE_DWQ_LIN;
	else if (cfg.coll_op && cfg.coll_type == COLL_TYPE_CONTEXT)
		if (cfg.rdv_type == HLTESTS_NIC_RDV_V_OP)
			cfg.db_fifo_mode = HL_NIC_DB_FIFO_TYPE_COLL_OPS_LONG;
		else
			cfg.db_fifo_mode = HL_NIC_DB_FIFO_TYPE_COLL_OPS_SHORT;
	else if (cfg.coll_op && cfg.coll_type == COLL_TYPE_DIRECT)
		if (cfg.rdv_type == HLTESTS_NIC_RDV_V_OP)
			cfg.db_fifo_mode = HL_NIC_DB_FIFO_TYPE_COLL_DIR_OPS_LONG;
		else
			cfg.db_fifo_mode = HL_NIC_DB_FIFO_TYPE_COLL_DIR_OPS_SHORT;
	else
		cfg.db_fifo_mode = HL_NIC_DB_FIFO_TYPE_DB;

	in_params = hlthunk_malloc(sizeof(*in_params));
	assert_non_null(in_params);

	in_params->test = LPBK;
	in_params->port_mask = test_ports_mask;
	in_params->cqs = cqs;
	/* cq points at the entry in the cqs above that we want to work with */
	in_params->cq = cq;
	in_params->local_dram_addr = local_dram_data_base;
	in_params->remote_dram_addr = remote_dram_data_base;
	in_params->local_sram_addr = lcl_sram_base;
	in_params->remote_sram_addr = rem_sram_base;
	in_params->fna_cmpl = cfg.fna_cmpl;
	in_params->fna_thresh = cfg.fna_thresh;
	in_params->nwq = nwq;
	in_params->atomic_val_loc = cfg.atomic_val_loc;
	in_params->is_sram = cfg.data_loc == DATA_LOC_SRAM;
	in_params->dst_data_size = dst_size;
	in_params->bp_offs = cfg.bp_offs;
	in_params->max_qps_per_port = cfg.max_qps_per_port;
	in_params->test_opcode = cfg.test_opcode;
	in_params->force_wq_with_pmmu = cfg.force_wq_with_pmmu;
	in_params->coll_type = cfg.coll_type;
	in_params->plain_rdma = cfg.plain_rdma;
	in_params->eq = &eq;
	in_params->rdv_type = cfg.rdv_type;

	for (i = 0 ; i < cfg.ports_num ; i++) {
		port_idx = cfg.ports[i];
		in_params->qps_per_port[port_idx] = cfg.qps_per_port[i];
	}

	/* We should have the cache mode enabled whenever the data is on HBM irrespective of the
	 * transfer type. This is to bypass any filters put by NOC which might block few
	 * transactions.
	 */
	in_params->cache_en = cfg.data_loc == DATA_LOC_DRAM;

	if (cfg.coll_op == COLL_OP_MODE_LEGACY || cfg.rdv_type == HLTESTS_NIC_RDV_V_OP) {
		assert_int_equal(hltests_nic_debugfs_set_coll_lag_size(fd, 1), 0);
	} else if (cfg.coll_op == COLL_OP_MODE_MULTI_LAG ||
			cfg.coll_op == COLL_OP_MODE_MULTI_CONTEXT ||
				cfg.coll_op == COLL_OP_MODE_MULTI_RANK) {
		assert_int_equal(hltests_nic_debugfs_set_coll_lag_size(fd, cfg.ports_num), 0);
	}

	assert_true(hltests_is_gaudi3(fd) || !cfg.err_inject_percent);
	assert_true(cfg.err_inject_percent <= 100);

	if (cfg.err_inject_percent)
		assert_int_equal(hltests_nic_debugfs_inject_rx_err(fd, cfg.err_inject_percent), 0);

	ib_in_params = hlthunk_malloc(sizeof(*ib_in_params));
	assert_non_null(ib_in_params);

	ib_in_params->in_params = in_params;
	ib_in_params->cqs = cqs;
	ib_in_params->cfg = &cfg;
	ib_in_params->fd = fd;
	ib_in_params->eq = &eq;

	in_params->ib_in_params = ib_in_params;

	for (i = 0 ; i < cfg.iterations_mem ; i++) {
		in_params->is_dram = (cfg.data_loc == DATA_LOC_ALL) ? (i & 1) :
					(cfg.data_loc == DATA_LOC_DRAM);

		if (in_params->is_dram && hw_ip->dram_enabled == 0) {
			if (cfg.data_loc == DATA_LOC_ALL) {
				if (cfg.verbose)
					printf("\niteration: %u, DRAM\n", i);
				printf("data_loc=DRAM but DRAM is not enabled - skipping\n");
				continue;
			} else {
				/* in case data_loc == DATA_LOC_DEVICE, change target to host*/
				if (cfg.verbose)
					printf("\niteration: %u, HOST\n", i);
				printf("%sno DRAM - data_loc is set to HOST instead of DRAM%s\n",
					KRED, KNRM);
				in_params->is_dram = false;
			}
		} else if (cfg.verbose) {
			printf("\niteration: %u, %s\n", i,
			       in_params->is_dram ? "DRAM" :
			       in_params->is_sram ? "SRAM" : "HOST");
		}

		print_wq_iteration = cfg.iterations_wq > 1 && cfg.verbose;
		for (j = 0 ; j < cfg.iterations_wq ; j++) {
			if (cfg.wq_loc == WQ_LOC_ALL)
				in_params->wq_loc = (j & 1) ? HL_NIC_MEM_DEVICE : HL_NIC_MEM_HOST;
			else
				in_params->wq_loc = (cfg.wq_loc == WQ_LOC_DEVICE) ?
								HL_NIC_MEM_DEVICE : HL_NIC_MEM_HOST;

			if (in_params->wq_loc == HL_NIC_MEM_DEVICE && hw_ip->dram_enabled == 0) {
				if (cfg.wq_loc == WQ_LOC_ALL) {
					if (print_wq_iteration)
						printf("\niteration WQ: %u, WQ on DEVICE\n", j);
					printf(
						"wq_loc=device but DRAM is not enabled - skipping\n");
					continue;
				} else {
					if (print_wq_iteration)
						printf("\niteration WQ: %u, WQ on HOST\n", j);
					printf(
						"%sno DRAM - wq_loc is set to HOST instead of DEVICE%s\n",
						KRED, KNRM);
					in_params->wq_loc = HL_NIC_MEM_HOST;
				}
			} else if (print_wq_iteration) {
				printf("\niteration WQ: %u, WQ on %s\n", j,
				       (in_params->wq_loc == HL_NIC_MEM_DEVICE) ? "DEVICE" :
				       "HOST");
			}

			assert_int_equal(ibdev_open_device(ib_in_params), 0);

			assert_int_equal(ibdev_set_ports_ex(in_params->ib_in_params), 0);

			test_nic_e2e_lpbk_aux(state, in_params, &cfg);

			assert_int_equal(ibdev_close_device(ib_in_params), 0);
		}
	}

	if (cfg.eq_poll && !hltests_nic_is_ibdev(fd))
		assert_int_equal(nic_eq_poll_stop(&eq), 0);

	if (cfg.err_inject_percent)
		assert_int_equal(hltests_nic_debugfs_inject_rx_err(fd, 0), 0);

	if ((cfg.cmpl & CQ_USR) || fna || hltests_nic_is_ibdev(fd))
		hlthunk_free(cqs);

	if (dram_addr)
		assert_int_equal(hltests_free_device_mem(fd, dram_addr), 0);

	hlthunk_free(ib_in_params);
	hlthunk_free(in_params);
	END_TEST;
}

VOID test_nic_e2e(void **state)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hlthunk_nic_get_ports_masks_out ports_masks;
	const char *config_filename = hltests_get_config_filename();
	struct hltests_nic_user_fifo_params fifo_params;
	struct hltests_nic_eq eq = {0};
	struct hltests_nic_conn_in *conn_in;
	struct hltests_nic_conn_out *conn_out;
	struct hltests_nic_contexts *nic_ctx;
	struct hltests_nic_in_params *in_params;
	struct hltests_nic_e2e_cfg cfg;
	struct hlthunk_hw_ip_info *hw_ip = &tests_state->hw_ip;
	struct timespec base;
	struct hlthunk_time_sync_info begin, end;
	struct hltests_nic_db_fifo_data **db_fifos = NULL;
	void ***src_buf, ***dst_buf;
	struct hltests_nic_cq *cq = NULL, *cqs = NULL;
	union hltests_nic_encap **encap_data = NULL;
	char **dst_macs;
	uint64_t sob_base_addr, sob_addr, data_size, test_port_mask = 0, local_dram_data_base = 0,
		remote_dram_data_base = 0, seq, nic_ports_mask = tests_state->nic_ports_mask,
		used_ports_mask = 0, needed_dram_size, cc_port_mask = 0;
	uint32_t num_of_conn, *dst_conn_ids, *remote_sob_idx, *remote_addr_idx, *seed, wqe_size,
		nwq, doorbell_to, *dst_ips, max_n_ports, qps_per_port = 0, used_sobs,
		last_remote_addr_idx, masked_conn_id, i, j, nic, *nic_list, num_of_nics, qp,
		max_qps_per_port, dst_macs_num, n_db_fifos = 1, iterations, qps_till_now = 0,
		qp_idx, port, port_idx;

	uint16_t first_sob;
	int rc, fd = tests_state->fd;
	char buf[ETH_ALEN * 3 + 1] = {0};
	double *perf_outcome = &tests_state->perf_outcomes[RESULTS_NIC_E2E];
	bool print_data, encap_en = false;
	struct hltests_nic_ib_in_params *ib_in_params;
	void *dram_addr = NULL;

	if (getenv("FORCE_NEW_E2E")) {
		rc = nic_common_lpbk_flow(state, NIC_TEST_TYPE_BASIC);
		if (rc == -ENOTSUP)
			skip();

		assert_int_equal(rc, 0);

		EXIT_FROM_TEST;
	}

	eq.ports_mask = nic_ports_mask;
	if (!hltests_is_gaudi(fd) && !hltests_nic_is_ibdev(fd))
		assert_int_equal(nic_eq_poll(fd, &eq, NULL), 0);

	clock_gettime(CLOCK_MONOTONIC_RAW, &base);

	if (!config_filename)
		fail_msg("User didn't supply a configuration file name!\n");

	/* The test can't run if all NIC ports are disabled */
	assert_true(nic_ports_mask & hltests_nic_get_port_mask(fd));

	max_n_ports = hltests_nic_get_max_num_of_ports(fd);
	dst_macs_num = max_n_ports;

	ALLOC_2D_ARR(src_buf, max_n_ports, MAX_NUM_OF_QPS);
	ALLOC_2D_ARR(dst_buf, max_n_ports, MAX_NUM_OF_QPS);
	ALLOC_2D_ARR(dst_macs, dst_macs_num, ETH_ALEN);

	dst_conn_ids = hlthunk_malloc(max_n_ports * sizeof(*dst_conn_ids));
	assert_non_null(dst_conn_ids);
	remote_sob_idx = hlthunk_malloc(max_n_ports * sizeof(*remote_sob_idx));
	assert_non_null(remote_sob_idx);
	remote_addr_idx = hlthunk_malloc(max_n_ports * sizeof(*remote_addr_idx));
	assert_non_null(remote_addr_idx);
	seed = hlthunk_malloc(max_n_ports * sizeof(*seed));
	assert_non_null(seed);

	dst_ips = hlthunk_malloc(max_n_ports * sizeof(*dst_ips));
	assert_non_null(dst_ips);

	/* QPC alloc */
	conn_in = hlthunk_malloc(sizeof(*conn_in));
	assert_non_null(conn_in);
	conn_out = hlthunk_malloc(sizeof(*conn_out));
	assert_non_null(conn_out);
	nic_ctx = hlthunk_malloc(sizeof(*nic_ctx));
	assert_non_null(nic_ctx);
	in_params = hlthunk_malloc(sizeof(*in_params));
	assert_non_null(in_params);

	memset(&cfg, 0, sizeof(cfg));

	in_params->base = base;

	/*
	 * these are dynamically allocated because we might need to enlarge them
	 * in case of lazy cfg
	 */
	cfg.dst_macs = (uint8_t **) dst_macs;
	cfg.dst_conn_ids = dst_conn_ids;
	cfg.remote_sob_idx = remote_sob_idx;
	cfg.remote_addr_idx = remote_addr_idx;
	cfg.seed = seed;
	cfg.dst_ips = dst_ips;

	if (ini_parse(config_filename, e2e_parser, &cfg) < 0)
		fail_msg("Can't load %s\n", config_filename);

	assert_int_not_equal(cfg.qps_per_port[0], 0);

	if (!cfg.ports_num)
		/*
		 * For the case when port list is not given, use same first qps_per_port
		 * for all enabled ports.
		 */
		for (port = 0, port_idx = 0 ; port < max_n_ports ; port++)
			if (tests_state->nic_ports_mask & BIT_ULL(port)) {
				cfg.ports[port_idx] = port;
				cfg.qps_per_port[port_idx++] = cfg.qps_per_port[0];
				cfg.ports_num++;
			}

	assert_int_not_equal(cfg.ports_num, 0);
	assert_int_not_equal(cfg.max_qps_per_port, 0);
	assert_int_not_equal(cfg.iterations, 0);
	assert_in_range(cfg.sleep_before_cleanup, 0, 60);
	/* TODO support cc on e2e test */
	assert_false(cfg.cc_cq);
	/* Plain RDMA is not valid with SOB completion */
	assert_false(cfg.plain_rdma && (cfg.cmpl == SOB));

	/* Only encap over UDP test is supported in Gaudi2 meaning that src_ip_addr must not be set
	 * and the encap type can't be over IPV4.
	 */
	assert_false(hltests_is_gaudi2(fd) &&
			(cfg.src_ip_addr || cfg.encap_type == HL_NIC_ENCAP_OVER_IPV4));
	/* Encap tests are not supported in Gaudi3 */
	assert_false(hltests_is_gaudi3(fd) && (cfg.src_ip_addr || cfg.encap_type));

	for (i = 0 ; i < cfg.ports_num ; i++)
		if (tests_state->nic_ports_mask & BIT_ULL(cfg.ports[i]))
			used_ports_mask |= BIT(cfg.ports[i]);

	/* Advance feature should be set by the test as soon as possible */
	nic_set_app_params_all_ports(fd, used_ports_mask, AFA_REG_CMPL, TEST_OPCODE_LINEAR_WRITE,
					cfg.plain_rdma, false);

	num_of_nics = cfg.ports_num;
	max_qps_per_port = cfg.max_qps_per_port;
	iterations = cfg.iterations;
	assert_in_range(iterations, 1, 1024);

	encap_en = cfg.encap_type || cfg.src_ip_addr;

	/*
	 * The number of signals should be less than the max value of the SOB.
	 * So, four quarter cycle doorbells for each QP of each port should be lte 2^15.
	 */
	assert_true((max_qps_per_port * iterations * 4) <= BIT_ULL(15));

	for (i = 0, num_of_conn = 0 ; i < cfg.ports_num ; i++)
		if (tests_state->nic_ports_mask & BIT_ULL(cfg.ports[i]))
			num_of_conn += cfg.qps_per_port[i];

	if (cfg.lazy) {
		/* If lazy configuration is set, expand following arrays and initiate with
		 * correct values according to configuration provided for a single port,
		 * repeat it according to qps_per_port value.
		 */
		uint32_t *new_dst_conn_ids, *new_dst_ips, *new_remote_sob_idx,
			*new_remote_addr_idx;
		uint32_t cfg_idx = 0, qp_offset = 0;
		uint8_t **new_dst_macs;

		/* Number of configuration elements should be equal to ports_num for a proper
		 * lazy config fill.
		 */
		assert_true(cfg.remote_addr_idx_num == cfg.ports_num);
		assert_true(cfg.remote_sob_idx_num == cfg.ports_num);
		assert_true(cfg.dst_conn_ids_num == cfg.ports_num);
		assert_true(cfg.dst_macs_num == cfg.ports_num);
		assert_true(cfg.dst_ips_num == cfg.ports_num);
		/* We must make sure that amount of seed provided is equal to amount of
		 * configured ports. We don't need to duplicate the seeds as to the base
		 * port seed, we add the connection ID to make them unique.
		 */
		assert_true(cfg.seed_num == cfg.ports_num);

		/* Allocate new arrays to hold lazy configuration */
		ALLOC_2D_ARR(new_dst_macs, num_of_conn, ETH_ALEN);

		new_remote_addr_idx = hlthunk_malloc(num_of_conn * sizeof(*new_remote_addr_idx));
		assert_non_null(new_remote_addr_idx);
		new_remote_sob_idx = hlthunk_malloc(num_of_conn * sizeof(*new_remote_sob_idx));
		assert_non_null(new_remote_sob_idx);
		new_dst_conn_ids = hlthunk_malloc(num_of_conn * sizeof(*new_dst_conn_ids));
		assert_non_null(new_dst_conn_ids);
		new_dst_ips = hlthunk_malloc(num_of_conn * sizeof(*new_dst_ips));
		assert_non_null(new_dst_ips);

		/* Fill lazy configuration. Lazy configuration is filled as follows:
		 * For each port that is declared in the configuration file we duplicate and
		 * increase the relevant configuration values according to number of QPs that
		 * were configured for that port. Each time we hit the last QP
		 * (qp_offset == qps_per_port) for that port configuration, we move to the next
		 * port (cfg_idx).
		 */
		qps_per_port = cfg.qps_per_port[cfg_idx];

		for (i = 0 ; i < num_of_conn ; i++) {
			new_remote_addr_idx[i] = cfg.remote_addr_idx[cfg_idx] + qp_offset;
			new_dst_conn_ids[i] = cfg.dst_conn_ids[cfg_idx] + qp_offset;
			memcpy(new_dst_macs[i], cfg.dst_macs[cfg_idx], ETH_ALEN);

			new_remote_sob_idx[i] = cfg.remote_sob_idx[cfg_idx];
			new_dst_ips[i] = cfg.dst_ips[cfg_idx];
			qp_offset++;

			if (qp_offset == qps_per_port && cfg_idx < cfg.ports_num) {
				cfg_idx++;
				qps_per_port = cfg.qps_per_port[cfg_idx];
				qp_offset = 0;
			}
		}

		/* Free old allocations */
		FREE_2D_ARR(cfg.dst_macs, dst_macs_num);
		free(cfg.remote_addr_idx);
		free(cfg.remote_sob_idx);
		free(cfg.dst_conn_ids);
		free(cfg.dst_ips);

		/* Point to the new filled arrays */
		cfg.remote_addr_idx = new_remote_addr_idx;
		cfg.remote_sob_idx = new_remote_sob_idx;
		cfg.dst_conn_ids = new_dst_conn_ids;
		cfg.dst_macs = new_dst_macs;
		cfg.dst_ips = new_dst_ips;

		/* Change the amount of elements to correspond to the new arrays */
		cfg.remote_addr_idx_num = num_of_conn;
		cfg.remote_sob_idx_num = num_of_conn;
		cfg.dst_conn_ids_num = num_of_conn;
		cfg.dst_macs_num = num_of_conn;
		cfg.dst_ips_num = num_of_conn;
	} else {
		assert_true(cfg.dst_macs_num || cfg.dst_ips_num);
		assert_true(!cfg.dst_macs_num || num_of_conn == cfg.dst_macs_num);
		assert_true(!cfg.dst_ips_num || num_of_conn == cfg.dst_ips_num);

		assert_int_equal(num_of_conn, cfg.dst_conn_ids_num);
	}

	if (!cfg.lazy)
		cfg.dst_macs_num = max_n_ports;

	assert_true(cfg.data_size_shift < sizeof(data_size) * CHAR_BIT);
	assert_true(cfg.wqe_size_shift < sizeof(wqe_size) * CHAR_BIT);
	data_size = 1ull << cfg.data_size_shift;
	wqe_size = 1 << cfg.wqe_size_shift;
	/* When using SOBs with multiple QPs, we use 1 SOB for all QPs in the port. This means we
	 * have no way of telling how many SOBs came from each QP, as 1 QP may produce several SOBs,
	 * while the other QP didn't produce any SOBs in the same time.
	 * When the WQ size is exactly 'data_size/wqe_size', the last PI updated would be 0. This
	 * can cause a case where WQ PI is updated to 0, before any progress has been made in this
	 * QP. This will result in CI==PI==0, meaning no WQE will be taken from the WQ, as it seems
	 * to be empty.
	 *
	 * There is a workaround for when 'cfg.iterations == 1', which is described in calc_nwq.
	 */
	assert_false(hltests_is_gaudi2(fd) && (cfg.max_qps_per_port > 1) && (cfg.cmpl == SOB)
			&& cfg.user_db && cfg.iterations > 1);
	nwq = calc_nwq(fd, data_size, wqe_size, cfg.max_qps_per_port, cfg.cmpl, cfg.user_db);

	/* Num of WQEs must be greater than 4 */
	assert_true(nwq > 4);

	/* half cycle doorbell requires at least two WQEs */
	assert_true(nwq > 1 || cfg.cmpl != SOB);
	/* iterations are supported only when using SOB */
	assert_true(iterations == 1 || cfg.cmpl == SOB);

	printf(
		"qps_num: %u, data_size: 1 << %u, wqe_size: 1 << %u, nwq: 1 << %u, iterations: %u, cmpl: %u wq_loc: %u\n",
		max_qps_per_port, cfg.data_size_shift, cfg.wqe_size_shift,
		cfg.data_size_shift - cfg.wqe_size_shift, iterations, cfg.cmpl, cfg.wq_loc);

	nic_list = (uint32_t *)cfg.ports;

	for (i = 0 ; i < num_of_nics ; i++) {
		for (j = 0 ; j < cfg.qps_per_port[i] ; j++) {
			hltests_nic_stringify_mac(buf, cfg.dst_macs[qps_till_now + j]);
			/* use j + 1 to skip the ETH QP */
			printf("port: %u, QP: %u, dst_mac: %s\n", nic_list[i], j + 1, buf);
		}
		qps_till_now += cfg.qps_per_port[i];
	}

	print_data = cfg.print_data;
	doorbell_to = cfg.doorbell_to;

	/* all the required ports should be up */
	for (i = 0 ; i < num_of_nics ; i++) {
		assert_int_not_equal(tests_state->nic_ports_mask & (1ULL << nic_list[i]), 0);
		test_port_mask |= (1ULL << nic_list[i]);
	}

	assert_true(hw_ip->dram_enabled || !hltests_is_gaudi(fd));
	/* since WTD is not supported, dram resident WQ is not allowed */
	assert_true(cfg.wq_loc != WQ_LOC_DEVICE);

	/* For dram space allocation we need to take into consideration also the biggest remote addr
	 * idx provided in the config file (+1) because we are going to receive data to this offset
	 * (Note that there is a reasonable assumption that the last idx is the biggest one).
	 * Note that in Gaudi1 we haven't seen this issue because there is no MMU, so there was no
	 * problem to write to a non-allocated dram space.
	 */
	if (cfg.remote_addr_idx_num) {
		uint32_t max_remote_addr = 0;

		for (i = 0 ; i < cfg.remote_addr_idx_num ; i++)
			max_remote_addr = MAX(max_remote_addr, cfg.remote_addr_idx[i] + 1);

		last_remote_addr_idx = max_remote_addr;
	} else {
		last_remote_addr_idx = 1;
	}

	/* need space for send and recv data */
	if (cfg.lazy)
		needed_dram_size = last_remote_addr_idx * data_size * 2;
	else
		needed_dram_size = last_remote_addr_idx * data_size * num_of_conn * 2;

	assert_true(needed_dram_size <= hw_ip->dram_size);

	dram_addr = hltests_allocate_device_mem(fd, needed_dram_size, 0, CONTIGUOUS);
	assert_non_null(dram_addr);

	local_dram_data_base = (uint64_t) (uintptr_t) dram_addr;
	remote_dram_data_base = local_dram_data_base + num_of_conn * data_size;

	hltests_nic_print_time_elapsed(&in_params->base, "initial setup", cfg.verbose);

	sob_base_addr = hltests_get_sob_base_addr(fd);
	first_sob = hltests_get_first_avail_sob(fd);

	/* Create CQ */
	if ((cfg.cmpl & CQ_USR) || hltests_nic_is_ibdev(fd)) {
		cqs = calloc(cfg.user_cq_idx + 1, sizeof(*cqs));
		assert_non_null(cqs);
		cq = &cqs[cfg.user_cq_idx];

		for (i = 0 ; i <= cfg.user_cq_idx ; i++) {
			if (hltests_is_gaudi(fd))
				memcpy(cqs[i].user_cq.port_mask, &tests_state->nic_ports_mask,
					sizeof(tests_state->nic_ports_mask));
			else
				memcpy(cqs[i].user_cq.port_mask,
					&used_ports_mask, sizeof(used_ports_mask));

			cqs[i].tests_state = tests_state;
			cqs[i].cq_buf_len = CQ_NUM_OF_ENTRIES;
			cqs[i].user_cq.cq_buf_len = 1 << cfg.user_cq_buf_len_shift;
		}
	}

	/* H6-3280: Set the port mask for CC - in Gaudi2 the CC test should run only on the
	 * external ports as congestion window is disabled on internal ports.
	 */
	cc_port_mask = test_port_mask;

	if (hltests_is_gaudi2(fd)) {
		rc = hlthunk_nic_get_ports_masks(fd, &ports_masks);
		assert_int_equal(rc, 0);

		cc_port_mask &= ports_masks.ext_ports_mask;
	}

	/* Set input parameters */
	in_params->test = E2E;
	in_params->is_dram = true;
	in_params->local_dram_addr = local_dram_data_base;
	in_params->remote_dram_addr = remote_dram_data_base;
	in_params->port_mask = test_port_mask;
	in_params->max_qps_per_port = cfg.max_qps_per_port;
	in_params->nic_conn = conn_out;
	in_params->dst_conn_ids = cfg.dst_conn_ids;
	in_params->data_size = data_size;
	in_params->wqe_size = wqe_size;
	in_params->iterations = iterations;
	in_params->seed = cfg.seed;
	in_params->cmpl = cfg.cmpl;
	in_params->single_alloc = false;
	in_params->db_qman = false;
	in_params->wq_loc = (cfg.wq_loc == WQ_LOC_DEVICE) ? HL_NIC_MEM_DEVICE : HL_NIC_MEM_HOST;
	in_params->remote_sob_idx = cfg.remote_sob_idx_num ? cfg.remote_sob_idx : NULL;
	in_params->remote_addr_idx = cfg.remote_addr_idx_num ? cfg.remote_addr_idx : NULL;
	in_params->verbose = cfg.verbose;
	in_params->user_db = cfg.user_db;
	in_params->test_opcode = TEST_OPCODE_LINEAR_WRITE;
	in_params->n_ports = cfg.ports_num;
	in_params->nwq = nwq;
	in_params->dst_data_size = data_size;
	in_params->cq = cq;
	in_params->cqs = cqs;
	in_params->nic_ctx = nic_ctx;
	in_params->is_plain_rdma = cfg.plain_rdma;
	in_params->eq = &eq;

	ib_in_params = hlthunk_malloc(sizeof(*ib_in_params));
	assert_non_null(ib_in_params);

	ib_in_params->in_params = in_params;
	ib_in_params->cqs = cqs;
	ib_in_params->fd = fd;
	ib_in_params->cfg = &cfg;
	ib_in_params->eq = &eq;

	in_params->ib_in_params = ib_in_params;

	assert_int_equal(ibdev_open_device(ib_in_params), 0);

	for (i = 0, qp_idx = 0 ; i < num_of_nics ; i++) {
		nic = nic_list[i];

		qps_per_port = in_params->qps_per_port[nic] = cfg.qps_per_port[i];
		for (qp = 0 ; qp < qps_per_port ; qp++) {

			src_buf[nic][qp] = hltests_allocate_host_mem(fd, data_size, NOT_HUGE_MAP);
			assert_non_null(src_buf[nic][qp]);
			rc = hltests_nic_hmem_list_push(src_buf[nic][qp]);
			assert_int_equal(rc, 0);

			if (cfg.rand_data) {
				/*
				 * set same seed on both sides for data
				 * matching
				 */
				masked_conn_id = cfg.dst_conn_ids[qp] &
						 ((uint32_t)hltests_get_max_num_of_qps(fd, nic) -
						  1);
				hltests_set_rand_seed(cfg.seed[i] + masked_conn_id);
				hltests_fill_rand_values(src_buf[nic][qp], data_size);
				/* randomize it back */
				hltests_set_rand_seed((uint32_t)time(NULL));
			} else {
				memset(src_buf[nic][qp], 0, data_size);
			}

			if (cfg.plain_rdma) {
				uint64_t *src_guard = (uint64_t *)
						((uint8_t *) src_buf[nic][qp] +
						(data_size - PLAIN_RDMA_MAGIC_SIZE));

				*src_guard = PLAIN_RDMA_MAGIC;
			}

			dst_buf[nic][qp] = hltests_allocate_host_mem(fd, data_size, NOT_HUGE_MAP);
			assert_non_null(dst_buf[nic][qp]);
			rc = hltests_nic_hmem_list_push(dst_buf[nic][qp]);
			assert_int_equal(rc, 0);

			memset(dst_buf[nic][qp], 0xFF, data_size);

			in_params->src_buf[nic][qp] = src_buf[nic][qp];
			in_params->dst_buf[nic][qp] = dst_buf[nic][qp];
		}
		qp_idx += qps_per_port;

		conn_in->conn_per_port[nic] = (int)qps_per_port;
	}

	assert_int_equal(ibdev_set_ports_ex(in_params->ib_in_params), 0);

	assert_int_equal(nic_cqs_create(fd, in_params), 0);

	hltests_nic_print_time_elapsed(&in_params->base, "alloc data", cfg.verbose);

	/*
	 * Must clear the SOBs before opening the QPs because the other side
	 * might start transmit immediately after the QPs are open and hence the
	 * SOBs might be incremented.
	 * We don't apply multi SOBs on patcher mode.
	 */
	used_sobs = in_params->user_db && !in_params->coll_op
				? max_n_ports * DB_ITER_PER_CYCLE : max_n_ports;

	if (cfg.cmpl == SOB) {
		hltests_clear_sobs_offset(fd, (uint16_t)num_of_nics, LOCAL_SOB_ID);
		hltests_clear_sobs_offset(fd, (uint16_t)num_of_nics, REMOTE_SOB_ID);
	}

	rc = nic_wq_array_create(fd, in_params);
	assert_int_equal(rc, 0);

	rc = nic_pre_setup_contexts(fd, &cfg, nic_ctx, in_params);
	assert_int_equal(rc, 0);

	rc = nic_create_qps(tests_state, conn_in, in_params, test_port_mask);
	assert_int_equal(rc, 0);

	if (encap_en) {
		encap_data = alloc_encap_ids_e2e(state, &cfg, test_port_mask);
		config_encap_e2e(state, encap_data, nic_ctx, &cfg, in_params, test_port_mask);
	}

	rc = nic_setup_contexts((void *) &cfg, tests_state, conn_out, nic_ctx, in_params);
	assert_int_equal(rc, 0);

	if (cfg.user_db)
		db_fifos = create_user_db_fifo_ids(fd, in_params, n_db_fifos,
							HL_NIC_DB_FIFO_TYPE_DB);

	hltests_nic_print_time_elapsed(&in_params->base, "QP setup", cfg.verbose);

	rc = nic_operation(tests_state, in_params, &seq, &begin);
	assert_int_equal(rc, 0);

	hltests_nic_print_time_elapsed(&in_params->base, "send job", cfg.verbose);

	if (print_data) {
		char *data;

		for (i = 0 ; i < num_of_nics ; i++) {
			nic = nic_list[i];

			for (qp = 0 ; qp < in_params->qps_per_port[nic] ; qp++) {
				data = src_buf[nic][qp];
				printf("\nnic: %u, qp: %u, send: %s", nic,
				       conn_out->conn_id[nic][qp], KGRN);

				for (j = 0 ; j < E2E_PRINT_LEN ; j++)
					if (!isspace(data[j]))
						printf("%c", data[j]);

				printf("%s, recv: ", KNRM);
				data = dst_buf[nic][qp];

				for (j = 0 ; j < E2E_PRINT_LEN ; j++)
					printf("%c", data[j]);

				printf("\n");
			}
		}
	}

	if (doorbell_to) {
		printf("\nsleep %ds before doorbell\n", doorbell_to);
		sleep(doorbell_to);
	} else {
		printf("\nwait for doorbell\n");

		while (1) {
			int c = getchar();

			assert_int_not_equal(c, EOF);
			if (c == 'r')
				break;
		}
	}

	if (cfg.user_db) {
		memset(&fifo_params, 0, sizeof(struct hltests_nic_user_fifo_params));
		fifo_params.tests_state = tests_state;
		fifo_params.fifos = db_fifos;
		fifo_params.test_params = in_params;
		fifo_params.port_mask = test_port_mask;
		fifo_params.qp_ids = conn_out->conn_id;
		fifo_params.qps_per_port = in_params->qps_per_port;
		fifo_params.nwqs = nwq;
		fifo_params.max_qps_per_port = in_params->max_qps_per_port;
		fifo_params.n_fifos = (int)n_db_fifos;
		fifo_params.test_opcode = in_params->test_opcode;
		trigger_user_db(&fifo_params);
		hltests_nic_print_time_elapsed(&in_params->base, "trigger user doorbells",
						cfg.verbose);
	} else {
		for (i = 0 ; i < num_of_nics ; i++) {
			nic = nic_list[i];
			sob_addr = sob_base_addr + (first_sob + DB_SOB_ID + nic) * 4;
			WRITE32(sob_addr, 1);
		}

		/*
		 * See comment above the nic_operation function which explains why we
		 * call this function here.
		 */
		rc = hltests_wait_for_cs_until_not_busy(fd, seq);
		assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

		hltests_nic_print_time_elapsed(&in_params->base, "wait for CS", cfg.verbose);
	}

	if (cfg.cmpl & CQ_USR) {
		in_params->cq = cq;
		hl_nic_cq_process(state, (void *) &cfg, &end, in_params);
	} else {
		hl_nic_process_sob(state, (void *) &cfg, &end, in_params);
	}

	*perf_outcome = get_bw_gigabit_from_timesync(data_size * num_of_nics *
							cfg.max_qps_per_port * iterations,
							&begin, &end);
	printf("\n%sB/W: %.02lf Gb/s%s\n", KRED, *perf_outcome, KNRM);

	rc = nic_copy_devmem_to_host(tests_state, in_params);
	assert_int_equal(rc, 0);

	hltests_nic_print_time_elapsed(&in_params->base, cfg.cmpl & CQ_USR ? "CQ" : "SOB",
					cfg.verbose);

	if (print_data) {
		char *data;

		for (i = 0 ; i < num_of_nics ; i++) {
			nic = nic_list[i];

			for (qp = 0 ; qp < cfg.qps_per_port[nic] ; qp++) {
				data = src_buf[nic][qp];
				printf("\nnic: %u, qp: %u, send: %s", nic, qp,
				       KGRN);

				for (j = 0 ; j < E2E_PRINT_LEN ; j++)
					if (!isspace(data[j]))
						printf("%c", data[j]);

				printf("%s, recv: %s", KNRM, KBLU);
				data = dst_buf[nic][qp];

				for (j = 0 ; j < E2E_PRINT_LEN ; j++)
					if (!isspace(data[j]))
						printf("%c", data[j]);

				printf("%s\n", KNRM);
			}
		}

		printf("\n");
	}

	if (cfg.data_cmp) {
		nic_data_cmp(fd, in_params, max_n_ports);
		hltests_nic_print_time_elapsed(&in_params->base, "data cmp", cfg.verbose);
	}

	if (!cfg.cleanup)
		EXIT_FROM_TEST;

	if (cfg.wait_for_cleanup) {
		hltests_nic_wait_for_cleanup();
	} else if (cfg.sleep_before_cleanup) {
		printf("\nsleep %ds before cleanup\n",
			cfg.sleep_before_cleanup);
		sleep(cfg.sleep_before_cleanup);
	}

	/* Cleanup */

	if (cfg.user_db) {
		user_db_popped(fd, test_port_mask, db_fifos, n_db_fifos);
		destroy_user_db_fifos(fd, in_params, test_port_mask, db_fifos, n_db_fifos);
	}

	if (encap_en)
		destroy_encap_e2e(state, encap_data, &cfg, in_params, test_port_mask);

	rc = nic_destroy_qps(tests_state, conn_in, nic_ctx, in_params, test_port_mask);
	assert_int_equal(rc, 0);

	rc = nic_cleanup(fd, in_params);
	assert_int_equal(rc, 0);

	assert_int_equal(ibdev_close_device(ib_in_params), 0);

	if (!hltests_is_gaudi(fd) && !hltests_nic_is_ibdev(fd))
		assert_int_equal(nic_eq_poll_stop(&eq), 0);

	if ((cfg.cmpl & CQ_USR) || hltests_nic_is_ibdev(fd))
		hlthunk_free(cqs);

	/* Save base before freeing in_params structure */
	base = in_params->base;

	hlthunk_free(cfg.dst_ips);
	hlthunk_free(cfg.seed);
	hlthunk_free(cfg.remote_addr_idx);
	hlthunk_free(cfg.remote_sob_idx);
	hlthunk_free(cfg.dst_conn_ids);
	hlthunk_free(conn_in);
	hlthunk_free(conn_out);
	hlthunk_free(nic_ctx);
	hlthunk_free(in_params);
	FREE_2D_ARR(src_buf, max_n_ports);
	FREE_2D_ARR(dst_buf, max_n_ports);
	FREE_2D_ARR(cfg.dst_macs, cfg.dst_macs_num);
	if (dram_addr)
		assert_int_equal(hltests_free_device_mem(fd, dram_addr), 0);

	hltests_nic_print_time_elapsed(&base, "cleanup", cfg.verbose);

	END_TEST;
}

#ifndef HLTESTS_LIB_MODE

const struct CMUnitTest nic_root_tests[] = {
	cmocka_unit_test_setup(test_nic_e2e, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_nic_e2e_lpbk, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_nic_lpbk_atomic_fna, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_nic_lpbk_basic, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_nic_lpbk_bp_offs, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_nic_lpbk_collective, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_nic_lpbk_lag, hltests_ensure_device_operational),
	cmocka_unit_test_setup(test_nic_lpbk_dna, hltests_ensure_device_operational),
};

static const char *const usage[] = {
	"nic_root [options]",
	NULL,
};

int main(int argc, const char **argv)
{
	int num_tests = sizeof(nic_root_tests) /
			sizeof((nic_root_tests)[0]);

	hltests_parser(argc, argv, usage,
			HLTEST_DEVICE_MASK_GAUDI_ALL |
			HLTEST_DEVICE_MASK_GAUDI2_ALL |
			HLTEST_DEVICE_MASK_GAUDI3_ALL,
			nic_root_tests, num_tests);

	if (!can_open_debugfs(true))
		return 0;

	hltests_set_capabilities_mask(0);
	return hltests_run_group_tests("nic_root", nic_root_tests,
		(size_t)num_tests, hltests_root_nic_setup, hltests_root_nic_teardown);
}

#endif /* HLTESTS_LIB_MODE */
