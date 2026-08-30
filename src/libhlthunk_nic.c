// SPDX-License-Identifier: MIT

/*
 * Copyright 2019-2022 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "libhlthunk.h"
#include "specs/common/pci_ids.h"
#include "specs/common/shim_types.h"
#include "specs/hw_ip/pci/pci_general.h"

#define _GNU_SOURCE

#include <assert.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/ethtool.h>
#include <linux/limits.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)	(sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef min
#define min(x, y) ({ \
	typeof(x) _x = (x);     \
	typeof(y) _y = (y);     \
	static_assert(__builtin_types_compatible_p(typeof(_x), typeof(_y)),	\
			"Type mismatch in min macro");				\
			(void)(&_x == &_y);    \
			_x < _y ? _x : _y; })
#endif

#define MAC_STR_LEN	      (ETH_ALEN * 2 + (ETH_ALEN))
#define PORT_MASK_NIBBLES_NUM 12 /* Reserved for 48 ports. */

int hlthunk_ioctl(int fd, unsigned long request, void *arg);

static void parse_mac(uint8_t *mac, const char *value)
{
	char tmp[3] = { 0 };
	int i;

	for (i = 0; i < ETH_ALEN; i++) {
		memcpy(tmp, value + (i * 3), 2);
		mac[i] = (uint8_t)strtoul(tmp, NULL, 16);
	}
}

hlthunk_public int hlthunk_alloc_conn(int fd, uint32_t port, uint32_t *conn_id)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_alloc_conn_in alloc_in;
	struct hl_nic_alloc_conn_out alloc_out;
	int rc;

	if (!conn_id)
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&alloc_in, 0, sizeof(alloc_in));
	memset(&alloc_out, 0, sizeof(alloc_out));
	alloc_in.port = port;
	ioctl_args.op = HL_NIC_OP_ALLOC_CONN;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&alloc_in;
	ioctl_args.input_size = sizeof(alloc_in);
	ioctl_args.output_ptr = (__u64)(uintptr_t)&alloc_out;
	ioctl_args.output_size = sizeof(alloc_out);

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	*conn_id = alloc_out.conn_id;

	return 0;
}

hlthunk_public int hlthunk_alloc_coll_conn(int fd, struct hlthunk_nic_alloc_coll_conn_in *in,
					   uint32_t *conn_id)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_alloc_coll_conn_in alloc_in;
	struct hl_nic_alloc_coll_conn_out alloc_out;
	int rc;

	if (!conn_id)
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&alloc_in, 0, sizeof(alloc_in));
	memset(&alloc_out, 0, sizeof(alloc_out));

	alloc_in.is_scale_out = in->is_scale_out;

	ioctl_args.op = HL_NIC_OP_ALLOC_COLL_CONN;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&alloc_in;
	ioctl_args.input_size = sizeof(alloc_in);
	ioctl_args.output_ptr = (__u64)(uintptr_t)&alloc_out;
	ioctl_args.output_size = sizeof(alloc_out);

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	*conn_id = alloc_out.conn_id;

	return 0;
}

hlthunk_public int hlthunk_set_requester_conn_ctx(int fd, uint32_t port, uint32_t conn_id,
						  const struct hlthunk_requester_conn_ctx *in,
						  struct hlthunk_requester_conn_ctx_out *out)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_req_conn_ctx_in hl_in;
	struct hl_nic_req_conn_ctx_out hl_out;
	int rc;

	if (!in)
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&hl_in, 0, sizeof(hl_in));
	memset(&hl_out, 0, sizeof(hl_out));

	ioctl_args.op = HL_NIC_OP_SET_REQ_CONN_CTX;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&hl_in;
	ioctl_args.input_size = sizeof(hl_in);
	ioctl_args.output_ptr = (__u64)(uintptr_t)&hl_out;
	ioctl_args.output_size = sizeof(hl_out);

	hl_in.port = port;
	hl_in.conn_id = conn_id;
	hl_in.dst_ip_addr = in->dst_ip_addr;
	hl_in.dst_conn_id = in->dst_conn_id;
	hl_in.last_index = in->last_index;
	memcpy(hl_in.dst_mac_addr, in->dst_mac_addr, ETH_ALEN);

	hl_in.priority = in->priority;
	hl_in.timer_granularity = in->timer_granularity;
	hl_in.swq_granularity = in->swq_granularity;
	hl_in.wq_type = in->wq_type;
	hl_in.wq_remote_log_size = in->wq_remote_log_size;
	hl_in.cq_number = in->cq_number;
	hl_in.encap_en = in->encap_en;
	hl_in.encap_id = in->encap_id;
	hl_in.mtu = in->mtu;
	hl_in.congestion_en = in->congestion_en;
	hl_in.loopback = in->loopback;
	hl_in.wq_size = in->wq_size;
	hl_in.coll_lag_idx = in->coll_lag_idx;
	hl_in.coll_last_in_lag = in->coll_last_in_lag;
	hl_in.compression_en = in->compression_en;
	hl_in.remote_key = in->remote_key;
	hl_in.sack_en = in->sack_en;
	hl_in.congestion_wnd = in->congestion_wnd;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	if (out) {
		out->swq_mem_handle = hl_out.swq_mem_handle;
		out->rwq_mem_handle = hl_out.rwq_mem_handle;
	}

	return 0;
}

hlthunk_public int hlthunk_set_responder_conn_ctx(int fd, uint32_t port, uint32_t conn_id,
						  const struct hlthunk_responder_conn_ctx *ctx)
{
	struct hl_nic_res_conn_ctx_in hl_ctx;
	struct hl_nic_args ioctl_args;

	if (!ctx)
		return -EINVAL;

	memset(&hl_ctx, 0, sizeof(hl_ctx));
	memset(&ioctl_args, 0, sizeof(ioctl_args));

	hl_ctx.port = port;
	hl_ctx.conn_id = conn_id;
	hl_ctx.dst_ip_addr = ctx->dst_ip_addr;
	hl_ctx.dst_conn_id = ctx->dst_conn_id;
	memcpy(hl_ctx.dst_mac_addr, ctx->dst_mac_addr, ETH_ALEN);

	hl_ctx.priority = ctx->priority;
	hl_ctx.wq_peer_granularity = ctx->wq_peer_granularity;
	hl_ctx.cq_number = ctx->cq_number;
	hl_ctx.conn_peer = ctx->conn_peer;
	hl_ctx.rdv = ctx->rdv;
	hl_ctx.encap_en = ctx->encap_en;
	hl_ctx.encap_id = ctx->encap_id;

	hl_ctx.loopback = ctx->loopback;
	hl_ctx.wq_peer_size = ctx->wq_peer_size;
	hl_ctx.local_key = ctx->local_key;
	hl_ctx.sack_en = ctx->sack_en;

	ioctl_args.input_ptr = (__u64)(uintptr_t)&hl_ctx;
	ioctl_args.input_size = sizeof(hl_ctx);
	ioctl_args.op = HL_NIC_OP_SET_RES_CONN_CTX;

	return hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
}

hlthunk_public int hlthunk_destroy_conn(int fd, uint32_t port, uint32_t conn_id)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_destroy_conn_in destroy_in;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&destroy_in, 0, sizeof(destroy_in));
	destroy_in.port = port;
	destroy_in.conn_id = conn_id;
	ioctl_args.op = HL_NIC_OP_DESTROY_CONN;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&destroy_in;
	ioctl_args.input_size = sizeof(destroy_in);

	return hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
}

hlthunk_public int hlthunk_nic_cq_create(int fd, uint32_t num_of_entries, uint64_t *handle)
{
	return -EPERM;
}

hlthunk_public int hlthunk_nic_cq_destroy(int fd, uint64_t handle)
{
	return -EPERM;
}

hlthunk_public int hlthunk_nic_cq_wait(int fd, uint64_t handle, uint32_t *status, uint32_t *pi,
				       uint32_t *num_of_cqes, uint64_t timeout_us)
{
	return -EPERM;
}

hlthunk_public int hlthunk_nic_cq_update_consumed_entries(int fd, uint64_t handle,
							  uint32_t num_of_consumed_entries)
{
	return -EPERM;
}

hlthunk_public int hlthunk_nic_user_ccq_set(int fd, struct hlthunk_nic_user_ccq_set_in *in,
					    struct hlthunk_nic_user_ccq_set_out *out)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_user_ccq_set_in in_params;
	struct hl_nic_user_ccq_set_out out_params;
	int rc;

	if (!in || !out)
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&in_params, 0, sizeof(in_params));
	memset(&out_params, 0, sizeof(out_params));

	in_params.port = in->port;
	in_params.num_of_entries = in->num_of_entries;

	ioctl_args.op = HL_NIC_OP_USER_CCQ_SET;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in_params;
	ioctl_args.input_size = sizeof(in_params);
	ioctl_args.output_ptr = (__u64)(uintptr_t)&out_params;
	ioctl_args.output_size = sizeof(out_params);

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	out->ccq_handle = out_params.mem_handle;
	out->ccq_pi_handle = out_params.pi_handle;

	return 0;
}

hlthunk_public int hlthunk_nic_user_ccq_unset(int fd, uint32_t port)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_user_ccq_unset_in destroy_in;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&destroy_in, 0, sizeof(destroy_in));

	destroy_in.port = port;
	ioctl_args.op = HL_NIC_OP_USER_CCQ_UNSET;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&destroy_in;
	ioctl_args.input_size = sizeof(destroy_in);

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	return 0;
}

hlthunk_public int hlthunk_nic_wq_arr_set(int fd, struct hlthunk_nic_wq_arr_set_in *in,
					  struct hlthunk_nic_wq_arr_set_out *out)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_user_wq_arr_set_in hl_in;
	struct hl_nic_user_wq_arr_set_out hl_out;
	int rc;

	if (!in || ((in->mem_id == HL_NIC_MEM_HOST) && !out))
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&hl_in, 0, sizeof(hl_in));
	memset(&hl_out, 0, sizeof(hl_out));
	ioctl_args.op = HL_NIC_OP_USER_WQ_SET;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&hl_in;
	ioctl_args.input_size = sizeof(hl_in);
	ioctl_args.output_ptr = (__u64)(uintptr_t)&hl_out;
	ioctl_args.output_size = sizeof(hl_out);

	hl_in.addr = in->addr;
	hl_in.port = in->port;
	hl_in.num_of_wqs = in->num_of_wqs;
	hl_in.num_of_wq_entries = in->num_of_wq_entries;
	hl_in.type = in->type;
	hl_in.mem_id = in->mem_id;
	hl_in.swq_granularity = in->swq_granularity;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	if (in->mem_id == HL_NIC_MEM_HOST)
		out->handle = hl_out.mem_handle;

	return 0;
}

hlthunk_public int hlthunk_nic_wq_arr_unset(int fd, uint32_t port, uint32_t type)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_user_wq_arr_unset_in in;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&in, 0, sizeof(in));
	ioctl_args.op = HL_NIC_OP_USER_WQ_UNSET;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in;
	ioctl_args.input_size = sizeof(in);

	in.port = port;
	in.type = type;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	return 0;
}

hlthunk_public int hlthunk_nic_user_cq_set(int fd, uint32_t port, uint64_t addr,
					   uint32_t num_of_cqes)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_user_cq_set_in in;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&in, 0, sizeof(in));
	ioctl_args.op = HL_NIC_OP_USER_CQ_SET;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in;
	ioctl_args.input_size = sizeof(in);

	in.addr = addr;
	in.port = port;
	in.num_of_cqes = num_of_cqes;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	return 0;
}

hlthunk_public int hlthunk_nic_user_cq_unset(int fd, uint32_t port)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_user_cq_unset_in in;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&in, 0, sizeof(in));
	ioctl_args.op = HL_NIC_OP_USER_CQ_UNSET;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in;
	ioctl_args.input_size = sizeof(in);

	in.port = port;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	return 0;
}

hlthunk_public int hlthunk_nic_user_cq_update_ci(int fd, uint32_t port, uint32_t ci)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_user_cq_update_ci_in in;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&in, 0, sizeof(in));
	ioctl_args.op = HL_NIC_OP_USER_CQ_UPDATE_CI;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in;
	ioctl_args.input_size = sizeof(in);

	in.port = port;
	in.ci = ci;

	return hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
}

hlthunk_public int hlthunk_nic_user_cq_id_alloc(int fd, struct hlthunk_nic_user_cq_id_alloc_in *in,
						struct hlthunk_nic_user_cq_id_alloc_out *out)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_alloc_user_cq_id_in hl_in;
	struct hl_nic_alloc_user_cq_id_out hl_out;
	int rc;

	if (!in || !out)
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&hl_in, 0, sizeof(hl_in));
	ioctl_args.op = HL_NIC_OP_ALLOC_USER_CQ_ID;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&hl_in;
	ioctl_args.input_size = sizeof(hl_in);
	ioctl_args.output_ptr = (__u64)(uintptr_t)&hl_out;
	ioctl_args.output_size = sizeof(hl_out);

	hl_in.port = in->port;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	out->id = hl_out.id;

	return 0;
}

hlthunk_public int hlthunk_nic_user_cq_id_set(int fd, struct hlthunk_nic_user_cq_id_set_in *in,
					      struct hlthunk_nic_user_cq_id_set_out *out)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_user_cq_id_set_in hl_in;
	struct hl_nic_user_cq_id_set_out hl_out;
	int rc;

	if (!in)
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&hl_in, 0, sizeof(hl_in));
	ioctl_args.op = HL_NIC_OP_USER_CQ_ID_SET;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&hl_in;
	ioctl_args.input_size = sizeof(hl_in);
	ioctl_args.output_ptr = (__u64)(uintptr_t)&hl_out;
	ioctl_args.output_size = sizeof(hl_out);

	hl_in.port = in->port;
	hl_in.num_of_cqes = in->num_of_cqes;
	hl_in.id = in->id;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	if (out) {
		out->mem_handle = hl_out.mem_handle;
		out->pi_handle = hl_out.pi_handle;
		out->regs_handle = hl_out.regs_handle;
		out->regs_offset = hl_out.regs_offset;
	}

	return 0;
}

hlthunk_public int hlthunk_nic_user_cq_id_unset(int fd, struct hlthunk_nic_user_cq_id_unset_in *in)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_user_cq_id_unset_in hl_in;

	if (!in)
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&hl_in, 0, sizeof(hl_in));
	ioctl_args.op = HL_NIC_OP_USER_CQ_ID_UNSET;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&hl_in;
	ioctl_args.input_size = sizeof(hl_in);

	hl_in.port = in->port;
	hl_in.id = in->id;

	return hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
}

hlthunk_public int
hlthunk_nic_user_set_app_params(int fd, uint32_t port,
				const struct hlthunk_nic_user_set_app_params_in *in)
{
	struct hl_nic_set_user_app_params_in hl_app_in;
	struct hl_nic_args ioctl_args;

	if (!in)
		return -EINVAL;

	memset(&hl_app_in, 0, sizeof(hl_app_in));
	memset(&ioctl_args, 0, sizeof(ioctl_args));

	hl_app_in.port = port;
	hl_app_in.advanced = in->advanced;

	memcpy(hl_app_in.bp_offs, in->bp_offs, sizeof(in->bp_offs[0]) * HL_NIC_USER_BP_OFFS_MAX);
	memcpy(hl_app_in.fna_fifo_offs, in->fna_fifo_offs,
	       sizeof(in->fna_fifo_offs[0]) * HL_NIC_FNA_CMPL_ADDR_NUM);
	hl_app_in.fna_mask_size = in->fna_mask_size;

	ioctl_args.op = HL_NIC_OP_SET_USER_APP_PARAMS;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&hl_app_in;
	ioctl_args.input_size = sizeof(hl_app_in);

	return hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
}

hlthunk_public int
hlthunk_nic_user_get_app_params(int fd, uint32_t port,
				struct hlthunk_nic_user_get_app_params_out *hl_out)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_get_user_app_params_in in;
	struct hl_nic_get_user_app_params_out out;
	int rc;

	if (!hl_out)
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	memset(hl_out, 0, sizeof(*hl_out));

	ioctl_args.op = HL_NIC_OP_GET_USER_APP_PARAMS;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in;
	ioctl_args.input_size = sizeof(in);
	ioctl_args.output_ptr = (__u64)(uintptr_t)&out;
	ioctl_args.output_size = sizeof(out);

	in.port = port;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	hl_out->max_num_of_qps = out.max_num_of_qps;
	hl_out->num_allocated_qps = out.num_allocated_qps;
	hl_out->max_allocated_qp_idx = out.max_allocated_qp_idx;
	hl_out->max_cq_size = out.max_cq_size;
	hl_out->advanced = out.advanced;
	hl_out->max_num_of_cqs = out.max_num_of_cqs;
	hl_out->max_num_of_db_fifos = out.max_num_of_db_fifos;
	hl_out->max_num_of_encaps = out.max_num_of_encaps;
	hl_out->speed = out.speed;
	hl_out->max_num_of_coll_qps = out.max_num_of_coll_qps;
	hl_out->coll_qps_offset = out.coll_qps_offset;
	hl_out->base_coll_qp_idx = out.base_coll_qp_idx;
	hl_out->base_scale_out_coll_qp_idx = out.base_scale_out_coll_qp_idx;
	hl_out->max_num_of_scale_out_coll_qps = out.max_num_of_scale_out_coll_qps;

	return 0;
}

hlthunk_public int hlthunk_nic_eq_poll(int fd, uint32_t port,
				       struct hlthunk_nic_eq_poll_out *hl_out)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_eq_poll_in in;
	struct hl_nic_eq_poll_out out;
	int rc;

	if (!hl_out)
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	memset(hl_out, 0, sizeof(*hl_out));

	ioctl_args.op = HL_NIC_OP_EQ_POLL;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in;
	ioctl_args.input_size = sizeof(in);
	ioctl_args.output_ptr = (__u64)(uintptr_t)&out;
	ioctl_args.output_size = sizeof(out);

	in.port = port;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	hl_out->poll_status = out.status;
	hl_out->ev_type = out.ev_type;
	hl_out->idx = out.idx;
	hl_out->ev_data = out.ev_data;

	return 0;
}

hlthunk_public int hlthunk_nic_alloc_user_db_fifo(int fd, uint32_t port, uint32_t *id)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_alloc_user_db_fifo_in in;
	struct hl_nic_alloc_user_db_fifo_out out;
	int rc;

	if (!id)
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	ioctl_args.op = HL_NIC_OP_ALLOC_USER_DB_FIFO;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in;
	ioctl_args.input_size = sizeof(in);
	ioctl_args.output_ptr = (__u64)(uintptr_t)&out;
	ioctl_args.output_size = sizeof(out);

	in.port = port;
	in.id_hint = *id;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	*id = out.id;

	return 0;
}

hlthunk_public int hlthunk_nic_user_db_fifo_set(int fd, struct hlthunk_nic_user_db_fifo_set_in *in,
						struct hlthunk_nic_user_db_fifo_set_out *out)
{
	struct hl_nic_user_db_fifo_set_out out_param;
	struct hl_nic_user_db_fifo_set_in in_param;
	struct hl_nic_args ioctl_args;
	int rc;

	if (!in || !out)
		return -EINVAL;

	memset(&out_param, 0, sizeof(out_param));
	memset(&in_param, 0, sizeof(in_param));
	memset(&ioctl_args, 0, sizeof(ioctl_args));

	in_param.port = in->port;
	in_param.id = in->id;
	in_param.mode = in->mode;
	in_param.base_sob_addr = in->base_sob_addr;
	in_param.num_sobs = in->num_sobs;
	in_param.dir_dup_ports_mask = in->dir_dup_ports_mask;

	ioctl_args.op = HL_NIC_OP_USER_DB_FIFO_SET;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in_param;
	ioctl_args.input_size = sizeof(in_param);
	ioctl_args.output_ptr = (__u64)(uintptr_t)&out_param;
	ioctl_args.output_size = sizeof(out_param);

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	out->ci_handle = out_param.ci_handle;
	out->regs_handle = out_param.regs_handle;
	out->regs_offset = out_param.regs_offset;
	out->fifo_size = out_param.fifo_size;
	out->fifo_bp_thresh = out_param.fifo_bp_thresh;

	return 0;
}

hlthunk_public int hlthunk_nic_user_db_fifo_unset(int fd, uint32_t port, uint32_t id)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_user_db_fifo_unset_in in;
	int rc;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&in, 0, sizeof(in));

	ioctl_args.op = HL_NIC_OP_USER_DB_FIFO_UNSET;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in;
	ioctl_args.input_size = sizeof(in);

	in.port = port;
	in.id = id;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	return 0;
}

hlthunk_public int hlthunk_get_habana_link_state(int fd,
						 struct hlthunk_get_habana_link_state_in *in,
						 struct hlthunk_get_habana_link_state_out *out)
{
	struct hl_info_args args;
	struct hl_info_habana_link_state hl_out;
	int rc;

	if (!in || !out)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&hl_out, 0, sizeof(hl_out));

	args.op = HL_INFO_HABANA_LINK_STATE;
	args.return_pointer = (__u64)(uintptr_t)&hl_out;
	args.return_size = sizeof(hl_out);
	args.habana_link_id = in->port;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_INFO, &args);
	if (rc)
		return rc;

	out->up = hl_out.up;

	return 0;
}

hlthunk_public int hlthunk_get_habana_link_statistics(int fd,
						      struct hlthunk_get_habana_link_stat_in *in,
						      struct hlthunk_get_habana_link_stat_out *out)
{
	struct hl_info_args args;
	struct hl_info_habana_link_counters hl_out;
	int rc;

	if (!in || !out)
		return -EINVAL;

	memset(&args, 0, sizeof(args));
	memset(&hl_out, 0, sizeof(hl_out));

	args.op = HL_INFO_HABANA_LINK_COUNTERS;
	args.return_pointer = (__u64)(uintptr_t)&hl_out;
	args.return_size = sizeof(hl_out);
	args.habana_link_id = in->port;

	hl_out.str_buf_ptr = (__u64)(uintptr_t)out->str_buf;
	hl_out.val_buf_ptr = (__u64)(uintptr_t)out->val_buf;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_INFO, &args);
	if (rc)
		return rc;

	out->num_of_stat = hl_out.num_of_stat;

	return 0;
}

hlthunk_public int hlthunk_nic_user_encap_alloc(int fd, uint32_t port, uint32_t *encap_id)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_user_encap_alloc_in in;
	struct hl_nic_user_encap_alloc_out out;
	int rc;

	if (!encap_id)
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	ioctl_args.op = HL_NIC_OP_USER_ENCAP_ALLOC;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in;
	ioctl_args.input_size = sizeof(in);
	ioctl_args.output_ptr = (__u64)(uintptr_t)&out;
	ioctl_args.output_size = sizeof(out);

	in.port = port;

	rc = hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
	if (rc)
		return rc;

	*encap_id = out.id;

	return 0;
}

hlthunk_public int hlthunk_nic_user_encap_set(int fd, const struct hlthunk_encap_cfg *encap_cfg)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_user_encap_set_in in;

	if (!encap_cfg)
		return -EINVAL;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&in, 0, sizeof(in));

	ioctl_args.op = HL_NIC_OP_USER_ENCAP_SET;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in;
	ioctl_args.input_size = sizeof(in);

	in.port = encap_cfg->port;
	in.id = encap_cfg->id;
	in.ipv4_addr = encap_cfg->src_ipv4_addr;
	in.encap_type = encap_cfg->encap_type;
	in.tnl_hdr_size = encap_cfg->tnl_hdr_size;
	in.tnl_hdr_ptr = encap_cfg->tnl_hdr_ptr;

	switch (in.encap_type) {
	case HL_NIC_ENCAP_OVER_UDP:
		in.udp_dst_port = encap_cfg->udp_dst_port;
		break;
	case HL_NIC_ENCAP_OVER_IPV4:
		in.ip_proto = encap_cfg->ip_proto;
		break;
	case HL_NIC_ENCAP_NONE:
		break;
	default:
		return -EINVAL;
	}

	return hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
}

hlthunk_public int hlthunk_nic_user_encap_unset(int fd, uint32_t port, uint32_t encap_id)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_user_encap_unset_in in;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&in, 0, sizeof(in));

	ioctl_args.op = HL_NIC_OP_USER_ENCAP_UNSET;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in;
	ioctl_args.input_size = sizeof(in);

	in.port = port;
	in.id = encap_id;

	return hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
}

hlthunk_public int hlthunk_nic_dump_qp(int fd, uint32_t port, uint32_t qpn, uint32_t req, char *buf,
				       uint32_t buf_size)
{
	struct hl_nic_args ioctl_args;
	struct hl_nic_dump_qp_in in;

	memset(&ioctl_args, 0, sizeof(ioctl_args));
	memset(&in, 0, sizeof(in));

	ioctl_args.op = HL_NIC_OP_DUMP_QP;
	ioctl_args.input_ptr = (__u64)(uintptr_t)&in;
	ioctl_args.input_size = sizeof(in);

	in.port = port;
	in.qpn = qpn;
	in.req = !!req;
	in.user_buf = (__u64)(uintptr_t)buf;
	in.user_buf_size = buf_size;

	return hlthunk_ioctl(fd, DRM_IOCTL_HL_NIC, &ioctl_args);
}

hlthunk_public int hlthunk_nic_get_enabled_ports_mask(int fd, uint64_t *mask)
{
	struct hlthunk_nic_get_ports_masks_out ports_masks;
	enum hlthunk_device_name device_name;
	struct hlthunk_hw_ip_info hw_ip;
	int rc = 0;

	/* NIC ports masks are exposed via IB driver sysfs from Gaudi2 onward. */
	device_name = hlthunk_get_device_name_from_fd(fd);

	if ((device_name != HLTHUNK_DEVICE_GAUDI) &&
	    (device_name != HLTHUNK_DEVICE_GAUDI_HL2000M)) {
		rc = hlthunk_nic_get_ports_masks(fd, &ports_masks);
		if (rc)
			return rc;

		*mask = ports_masks.ports_mask;
	} else {
		rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
		if (rc)
			return rc;

		*mask = hw_ip.nic_ports_mask;
	}

	return rc;
}

hlthunk_public int hlthunk_get_mac_addr_info(int fd, struct hlthunk_mac_addr_info *info)
{
	struct hl_info_module_params hl_info;
	struct ethtool_drvinfo drvinfo;
	struct hl_info_args args;
	struct ethtool_cmd cmd;
	struct ifreq ifr;
	struct if_nameindex *if_nidxs, *intf;
	char pci_bus_id[13], path[PATH_MAX], buf[5], mac[MAC_STR_LEN];
	uint64_t mask = 0, dev_ports_mask;
	ssize_t size;
	int rc = 0, sock, dev_port_fd, port, num_of_ports;

	if (!info)
		return -EINVAL;

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc)
		return -ENODEV;

	memset(&args, 0, sizeof(args));
	memset(&hl_info, 0, sizeof(hl_info));

	rc = hlthunk_nic_get_enabled_ports_mask(fd, &dev_ports_mask);
	if (rc)
		return rc;

	if (!dev_ports_mask) {
		info->mask[0] = 0;
		info->mask[1] = 0;
		return 0;
	}

	/* We don't know what is the ASIC type, so we cannot know how many ports can be supported.
	 * What we can do is to get the total number of ports that can be enabled. We can achieve
	 * that by counting how many bits are to the right of the most significant 1 bit included,
	 * which means in other words to subtract the number of leading zeros starting from the MSB
	 * from the total number of bits available.
	 */
	num_of_ports = sizeof(dev_ports_mask) * CHAR_BIT - (__u64)__builtin_clzll(dev_ports_mask);

	/* get all interfaces names */
	if_nidxs = if_nameindex();
	if (!if_nidxs)
		return -1;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) {
		rc = -1;
		goto free_if_names;
	}

	memset(&ifr, 0, sizeof(ifr));
	memset(&cmd, 0, sizeof(cmd));
	memset(&drvinfo, 0, sizeof(drvinfo));

	/* add the external ports */
	for (intf = if_nidxs; intf->if_index || intf->if_name; intf++) {
		memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
		/* keep a null character at the end */
		strncpy(ifr.ifr_name, intf->if_name, sizeof(ifr.ifr_name) - 1);

		rc = ioctl(sock, SIOCGIFHWADDR, &ifr);
		if (rc)
			goto close_socket;

		memset(mac, 0, MAC_STR_LEN);

		snprintf(mac, MAC_STR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x",
			 (uint8_t)ifr.ifr_addr.sa_data[0], (uint8_t)ifr.ifr_addr.sa_data[1],
			 (uint8_t)ifr.ifr_addr.sa_data[2], (uint8_t)ifr.ifr_addr.sa_data[3],
			 (uint8_t)ifr.ifr_addr.sa_data[4], (uint8_t)ifr.ifr_addr.sa_data[5]);

		ifr.ifr_data = (void *)&drvinfo;
		drvinfo.cmd = ETHTOOL_GDRVINFO;

		/* skip interfaces with no ethtool support */
		if (ioctl(sock, SIOCETHTOOL, &ifr) < 0)
			continue;

		/* skip interfaces of other vendors */
		if (!strstr(drvinfo.driver, "habanalabs"))
			continue;

		/* skip interfaces of other devices */
		if (strstr(drvinfo.bus_info, pci_bus_id) != drvinfo.bus_info)
			continue;

		/* read the interface port */
		snprintf(path, PATH_MAX, "/sys/class/net/%s/dev_port", intf->if_name);

		dev_port_fd = open(path, O_RDONLY);
		if (dev_port_fd == -1) {
			rc = -errno;
			goto close_socket;
		}

		size = read(dev_port_fd, buf, sizeof(buf));
		if (size < 0 || size >= sizeof(buf)) {
			close(dev_port_fd);
			rc = -errno;
			goto close_socket;
		}

		buf[size] = '\0';
		port = (int)strtoul(buf, NULL, 10);
		close(dev_port_fd);

		if (port >= min(sizeof(mask) * CHAR_BIT, ARRAY_SIZE(info->array))) {
			rc = -EINVAL;
			goto close_socket;
		}

		mask |= 1ull << port;

		/* copy the interface MAC */
		parse_mac(info->array[port].addr, mac);
	}

	/* add the internal ports */
	for (port = 0; port < num_of_ports; port++) {
		if ((dev_ports_mask & (1ull << port)) && !(mask & (1ull << port))) {
			mask |= 1ull << port;
			/* The MAC address of internal ports is irrelevant so use broadcast */
			parse_mac(info->array[port].addr, "ff:ff:ff:ff:ff:ff");
		}
	}

	/* set the global ports mask */
	info->mask[0] = mask;
	info->mask[1] = 0;

close_socket:
	close(sock);
free_if_names:
	if_freenameindex(if_nidxs);

	return rc;
}

/* len should be the max amount of bytes one wish to read include the null terminator. */
static int hlthunk_open_and_read(char *path, char *buf, size_t len)
{
	ssize_t size;
	int fd, rc;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	size = read(fd, buf, len - 1);
	if (size <= 0) {
		rc = -errno;
		close(fd);
		return rc;
	}

	rc = close(fd);
	if (rc)
		return -errno;

	buf[size] = '\0';

	return rc;
}

hlthunk_public int hlthunk_nic_get_ports_masks(int fd, struct hlthunk_nic_get_ports_masks_out *out)
{
	char path[PATH_MAX], pci_bus_id[16], read_masks[PORT_MASK_NIBBLES_NUM + 1];
	struct hlthunk_hw_ip_info hw_ip;
	int rc, device_idx;

	rc = hlthunk_get_hw_ip_info(fd, &hw_ip);
	if (rc)
		return rc;

	rc = hlthunk_get_pci_bus_id_from_fd(fd, pci_bus_id, sizeof(pci_bus_id));
	if (rc)
		return -ENODEV;

	device_idx = hlthunk_get_device_index_from_pci_bus_id(pci_bus_id);
	if (device_idx < 0)
		return -EINVAL;

	snprintf(path, PATH_MAX, "/sys/class/infiniband/hbl_%d/ports_mask", device_idx);

	rc = hlthunk_open_and_read(path, read_masks, sizeof(read_masks));
	if (rc) {
		/* SW-149638: TODO remove fallback mechanism once non-IB flow becomes obsolete. */
		if (rc == -ENOENT) {
			out->ports_mask = hw_ip.nic_ports_mask;
			out->ext_ports_mask = hw_ip.nic_ports_external_mask;

			return 0;
		} else {
			return rc;
		}
	}

	out->ports_mask = strtoull(read_masks, NULL, 16);

	snprintf(path, PATH_MAX, "/sys/class/infiniband/hbl_%d/ext_ports_mask", device_idx);

	rc = hlthunk_open_and_read(path, read_masks, sizeof(read_masks));
	if (rc)
		return rc;

	out->ext_ports_mask = strtoull(read_masks, NULL, 16);

	return 0;
}
