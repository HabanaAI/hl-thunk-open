// SPDX-License-Identifier: MIT

/*
 * Copyright 2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 */

#include "hlthunk.h"
#include "hlthunk_nic_tests.h"
#include "hlthunk_tests.h"
#include "infiniband/verbs.h"
#include "reduction_test.h"
#include "ini.h"
#include "config_iterator/config_iterator.h"
#include "nic_root.h"

#include <arpa/inet.h>
#include <asm-generic/errno-base.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <linux/limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ether.h>

#if !defined(HLTESTS_LIB_MODE)
/* These inclues are necessary for cmocka */
#include <setjmp.h>
#include <stdarg.h>

#include <cmocka.h>
#endif /* !defined(HLTESTS_LIB_MODE) */

#include <infiniband/hbldv.h>

#define NUM_CC_USER_FIFOS	1

static int port_to_port_idx(struct hltests_nic_test_cfg *cfg, uint32_t port)
{
	uint32_t port_idx;

	for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
		if (port == cfg->ports[port_idx])
			return (int)port_idx;
	}

	return -EINVAL;
}

static int get_rand_seed_for_port(struct hltests_nic_test_cfg *cfg, uint32_t port)
{
	int port_idx = port_to_port_idx(cfg, port);

	assert_true(port_idx >= 0);

	return (int)cfg->e2e.rand_seed[port_idx];
}

static int get_dst_conn_id_for_qp(struct hltests_nic_test_cfg *cfg, struct hltests_nic_qp *qp_p)
{
	int port_idx = port_to_port_idx(cfg, qp_p->port);

	assert_true(port_idx >= 0);

	return (int)cfg->e2e.dst_conn_ids[port_idx];
}

static const uint8_t *get_dst_mac_for_port(struct hltests_nic_test_cfg *cfg, uint32_t port)
{
	int port_idx = port_to_port_idx(cfg, port);

	assert(port_idx >= 0);

	return cfg->e2e.dst_macs[port_idx].addr;
}

static int32_t get_dst_ip_for_port(struct hltests_nic_test_cfg *cfg, uint32_t port)
{
	int port_idx = port_to_port_idx(cfg, port);

	assert_true(port_idx >= 0);

	return (int32_t)cfg->e2e.dst_ips[port_idx];
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
	       (a->s6_addr32[0] == htobe32(0xff0e0000) &&
		((a->s6_addr32[1] | (a->s6_addr32[2] ^ htobe32(0x0000ffff))) == 0UL));
}

/**
 * Retrieve destination gid/sgid_index based on destination mac or ip.
 */
static int get_dgid_for_qp(struct hltests_nic_qp *qp_p, union ibv_gid *dgid, uint8_t *sgid_index)
{
	struct hltests_nic_responder_conn_ctx *res_ctx;
	struct ibv_qp *ibqp;
	uint8_t ib_port_num;
	int fd, rc, index;
	union ibv_gid gid;
	uint32_t port;

	fd = qp_p->test_params->fd;
	res_ctx = &qp_p->res_ctx;
	port = qp_p->port;
	ib_port_num = (uint8_t)hltests_nic_to_ibdev_port_num(fd, port);
	ibqp = qp_p->ibqp;

	if (res_ctx->dst_ip_addr) {
		struct ibv_port_attr port_attr;
		enum ibv_gid_type_sysfs sgid_type;

		hlibv_query_port(ibqp->context, ib_port_num, &port_attr);
		assert_false(port_attr.gid_tbl_len < 3);

		for (index = 0; index < port_attr.gid_tbl_len; index++) {
			rc = hlibv_query_gid(ibqp->context, ib_port_num, index, &gid);
			assert_int_equal(rc, 0);

			if (ipv6_addr_v4mapped((struct in6_addr *)&gid.raw)) {
				rc = hlibv_query_gid_type(ibqp->context, ib_port_num,
							  (uint32_t)index,
							  &sgid_type);
				assert_int_equal(rc, 0);

				if (sgid_type == IBV_GID_TYPE_SYSFS_ROCE_V2)
					break;
			}
		}

		assert_true(index < port_attr.gid_tbl_len);

		*sgid_index = (uint8_t)index;

		ip_to_gid(res_ctx->dst_ip_addr, (struct in6_addr *)dgid->raw);
	} else {
		uint8_t mac_addr[ETH_ALEN] = {};

		/* Default GID 0 is reserved for MAC address, used for L2 networks */
		*sgid_index = 0;

		hltests_nic_copy_mac_reverse(mac_addr, res_ctx->dst_mac_addr);
		mac_to_gid(mac_addr, dgid);
	}

	return 0;
}

static void set_qps_per_port(struct hltests_nic_test_cfg *cfg, const char *value)
{
	size_t len = strlen(value) > 200 ? 200 : strlen(value);
	char str[INI_MAX_LINE] = {0}, *token;
	uint32_t *ptr, num_elements = 0;

	memcpy(str, value, len);
	token = strtok(str, " ");
	while (token) {
		ptr = &cfg->qps_per_port[num_elements];

		*ptr = (uint32_t)strtoul(token, NULL, 0);

		num_elements++;
		token = strtok(NULL, " ");
	}

	cfg->qps_per_port_num_elements = num_elements;
}

static void set_lpbk_qps_per_port(struct hltests_nic_test_cfg *cfg, const char *value)
{
	size_t len = strlen(value) > 200 ? 200 : strlen(value);
	char str[INI_MAX_LINE] = {0}, *token;
	uint32_t *ptr, num_elements = 0;

	memcpy(str, value, len);
	token = strtok(str, " ");
	while (token) {
		ptr = &cfg->lpbk_qps_per_port[num_elements];

		*ptr = (uint32_t)strtoul(token, NULL, 0);

		if (*ptr)
			cfg->features_bitmap |= BIT_ULL(QP_LPBK);

		num_elements++;
		token = strtok(NULL, " ");
	}

	cfg->lpbk_qps_per_port_num_elements = num_elements;
}

static int nic_common_cfg_parser(void *user, const char *section, const char *name,
				 const char *value)
{
	struct hltests_nic_test_cfg *cfg = (struct hltests_nic_test_cfg *) user;
	size_t len = strlen(value) > 200 ? 200 : strlen(value);
	char str[INI_MAX_LINE] = {0}, *token;
	struct in_addr inp;

	if (MATCH("common", "runtime_iterations")) {
		cfg->runtime_iterations = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("common", "data_loc")) {
		if (!strcmp(value, "host"))
			cfg->data_loc = LOC_HOST;
		else if (!strcmp(value, "dram"))
			cfg->data_loc = LOC_HBM;
		else if (!strcmp(value, "sram"))
			cfg->data_loc = LOC_SRAM;
		else
			cfg->data_loc = LOC_ALL;
	} else if (MATCH("common", "wq_loc")) {
		if (!strcmp(value, "host"))
			cfg->wq_loc = LOC_HOST;
		else if (!strcmp(value, "device"))
			cfg->wq_loc = LOC_HBM;
		else
			cfg->wq_loc = LOC_ALL;
	} else if (MATCH("common", "cmpl")) {
		if (!strcmp(value, "cq"))
			cfg->cmpl = CQ_USR;
		else
			cfg->cmpl = SOB;
	} else if (MATCH("common", "cq_type")) {
		if (!strcmp(value, "port")) {
			cfg->cq_type = HLTESTS_NIC_CQ_TYPE_PORT;
		} else if (!strcmp(value, "device")) {
			cfg->cq_type = HLTESTS_NIC_CQ_TYPE_DEVICE;
		} else if (!strcmp(value, "all")) {
			cfg->cq_type = HLTESTS_NIC_CQ_TYPE_ALL;
		} else {
			fail_msg("Invalid cq_type: [%s]\n", value);
			return 0;
		}
	} else if (MATCH("common", "user_fifo")) {
		cfg->submission = !strcmp(value, "yes") ? USER_FIFO : QMAN;
	} else if (MATCH("common", "avx")) {
		cfg->avx = (uint8_t)strtoul(value, NULL, 0);
		if (cfg->avx != 0 && cfg->avx != 4 && cfg->avx != 8 && cfg->avx != 16) {
			fail_msg("Invalid avx value: [%s]\n", value);
			return 0;
		}
	} else if (MATCH("common", "test_opcode")) {
		if (!strcmp(value, "wr-rdv")) {
			cfg->test_opcode = TEST_OPCODE_RENDEZVOUS_WRITE;
			cfg->features_bitmap |= BIT_ULL(OP_RDV_WRITE);
		} else if (!strcmp(value, "rd-rdv")) {
			cfg->test_opcode = TEST_OPCODE_RENDEZVOUS_READ;
			cfg->features_bitmap |= BIT_ULL(OP_RDV_READ);
		} else if (!strcmp(value, "fna")) {
			cfg->test_opcode = TEST_OPCODE_ATOMIC_FETCH_ADD;
			cfg->features_bitmap |= BIT_ULL(OP_WRITE);
		} else if (!strcmp(value, "write")) {
			cfg->test_opcode = TEST_OPCODE_LINEAR_WRITE;
			cfg->features_bitmap |= BIT_ULL(OP_WRITE);
		} else {
			fail_msg("Invalid test_opcode: [%s]\n", value);
			return 0;
		}
	} else if (MATCH("common", "ports")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			cfg->ports[cfg->ports_num++] = (uint32_t)strtoul(token, NULL, 0);
			token = strtok(NULL, " ");
		}
	} else if (MATCH("common", "qps_per_port")) {
		set_qps_per_port(cfg, value);
	} else if (MATCH("common", "lpbk_qps_per_port")) {
		set_lpbk_qps_per_port(cfg, value);
	} else if (MATCH("common", "data_size_shift")) {
		cfg->data_size_shift = (uint8_t)strtoul(value, NULL, 0);
	} else if (MATCH("common", "wqe_size_shift")) {
		cfg->wqe_size_shift = (uint8_t)strtoul(value, NULL, 0);
	} else if (MATCH("common", "cq_size_shift")) {
		cfg->cq_size_shift = (uint8_t)strtoul(value, NULL, 0);
	} else if (MATCH("common", "mtu")) {
		cfg->mtu = (uint16_t)strtoul(value, NULL, 0);
	} else if (MATCH("common", "user_cq_idx")) {
		cfg->user_cq_idx = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("common", "data_cmp")) {
		cfg->data_cmp = !strcmp(value, "yes");
	} else if (MATCH("common", "single_alloc")) {
		cfg->single_alloc = !strcmp(value, "yes");
	} else if (MATCH("common", "single_cmpl")) {
		cfg->single_cmpl = !strcmp(value, "yes");
	} else if (MATCH("common", "eq_poll")) {
		cfg->eq_poll = !strcmp(value, "yes");
	} else if (MATCH("common", "cleanup")) {
		cfg->cleanup = !strcmp(value, "yes");
	} else if (MATCH("common", "wait_for_cleanup")) {
		cfg->wait_for_cleanup = !strcmp(value, "yes");
	} else if (MATCH("common", "force_wq_with_pmmu")) {
		cfg->force_wq_with_pmmu = !strcmp(value, "yes");
	} else if (MATCH("common", "assign_qp_priority")) {
		cfg->assign_qp_priority = !strcmp(value, "yes");
	} else if (MATCH("common", "verbose")) {
		if (!strcmp(value, "0"))
			cfg->verbose = VERBOSE_NONE;
		else if (!strcmp(value, "1"))
			cfg->verbose = VERBOSE_INFO;
		else
			cfg->verbose = VERBOSE_DEBUG;
	} else if (MATCH("common", "print_bw")) {
		cfg->print_bw = !strcmp(value, "yes");
	} else if (MATCH("common", "wtd_en")) {
		cfg->wtd_en = !strcmp(value, "yes");
		if (cfg->wtd_en)
			cfg->features_bitmap |= BIT_ULL(WTD_DWQ);
	} else if (MATCH("common", "ms_type")) {
		if (!strcmp(value, "single")) {
			cfg->ms_type = NIC_MS_TYPE_SINGLE;
			cfg->features_bitmap |= BIT_ULL(MS_TYPE_SINGLE);
		} else if (!strcmp(value, "dual")) {
			cfg->ms_type = NIC_MS_TYPE_DUAL;
			cfg->features_bitmap |= BIT_ULL(MS_TYPE_DUAL);
		} else {
			cfg->ms_type = NIC_MS_TYPE_NONE;
		}
	} else if (MATCH("common", "reduction_en")) {
		cfg->reduction_en = !strcmp(value, "yes");
		if (cfg->reduction_en)
			cfg->features_bitmap |= BIT_ULL(REDUCTION);
	} else if (MATCH("common", "red_dt")) {
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
	} else if (MATCH("common", "red_op")) {
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
	} else if (MATCH("common", "encap_type")) {
		if (!strcmp(value, "vxlan")) {
			cfg->encap_type = HL_NIC_ENCAP_OVER_UDP;
			cfg->encap_en = true;
			cfg->features_bitmap |= BIT_ULL(ENCAP_TYPE_VXLAN);
		} else if (!strcmp(value, "gre")) {
			cfg->encap_type = HL_NIC_ENCAP_OVER_IPV4;
			cfg->encap_en = true;
			cfg->features_bitmap |= BIT_ULL(ENCAP_TYPE_GRE);
		} else {
			cfg->encap_type = HL_NIC_ENCAP_NONE;
		}
	} else if (MATCH("common", "src_ip")) {
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

		cfg->encap_en = true;
		cfg->features_bitmap |= BIT_ULL(ENCAP_TYPE_SRC_IP);
	} else if (MATCH("common", "cc_mode")) {
		if (!strcmp(value, "bbr")) {
			cfg->cc_mode = CC_MODE_BBR;
			cfg->features_bitmap |= BIT_ULL(CC_BBR);
		} else if (!strcmp(value, "swift")) {
			cfg->cc_mode = CC_MODE_SWIFT;
			cfg->features_bitmap |= BIT_ULL(CC_SWIFT);
		} else {
			cfg->cc_mode = CC_MODE_DISABLED;
		}
	} else if (MATCH("common", "odp_en")) {
		cfg->odp_en = !strcmp(value, "yes");

		if (cfg->odp_en)
			cfg->features_bitmap |= BIT_ULL(ODP);
	} else if (MATCH("common", "sack_en")) {
		cfg->sack_en = !strcmp(value, "yes");

		if (cfg->sack_en)
			cfg->features_bitmap |= BIT_ULL(SACK);
	} else if (MATCH("common", "compression_en")) {
		cfg->compression_en = !strcmp(value, "yes");

		if (cfg->compression_en)
			cfg->features_bitmap |= BIT_ULL(COMPRESSION);
	} else if (MATCH("common", "plain_rdma")) {
		cfg->plain_rdma_en = !strcmp(value, "yes");

		if (cfg->plain_rdma_en)
			cfg->features_bitmap |= BIT_ULL(PLAIN_RDMA);
	} else if (MATCH("common", "rdv_type")) {
		if (!strcmp(value, "ms"))
			cfg->rdv_type = HLTESTS_NIC_RDV_MS;
		else if (!strcmp(value, "v-op"))
			cfg->rdv_type = HLTESTS_NIC_RDV_V_OP;
		else
			cfg->rdv_type = HLTESTS_NIC_RDV_SND_RCV;
	} else if (MATCH("migration", "enable")) {
		cfg->migration.enable = !strcmp(value, "yes");
	} else if (MATCH("migration", "check_event")) {
		cfg->migration.check_event = !strcmp(value, "yes");
	} else if (MATCH("migration", "old_port")) {
		if (!strcmp(value, "last")) {
			/* Trick to allow setting the index to the last available port */
			cfg->migration.old_port = INT32_MAX;
			return 1;
		}

		if (!strcmp(value, "first")) {
			/* Trick to allow setting the index to the first available port */
			cfg->migration.old_port = INT32_MIN;
			return 1;
		}

		int32_t temp = (int32_t)strtoul(value, NULL, 0);

		if (errno == ERANGE || temp > MAX_NIC_NUMBER_OF_PORTS) {
			E("old_port out of range!");
			return 0;
		}

		cfg->migration.old_port = temp;
	} else if (MATCH("migration", "new_port")) {
		if (!strcmp(value, "last")) {
			/* Trick to allow setting the index to the last available port */
			cfg->migration.new_port = INT32_MAX;
			return 1;
		}

		if (!strcmp(value, "first")) {
			/* Trick to allow setting the index to the first available port */
			cfg->migration.new_port = INT32_MIN;
			return 1;
		}

		int32_t temp = (int32_t)strtoul(value, NULL, 0);

		if (errno == ERANGE || temp > MAX_NIC_NUMBER_OF_PORTS) {
			E("new_port out of range!");
			return 0;
		}

		cfg->migration.new_port = temp;
	} else if (MATCH("migration", "runtime_iterations_trigger")) {
		uint32_t temp = (uint32_t)strtoul(value, NULL, 0);

		if (errno == ERANGE || temp > MAX_NIC_NUMBER_OF_PORTS) {
			E("runtime_iterations_trigger out of range!");
			return 0;
		}

		cfg->migration.runtime_iterations_trigger = temp;
	} else if (MATCH("common", "keys_en")) {
		cfg->keys_en = !strcmp(value, "yes");

		if (cfg->keys_en)
			cfg->features_bitmap |= BIT_ULL(RDMA_KEYS_IN_WQE);
	} else if (MATCH("common", "wqe_rd")) {
		if (!strcmp(value, "yes"))
			cfg->rd_en = true;
		else
			cfg->rd_en = false;

	} else if (MATCH("e2e", "e2e")) {
		cfg->e2e.enabled = !strcmp(value, "yes");
	} else if (MATCH("e2e", "seconds_to_wait_to_submit")) {
		cfg->e2e.seconds_to_wait_to_submit = (uint32_t)strtoul(value, NULL, 0);
	} else if (MATCH("e2e", "dst_ips")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			if (!inet_aton(token, &inp)) {
				E("dst ip %s is invalid", token);
				return 0;
			}
			if (cfg->e2e.num_dst_ips >= ARRAY_SIZE(cfg->e2e.dst_ips) - 1) {
				E("too many destination ips for e2e provided");
				return 0;
			}
			cfg->e2e.dst_ips[cfg->e2e.num_dst_ips++] = be32toh(inp.s_addr);
			token = strtok(NULL, " ");
		}
	} else if (MATCH("e2e", "dst_macs")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			if (cfg->e2e.num_dst_macs >= ARRAY_SIZE(cfg->e2e.dst_macs) - 1) {
				E("too many destination macs for e2e provided");
				return 0;
			}
			hltests_nic_parse_mac(cfg->e2e.dst_macs[cfg->e2e.num_dst_macs++].addr,
					      token);
			token = strtok(NULL, " ");
		}
	} else if (MATCH("e2e", "dst_conn_ids")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			if (cfg->e2e.num_dst_conn_ids >= ARRAY_SIZE(cfg->e2e.dst_conn_ids) - 1) {
				E("too many destination macs for e2e provided");
				return 0;
			}
			cfg->e2e.dst_conn_ids[cfg->e2e.num_dst_conn_ids++] =
				(uint32_t)strtoul(token, NULL, 0);
			token = strtok(NULL, " ");
		}
	} else if (MATCH("e2e", "seed")) {
		memcpy(str, value, len);
		token = strtok(str, " ");
		while (token) {
			if (cfg->e2e.num_seeds >= ARRAY_SIZE(cfg->e2e.rand_seed) - 1) {
				E("too many seeds for e2e provided");
				return 0;
			}
			cfg->e2e.rand_seed[cfg->e2e.num_seeds++] =
				(uint32_t)strtoul(token, NULL, 0);
			token = strtok(NULL, " ");
		}
	} else {
		return 0; /* unknown section/name, error */
	}

	return 1;
}

static int init_test_funcs(int fd, enum hltests_nic_test_type test_type)
{
	struct hltests_nic_test_ctx *test_ctx;

	test_ctx = get_nic_ctx_from_fd(fd);

	switch (test_type) {
	case NIC_TEST_TYPE_BASIC:
		nic_basic_set_test_funcs(fd);
		break;
	case NIC_TEST_TYPE_COLL:
		nic_collective_set_test_funcs(fd);
		break;
	case NIC_TEST_TYPE_BP_OFFS:
		nic_bp_offs_set_test_funcs(fd);
		break;
	case NIC_TEST_TYPE_ATOMIC_FNA:
		nic_afa_set_test_funcs(fd);
		break;
	case NIC_TEST_TYPE_PLAIN_RDMA:
		break;
	default:
		printf("invalid test type: [%u]\n", test_type);
		fail();
	}

	test_ctx->type = test_type;

	return 0;
}

static void print_cfg(struct hltests_nic_test_cfg *cfg)
{
	int port_idx;

	printf("\n");

	printf("ports to run:                           ");
	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++)
		printf(" %4u", cfg->ports[port_idx]);

	printf("\n");

	printf("total qps_per_port:                     ");
	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++)
		printf(" %4u", cfg->qps_per_port[port_idx]);

	printf("\n");

	if (cfg->lpbk_qps_per_port_num_elements) {
		printf("lpbk_qps_per_port:                      ");
		for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++)
			printf(" %4u", cfg->lpbk_qps_per_port[port_idx]);

		printf("\n");
	}

	printf("\n");

	printf("runtime_iterations: %d\n", cfg->runtime_iterations);
	printf("data_loc: %d, wq_loc: %d\n", cfg->data_loc, cfg->wq_loc);
	printf("data_size: 1 << %d, wqe_size: 1 << %d, cq_size: 1 << %d\n", cfg->data_size_shift,
		cfg->wqe_size_shift, cfg->cq_size_shift);
	printf("submission: %d, cmpl: %d, single_cmpl: %d, single_alloc: %d, mtu: %d%s\n",
		cfg->submission, cfg->cmpl, cfg->single_cmpl, cfg->single_alloc, cfg->mtu,
		(!cfg->mtu ? "(default)":""));
	printf("data_cmp: %d, cleanup: %d, wait_for_cleanup: %d, verbose: %d\n",
		cfg->data_cmp, cfg->cleanup, cfg->wait_for_cleanup, cfg->verbose);
	printf("test_opcode: %d, rdv_type: %d, eq_poll: %d, wtd_en: %d\n",
		cfg->test_opcode, cfg->rdv_type, cfg->eq_poll, cfg->wtd_en);
	printf("reduction_en: %d, red_data_type: %d, reduction_operation: %d\n",
		cfg->reduction_en, cfg->red_dt, cfg->red_op);
	printf("encap_en: %d, encap_type: %d, cc_mode: %d, compression_en: %d, odp_en: %d\n",
		cfg->encap_en, cfg->encap_type, cfg->cc_mode, cfg->compression_en, cfg->odp_en);
	printf("keys_en: %d, sack_en: %d, force_wq_with_pmmu: %d, print_bw: %d\n",
		cfg->keys_en, cfg->sack_en, cfg->force_wq_with_pmmu, cfg->print_bw);

	if (cfg->migration.enable)
		printf("migration enable: %u, old_port: %d, new_port: %d, trigger:%u, event: %u\n",
		       cfg->migration.enable, cfg->migration.old_port, cfg->migration.new_port,
		       cfg->migration.runtime_iterations_trigger, cfg->migration.check_event);
	if (cfg->e2e.enabled) {
		int i;

		printf("e2e:\n");
		printf("wait_to_submit: %u dst_macs: %u dst_ips: %u dst_conn_ids %u seeds %u\n",
		       cfg->e2e.seconds_to_wait_to_submit, cfg->e2e.num_dst_macs,
		       cfg->e2e.num_dst_ips, cfg->e2e.num_dst_conn_ids, cfg->e2e.num_seeds);
		for (i = 0; i < cfg->e2e.num_dst_conn_ids; i++)
			printf("dst_conn_ids[%d]: %u\n", i, cfg->e2e.dst_conn_ids[i]);
		for (i = 0; i < cfg->e2e.num_dst_ips; i++)
			printf("dst_ips[%d]: 0x%08x\n", i, cfg->e2e.dst_ips[i]);
		for (i = 0; i < cfg->e2e.num_seeds; i++)
			printf("seed[%d]: %u\n", i, cfg->e2e.rand_seed[i]);
		for (i = 0; i < cfg->e2e.num_dst_macs; i++)
			printf("dst_macs[%d]: %s\n", i,
			       ether_ntoa((struct ether_addr *)&cfg->e2e.dst_macs[i]));
	}
	printf("\n");
}

static void dump_cqes_status_to_file(struct hltests_nic_test_params *params, char *f_req_path,
				     char *f_res_path, uint32_t max_num_of_qps)
{
	struct hltests_nic_test_funcs *funcs = params->test_ctx->funcs;
	struct hltests_nic_qp *qp_p;
	FILE *f_req, *f_res;

	f_req = fopen(f_req_path, "wb");
	f_res = fopen(f_res_path, "wb");

	for (uint32_t q = 1; q <= max_num_of_qps; q++) {
		for (uint32_t p = 0; p < params->max_num_of_ports; p++) {
			if (!(BIT(p) & params->cfg->ports_mask))
				continue;

			if (q <= params->num_qps_per_port[p]) {
				qp_p = funcs->find_qp_by_port_and_qpn(params, p, q);

				if (!qp_p) {
					D("q: %u port: %u not found", q, p);
					continue;
				}

				fprintf(f_req, "%s,", (qp_p->req_comp_params.total_cqes ==
						       qp_p->req_comp_params.recv_cqes)
						       ? "V" : ".");
				fprintf(f_res, "%s,", (qp_p->res_comp_params.total_cqes ==
						       qp_p->res_comp_params.recv_cqes)
						       ? "V" : ".");
			} else {
				fprintf(f_req, ",");
				fprintf(f_res, ",");
			}
		}

		fprintf(f_req, "\n");
		fprintf(f_res, "\n");
	}

	fclose(f_req);
	fclose(f_res);
}

static int set_migration_ports(struct hltests_nic_test_params *params)
{
	struct hlthunk_nic_get_ports_masks_out masks_info;
	struct hltests_nic_test_cfg *cfg = params->cfg;
	int fd = params->fd, rc = 0;
	ssize_t i = 0;

	rc = hlthunk_nic_get_ports_masks(fd, &masks_info);
	if (rc) {
		errno = rc;
		E("failed to get ports mask!");

		return rc;
	}

	/* Find first external port and set it depending on migration conf */
	for (i = 0; i < cfg->ports_num; i++) {
		uint32_t port = cfg->ports[i];

		if (!(BIT_ULL(port) & masks_info.ext_ports_mask))
			continue;

		if (cfg->migration.new_port == INT32_MIN)
			cfg->migration.new_port = (int32_t)port;

		if (cfg->migration.old_port == INT32_MIN)
			cfg->migration.old_port = (int32_t)port;

		break;
	}

	/* Find last external port and set it depending on migration conf */
	for (i = cfg->ports_num; i > 0; i--) {
		uint32_t port = cfg->ports[i - 1];

		if (!(BIT_ULL(port) & masks_info.ext_ports_mask))
			continue;

		if (cfg->migration.new_port == INT32_MAX)
			cfg->migration.new_port = (int32_t)port;

		if (cfg->migration.old_port == INT32_MAX)
			cfg->migration.old_port = (int32_t)port;

		break;
	}

	return 0;
}

static int parse_cfg(struct hltests_nic_test_params *params)
{
	const char *config_filename = hltests_get_config_filename();
	struct hltests_nic_test_ctx *test_ctx;
	struct hltests_nic_test_cfg *cfg;
	uint64_t nic_ports_mask, max_num_of_ports, test_ports_mask = 0;
	uint32_t port;
	int fd, port_idx, rc;

	fd = params->fd;
	test_ctx = params->test_ctx;
	nic_ports_mask = test_ctx->tests_state->nic_ports_mask;
	max_num_of_ports = params->max_num_of_ports;

	cfg = hlthunk_malloc(sizeof(*cfg));
	assert_non_null(cfg);

	params->cfg = cfg;

	/* The default value of CQ size will be 2^13 */
	cfg->cq_size_shift = 13;
	cfg->e2e.enabled = 0;
	cfg->e2e.seconds_to_wait_to_submit = 5;

	/* TODO: need to add default config in case no cfg file */
	if (ini_parse(config_filename, nic_common_cfg_parser, cfg) < 0) {
		fail_msg("Can't load %s\n", config_filename);
		return -EFAULT;
	}

	if (cfg->ports_num) {
		for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
			port = cfg->ports[port_idx];
			assert_int_not_equal(nic_ports_mask & (1ULL << port), 0);
			test_ports_mask |= (1ULL << port);
		}
	} else {
		for (port = 0, port_idx = 0 ; port < max_num_of_ports ; port++) {
			if (!(nic_ports_mask & (1ULL << port)))
				continue;

			cfg->ports[port_idx++] = port;
			cfg->ports_num++;
		}

		test_ports_mask = nic_ports_mask;
	}

	cfg->ports_mask = test_ports_mask;

	assert_true(cfg->qps_per_port_num_elements >= 1);

	if (cfg->qps_per_port_num_elements > 1) {
		/* there are only two valid options: set a single qps_per_port for all ports, or set
		 * a unique qps_per_port for each port. in case of the later, the number of the
		 * values should be equal to the number of the given ports.
		 */
		assert_int_equal(cfg->ports_num, cfg->qps_per_port_num_elements);
	} else {
		/* For the case when port list is not given, use same first qps_per_port for all
		 * enabled ports.
		 */
		for (port_idx = 1 ; port_idx < cfg->ports_num ; port_idx++)
			cfg->qps_per_port[port_idx] = cfg->qps_per_port[0];
	}

	if (cfg->lpbk_qps_per_port_num_elements > 1) {
		assert_int_equal(cfg->ports_num, cfg->lpbk_qps_per_port_num_elements);
	} else if (cfg->lpbk_qps_per_port_num_elements == 1) {
		for (port_idx = 1 ; port_idx < cfg->ports_num ; port_idx++)
			cfg->lpbk_qps_per_port[port_idx] = cfg->lpbk_qps_per_port[0];
	}

	/* For each port, the number of LPBK QPs represents how many QPs from the total QPs are
	 * loopback, hence it can't be greater than the number of QPs
	 */
	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++)
		assert_false(cfg->lpbk_qps_per_port[port_idx] > cfg->qps_per_port[port_idx]);

	rc = test_ctx->funcs->parse_cfg(fd, cfg);
	if (rc)
		return rc;

	/* Update migration ports */
	if (cfg->migration.enable)
		set_migration_ports(params);

	if (cfg->verbose) {
		print_cfg(cfg);

		if (test_ctx->funcs->print_cfg)
			test_ctx->funcs->print_cfg(cfg);
	}

	hltests_nic_print_time_elapsed(&params->base, "parse cfg", cfg->verbose);

	return 0;
}

static int validate_cfg(struct hltests_nic_test_params *params)
{
	struct hlthunk_nic_get_ports_masks_out masks_info;
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint64_t supported_features_mask, lpbk_mask;
	struct hltests_nic_test_ctx *test_ctx;
	struct hltests_state *tests_state;
	struct hlthunk_hw_ip_info *hw_ip;
	int rc, fd;

	fd = params->fd;
	test_ctx = params->test_ctx;
	tests_state = test_ctx->tests_state;
	hw_ip = &tests_state->hw_ip;

	rc = hlthunk_nic_get_ports_masks(fd, &masks_info);
	if (rc) {
		errno = rc;
		E("failed to get ports mask!");

		return rc;
	}

	supported_features_mask = test_ctx->funcs->get_supported_features_mask(fd);
	if ((cfg->features_bitmap & supported_features_mask) != cfg->features_bitmap) {
		printf("requested features bmap 0x%lx vs supported features bmap 0x%lx\n",
		       cfg->features_bitmap, supported_features_mask);
		fail();
	}

	if (!hw_ip->dram_enabled) {
		if (cfg->reduction_en)
			/* This error code will indicate that we need to skip this test */
			return -ENOTSUP;

		if (cfg->data_loc == LOC_ALL || cfg->data_loc == LOC_HBM) {
			printf("dram isn't enabled, hence data location is set to HOST\n");
			cfg->data_loc = LOC_HOST;
		}

		if (cfg->wq_loc == LOC_ALL || cfg->wq_loc == LOC_HBM) {
			printf("dram isn't enabled, hence WQ location is set to HOST\n");
			cfg->wq_loc = LOC_HOST;
		}
	}

	/* ODP is supported from kernel version 5.5 and above */
	if (cfg->odp_en && !hw_ip->odp_supported)
		/* This error code will indicate that we need to skip this test */
		return -ENOTSUP;

	rc = hltests_nic_get_mac_loopback_mask(fd, &lpbk_mask);
	assert_int_equal(rc, 0);

	/* Notify the user that MAC loopback is not set. The test may still continue, as external
	 * loopback or QP lpbk (Gaudi3 and above) might be used.
	 */
	if (((cfg->ports_mask & lpbk_mask) != cfg->ports_mask))
		printf("Note - MAC loopback is not set\n\n");

	assert_true(cfg->data_size_shift < sizeof(uint64_t) * CHAR_BIT);
	assert_true(cfg->wqe_size_shift < sizeof(uint32_t) * CHAR_BIT);

	assert_true(!cfg->mtu || cfg->mtu == SZ_1K || cfg->mtu == SZ_2K || cfg->mtu == SZ_4K ||
		    cfg->mtu == SZ_8K);

	/* QMAN is supported only for Gaudi2 */
	assert_true(cfg->submission != QMAN || hltests_is_gaudi2(fd));

	/* running with multiple memory iterations requires doing full cleanup so we won't fail in
	 * the next initialization phase.
	 */
	assert_true(cfg->data_loc != LOC_ALL || cfg->cleanup);

	/* We can force WQ access using PMMU only if WQ resides on HOST */
	assert_true(!cfg->force_wq_with_pmmu || cfg->wq_loc == LOC_HOST);

	/* If compression is enabled, data size must be In chunks of 128 bytes (HW limitation) */
	assert_true(!cfg->compression_en || BIT(cfg->data_size_shift) >= SZ_128);

	/* In Gaudi3, compression and QP loopback are not supported together */
	assert_false(hltests_is_gaudi3(fd) && cfg->compression_en &&
		     (cfg->features_bitmap & BIT_ULL(QP_LPBK)));

	if (IS_RDV(cfg->features_bitmap)) {
		uint64_t data_size = BIT_ULL(cfg->data_size_shift);
		uint32_t wqe_size = BIT(cfg->wqe_size_shift);
		uint32_t num_of_wqes = (uint32_t)(data_size / wqe_size);
		int port_idx;

		/* The number of WQEs should always be a power of 2 */
		assert_true(__builtin_popcount(num_of_wqes) == 1);

		/* In Gaudi3, due to H/W bug H9-5709, the number of WQEs should be at least 32 */
		assert_false(hltests_is_gaudi3(fd) && (num_of_wqes < 32));

		/* In Gaudi3, RDV and QP loopback are not supported */
		assert_false(hltests_is_gaudi3(fd) && (cfg->features_bitmap & BIT_ULL(QP_LPBK)));

		/* In RDV, the number of QPs in each port must be even */
		for (port_idx = 0; port_idx < cfg->ports_num; port_idx++)
			assert_false(cfg->qps_per_port[port_idx] & 0x1);
	}

	if (cfg->reduction_en) {
		assert_true(cfg->data_loc == LOC_HBM ||
			    (cfg->data_loc == LOC_SRAM && !hltests_is_gaudi2(fd)));
		assert_true((cfg->red_op != HLTESTS_NIC_REDUCTION_OP_INVALID) &&
			    (cfg->red_dt != HLTESTS_NIC_REDUCTION_DT_INVALID));
		assert_true(!cfg->single_alloc);

		/* 'sub' operation isn't supported in Gaudi3 (H9-5261) */
		assert_false(hltests_is_gaudi3(fd) &&
			     (cfg->red_op == HLTESTS_NIC_REDUCTION_OP_SUBTRACTION));
	}

	if (cfg->cc_mode != CC_MODE_DISABLED) {
		/* H6-3280: In Gaudi2 the CC test should run only on the external ports as
		 * congestion window is disabled on internal ports.
		 */
		if (hltests_is_gaudi2(fd)) {
			assert_true((masks_info.ext_ports_mask & cfg->ports_mask) ==
				    cfg->ports_mask);
		}

		/* cc isn't supported on simulator */
		assert_false(hltests_is_simulator(fd));
	}

	assert_false(cfg->print_bw && (cfg->qps_per_port_num_elements > 1));

	if (cfg->migration.enable) {
		/* New and old ports must have been updated to real values */
		assert_true(cfg->migration.new_port != INT32_MAX &&
			    cfg->migration.new_port != INT32_MIN);
		assert_true(cfg->migration.old_port != INT32_MAX &&
			    cfg->migration.old_port != INT32_MIN);

		/* Both migration ports must be external */
		assert_true(BIT_ULL(cfg->migration.new_port) & masks_info.ext_ports_mask);
		assert_true(BIT_ULL(cfg->migration.old_port) & masks_info.ext_ports_mask);

		/* Migration ports have to be different */
		assert_true(cfg->migration.new_port != cfg->migration.old_port);
	}

	if (cfg->e2e.enabled) {
		/* For e2e we currently require HBM, since then both peers
		 * automatically use the same addresses
		 */
		assert_true(cfg->data_loc == LOC_HBM);
		assert_true(cfg->e2e.num_dst_conn_ids == cfg->ports_num);
		assert_true(cfg->e2e.num_dst_macs == cfg->ports_num);
		assert_true(cfg->e2e.num_seeds == cfg->ports_num);
		assert_true(cfg->e2e.num_dst_ips == 0 || cfg->e2e.num_dst_ips == cfg->ports_num);
	}

	rc = test_ctx->funcs->validate_cfg(fd, cfg);
	if (rc)
		return rc;

	hltests_nic_print_time_elapsed(&params->base, "validate cfg", cfg->verbose);

	return 0;
}

static int __set_cq_params(struct hltests_nic_test_params *params, struct hltests_nic_cq *cqs)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_test_ctx *test_ctx;
	struct hltests_state *tests_state;
	uint32_t user_cq_buf_len;
	int fd, i;

	fd = params->fd;
	test_ctx = params->test_ctx;
	tests_state = test_ctx->tests_state;

	user_cq_buf_len = BIT(cfg->cq_size_shift);

	for (i = 0 ; i <= cfg->user_cq_idx ; i++) {
		cqs[i].user_cq.port_mask[0] = cfg->ports_mask;
		cqs[i].tests_state = tests_state;
		cqs[i].user_cq.cq_buf_len = user_cq_buf_len;
		cqs[i].cq_buf_len = next_pow2(user_cq_buf_len * params->max_num_of_ports);
		cqs[i].type = params->cq_type;
	}

	if (test_ctx->funcs->set_cq_params)
		test_ctx->funcs->set_cq_params(params);

	return 0;
}

static int set_cq_params(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_cq *rd_cqs, *rd_cq;
	struct hltests_nic_cq *cqs, *cq;
	int rc;

	/* Allocate a bunch of CQs, we're only going to use the last one.
	 * This is done to allow testing higher index CQs / testing allocation of many CQs.
	 */
	cqs = calloc(cfg->user_cq_idx + 1, sizeof(*cqs));
	assert_non_null(cqs);

	cq = &cqs[cfg->user_cq_idx];

	/* Store all the CQs so we can create/destroy them later */
	params->cqs = cqs;

	/* This CQ will be used in the tests */
	params->cq = cq;

	rc = __set_cq_params(params, params->cqs);
	assert_int_equal(rc, 0);

	/* This RD CQ is used for RD WQE test */
	if (cfg->rd_en) {
		rd_cqs = calloc(cfg->user_cq_idx + 1, sizeof(*rd_cqs));
		assert_non_null(rd_cqs);

		rd_cq = &rd_cqs[cfg->user_cq_idx];

		params->rd_cqs = rd_cqs;

		params->rd_cq = rd_cq;

		rc = __set_cq_params(params, params->rd_cqs);
		assert_int_equal(rc, 0);
	}

	return 0;
}

static void unset_cq_params(struct hltests_nic_test_params *params)
{
	hlthunk_free(params->cqs);

	if (params->cfg->rd_en)
		hlthunk_free(params->rd_cqs);
}

static int alloc_generic_qps_db(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_qp *qps_array, *qp_p;
	uint32_t port, qp, qps_per_port, lpbk_qps_per_port;
	int port_idx;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		qps_per_port = cfg->qps_per_port[port_idx];
		if (!qps_per_port)
			continue;

		port = cfg->ports[port_idx];
		lpbk_qps_per_port = cfg->lpbk_qps_per_port[port];
		params->num_qps_per_port[port] = qps_per_port;

		qps_array = hlthunk_malloc(sizeof(*qps_array) * qps_per_port);
		assert_non_null(qps_array);

		for (qp = 0; qp < qps_per_port; qp++) {
			qp_p = &qps_array[qp];

			qp_p->test_params = params;
			qp_p->id = qp;
			qp_p->port = port;

			if (IS_RDV(cfg->features_bitmap)) {
				if (qp & 0x1) {
					qp_p->is_rdv_sender = true;
					qp_p->rdv_recv_qp = &qps_array[qp - 1];
				} else {
					qp_p->rdv_send_qp = &qps_array[qp + 1];
				}
			}

			if (qp < lpbk_qps_per_port)
				qp_p->is_lpbk = true;

			if (cfg->cmpl == CQ_USR) {
				bool *req_comp_map, *res_comp_map;
				uint32_t num_wqes_in_wq = params->num_wqes_in_wq;

				req_comp_map =
					hlthunk_malloc(num_wqes_in_wq * sizeof(*req_comp_map));
				assert_non_null(req_comp_map);

				res_comp_map =
					hlthunk_malloc(num_wqes_in_wq * sizeof(*res_comp_map));
				assert_non_null(res_comp_map);

				qp_p->req_comp_params.cmpl_map = req_comp_map;
				qp_p->res_comp_params.cmpl_map = res_comp_map;
				qp_p->req_comp_params.cmpl_map_length = num_wqes_in_wq;
				qp_p->res_comp_params.cmpl_map_length = num_wqes_in_wq;
			}
		}

		params->qps[port] = qps_array;
	}

	/* Raise a flag in case at least one of the ports needs generic QPs - This flag will be
	 * checked in later generic QPs related function.
	 */
	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		qps_per_port = cfg->qps_per_port[port_idx];
		if (!qps_per_port)
			continue;

		params->use_generic_qps = true;
		break;
	}

	if (cfg->migration.enable) {
		switch (params->test_ctx->type) {
		case NIC_TEST_TYPE_BASIC:
			/* We want the same amount of QPS as in the old port */
			qps_per_port = (uint32_t)params->num_qps_per_port[cfg->migration.old_port];
			lpbk_qps_per_port = cfg->lpbk_qps_per_port[cfg->migration.old_port];
			break;
		case NIC_TEST_TYPE_COLL:
			/* All coll ports have same amount of QPs */
			qps_per_port = (uint32_t)cfg->coll_qps_count[cfg->coll_type];
			lpbk_qps_per_port = (uint32_t)cfg->coll_lpbk_qps_count[cfg->coll_type];
			break;
		default:
			fail_msg("QP Migration not implemented for test type %u",
				 params->test_ctx->type);
			return -ENOTSUP;
		}

		if (!qps_per_port)
			return 0;

		qps_array = hlthunk_malloc(sizeof(*qps_array) * qps_per_port);
		assert_non_null(qps_array);

		for (qp = 0; qp < qps_per_port; qp++) {
			qp_p = &qps_array[qp];

			qp_p->test_params = params;
			/* The new QPs IDs should continue where the old ones finished, align up to
			 * not break rdv
			 */
			qp_p->id = qp;

			/* The new QPs belong to the new port */
			qp_p->port = (uint32_t)cfg->migration.new_port;

			if (IS_RDV(cfg->features_bitmap)) {
				if (qp & 0x1) {
					qp_p->is_rdv_sender = true;
					qp_p->rdv_recv_qp = &qps_array[qp - 1];
				} else {
					qp_p->rdv_send_qp = &qps_array[qp + 1];
				}
			}

			if (qp < lpbk_qps_per_port)
				qp_p->is_lpbk = true;
		}

		params->migration.qps = qps_array;
	}

	return 0;
}

static int alloc_qps_db(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_ctx *test_ctx = params->test_ctx;
	int rc;

	rc = alloc_generic_qps_db(params);
	if (rc)
		return rc;

	rc = test_ctx->funcs->alloc_qps_db(params);

	return rc;
}

static void fill_buffers(struct hltests_nic_test_params *params, uint32_t port, void *src_buf,
			 void *dst_buf)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint64_t src_size, dst_size;
	int rc;

	src_size = params->data_size;
	dst_size = params->dst_data_size;

	if (cfg->reduction_en) {

		if (cfg->red_dt == HLTESTS_NIC_REDUCTION_BF16 || params->upscale_en)
			fill_buffer_bfloat16(src_buf, src_size);
		else if (cfg->red_dt == HLTESTS_NIC_REDUCTION_FP32 || params->downscale_en ||
				cfg->red_dt == HLTESTS_NIC_REDUCTION_BF16_DOWN_AND_UP)
			fill_buffer_fp32(src_buf, src_size);
		else
			hltests_fill_rand_values(src_buf, src_size);

		if (cfg->red_dt == HLTESTS_NIC_REDUCTION_BF16)
			fill_buffer_bfloat16(dst_buf, dst_size);
		else if (cfg->red_dt == HLTESTS_NIC_REDUCTION_FP32 ||
			cfg->red_dt == HLTESTS_NIC_REDUCTION_BF16_DOWN_AND_UP)
			fill_buffer_fp32(dst_buf, dst_size);
		else if (params->upscale_en)
			fill_buffer_fp32(dst_buf, dst_size);
		else if (params->downscale_en)
			/* we are filling to half the size because upon downscale the total data
			 * size would be halved
			 */
			fill_buffer_bfloat16(dst_buf, dst_size);
		else
			hltests_fill_rand_values(dst_buf, dst_size);
	} else {
		if (!cfg->e2e.enabled) {
			hltests_fill_rand_values(src_buf, src_size);
		} else {
			/*
			 * For e2e both peers will use the same seed for the
			 * comparison to work.
			 */
			rc = get_rand_seed_for_port(cfg, port);
			if (rc < 0) {
				errno = EINVAL;
				E("Cannot get random seed, invalid port %d", port);

				return;
			}

			hltests_set_rand_seed((uint32_t)rc);
			hltests_fill_rand_values(src_buf, src_size);
			/* randomize it back */
			hltests_set_rand_seed((uint32_t)time(NULL));
		}

		if (params->cfg->plain_rdma_en) {
			uint64_t *src_guard = (uint64_t *)
				((uint8_t *) src_buf + (src_size - PLAIN_RDMA_MAGIC_SIZE));

			*src_guard = PLAIN_RDMA_MAGIC;
		}

		memset(dst_buf, 0xFF, dst_size);
	}
}

static int alloc_generic_host_mem_buffers(struct hltests_nic_test_params *params)
{
	struct hltests_nic_qp **qps_db = params->qps;
	struct hltests_nic_test_cfg *cfg = params->cfg;
	size_t port_idx;

	if (!params->use_generic_qps)
		return 0;

	for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
		size_t qp_idx;
		uint32_t port = cfg->ports[port_idx];
		uint32_t qps_per_port = (uint32_t)params->num_qps_per_port[port];

		for (qp_idx = 0; qp_idx < qps_per_port; qp_idx++) {
			struct hltests_nic_qp *qp_p = &qps_db[port][qp_idx];
			int rc;

			if (cfg->single_alloc && qp_idx) {
				qp_p->host_src_buf = qps_db[port][0].host_src_buf;
				qp_p->host_dst_buf = qps_db[port][0].host_dst_buf;

				continue;
			}

			rc = nic_common_alloc_qp_mem_buffers(params, qp_p);
			assert_int_equal(rc, 0);
		}
	}

	return 0;
}

static int alloc_host_mem_buffers(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_ctx *test_ctx = params->test_ctx;
	int rc;

	rc = alloc_generic_host_mem_buffers(params);
	if (rc)
		return rc;

	rc = test_ctx->funcs->alloc_host_mem_buffers(params);
	if (rc)
		return rc;

	hltests_nic_print_time_elapsed(&params->base, "alloc host memory", params->cfg->verbose);

	return 0;
}

static uint32_t get_generic_num_of_buffers(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t num_of_buffers = 0, port, qps_per_port;
	int port_idx;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];

		qps_per_port = (uint32_t)params->num_qps_per_port[port];

		if (cfg->single_alloc) {
			if (qps_per_port)
				num_of_buffers++;
		} else {
			num_of_buffers += qps_per_port;
		}
	}

	return num_of_buffers;
}

static int alloc_generic_device_mem(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_ctx *test_ctx = params->test_ctx;
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_qp **qps_db, *qp_p;
	struct hlthunk_hw_ip_info *hw_ip;
	struct hltests_memory mem = { 0 };
	uint64_t total_size, data_size, dst_data_size, local_dev_base_offset,
		remote_dev_base_offset;
	uint32_t num_of_buffers, port, qp, qps_per_port, factor, port_idx;
	int rc, fd;

	if (!params->use_generic_qps)
		return 0;

	hw_ip = &test_ctx->tests_state->hw_ip;
	fd = params->fd;

	num_of_buffers = get_generic_num_of_buffers(params);
	data_size = params->data_size;
	dst_data_size = params->dst_data_size;

	total_size = num_of_buffers * (data_size + dst_data_size);
	assert_true(total_size);

	if (cfg->data_loc == LOC_ALL || cfg->data_loc == LOC_HBM) {
		const struct hltests_memory *device_mem;

		/* Compression: Source and destination address should be 128 bytes aligned.
		 * Allocate extra space to align the addresses later.
		 */
		if (cfg->compression_en)
			total_size += 2 * SZ_128;

		assert_true(total_size <= hw_ip->dram_size);

		/* We'll be pushing the virtual address into the dmem list, it will be popped and
		 * freed in `destroy_device_mem`
		 */
		device_mem = hltests_allocate_device_mem_ret_mem(fd, total_size, 0, CONTIGUOUS);
		assert_non_null(device_mem);

		mem = *device_mem;

		static_assert(sizeof(void *) >= sizeof(mem.device_virt_addr),
			      "The cast to `void *` can be fatal on 32bit systems, whoever decided to return a `void *` clearly wasn't thinking straight.");
		rc = hltests_nic_dmem_list_push((void *)(uintptr_t)mem.device_virt_addr);
		assert_int_equal(rc, 0);

		local_dev_base_offset = 0;
		remote_dev_base_offset = local_dev_base_offset + num_of_buffers * data_size;

		if (cfg->compression_en) {
			uint64_t alignment =
				ALIGN_UP(mem.device_virt_addr, SZ_128) - mem.device_virt_addr;

			local_dev_base_offset = alignment;
			remote_dev_base_offset =
				alignment + ALIGN_UP((num_of_buffers * data_size), SZ_128);
		}
	} else { /* DATA_LOC_SRAM */
		assert_true(total_size <= hw_ip->sram_size);

		mem.device_virt_addr = hw_ip->sram_base_address;
		mem.host_ptr = NULL;

		local_dev_base_offset = 0;
		remote_dev_base_offset = local_dev_base_offset + num_of_buffers * data_size;
	}

	qps_db = params->qps;
	factor = 0;

	for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
		port = cfg->ports[port_idx];
		qps_per_port = (uint32_t)params->num_qps_per_port[port];

		for (qp = 0; qp < qps_per_port; qp++) {
			qp_p = &qps_db[port][qp];
			qp_p->dev_mem = mem;

			if (cfg->single_alloc) {
				qp_p->local_dev_mem_offset =
					local_dev_base_offset + (port_idx * data_size);
				qp_p->remote_dev_mem_offset =
					remote_dev_base_offset +
					(port_idx * dst_data_size);
			} else {
				qp_p->local_dev_mem_offset =
					local_dev_base_offset + (factor * data_size);
				qp_p->remote_dev_mem_offset =
					remote_dev_base_offset + (factor * dst_data_size);
				factor++;
			}
		}
	}

	return 0;
}

static int alloc_device_mem(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_ctx *test_ctx = params->test_ctx;
	int rc;

	rc = alloc_generic_device_mem(params);
	if (rc)
		return rc;

	rc = test_ctx->funcs->alloc_device_mem(params);
	if (rc)
		return rc;

	hltests_nic_print_time_elapsed(&params->base, "alloc device memory", params->cfg->verbose);

	return 0;
}

static int set_params(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint64_t data_size;
	int rc;

	data_size = BIT_ULL(cfg->data_size_shift);

	params->wqe_size = BIT_ULL(cfg->wqe_size_shift);
	params->data_size = data_size;
	params->dst_data_size = data_size;
	params->num_wqes_in_wq = (uint32_t)(params->data_size / params->wqe_size);

	/* Num of WQEs must be greater than 4 */
	assert_true(params->num_wqes_in_wq > 4);

	if (cfg->reduction_en) {
		/* Upscale: Destination buffer(fp32) is twice the size of source buffer(bf16)
		 * Downscale: Destination buffer(bf16) is half the size of source buffer(fp32)
		 */
		if (cfg->red_dt == HLTESTS_NIC_REDUCTION_UPSCALING_BF16) {
			params->dst_data_size = data_size << 1;
			params->upscale_en = true;
		} else if (cfg->red_dt == HLTESTS_NIC_REDUCTION_DOWNSCALING_TO_BF16) {
			params->dst_data_size = data_size >> 1;
			params->downscale_en = true;
		}

		rc = hltests_nic_config_reduction(params->fd, cfg->red_op, cfg->red_dt,
							&params->reduction_cfg);
		if (rc)
			return rc;
	}

	rc = alloc_qps_db(params);
	if (rc)
		return rc;

	rc = alloc_host_mem_buffers(params);
	if (rc)
		return rc;

	if (cfg->data_loc != LOC_HOST) {
		rc = alloc_device_mem(params);
		if (rc)
			return rc;
	}

	return 0;
}

static int init_test_params(struct hltests_state *tests_state)
{
	struct hltests_nic_test_params *test_params;
	struct hltests_nic_test_ctx *test_ctx;
	int fd = tests_state->fd, rc;

	test_ctx = get_nic_ctx_from_fd(fd);

	test_params = hlthunk_malloc(sizeof(*test_params));
	assert_non_null(test_params);

	test_params->test_ctx = test_ctx;
	test_params->fd = fd;
	test_params->max_num_of_ports = hltests_nic_get_max_num_of_ports(fd);

	clock_gettime(CLOCK_MONOTONIC_RAW, &test_params->base);

	rc = parse_cfg(test_params);
	if (rc)
		return rc;

	rc = validate_cfg(test_params);
	if (rc)
		return rc;

	rc = set_params(test_params);
	if (rc)
		return rc;

	test_ctx->params = test_params;

	return 0;
}

static int test_ctx_init(struct hltests_state *tests_state, enum hltests_nic_test_type test_type)
{
	struct hltests_nic_test_ctx *test_ctx;
	struct hltests_device *hdev;
	int fd = tests_state->fd, rc;

	if (!hltests_nic_is_ibdev(fd)) {
		printf("Non IB device is not supported\n");
		fail();
	}

	hdev = get_hdev_from_fd(fd);

	test_ctx = hlthunk_malloc(sizeof(*test_ctx));
	assert_non_null(test_ctx);

	test_ctx->tests_state = tests_state;

	hdev->nic_test_ctx = test_ctx;

	init_test_funcs(fd, test_type);

	rc = init_test_params(tests_state);
	if (rc)
		return rc;

	return 0;
}

static const char *const location_names[] = {
	[LOC_HOST] = "LOC_HOST",
	[LOC_HBM] = "LOC_HBM",
	[LOC_SRAM] = "LOC_SRAM",
	[LOC_ALL] = "LOC_ALL",
};

static const char *const completion_names[] = {
	[NONE] = "NONE",
	[SOB] = "SOB",
	[CQ_USR] = "CQ_USR",
};

static const char *const cq_type_names[] = {
	[HLTESTS_NIC_CQ_TYPE_PORT] = "PORT",
	[HLTESTS_NIC_CQ_TYPE_DEVICE] = "DEVICE",
	[HLTESTS_NIC_CQ_TYPE_ALL] = "ALL",
};

static int print_iteration_info(struct hltests_nic_test_params *params, size_t iteration)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	enum hltests_nic_location data_loc = params->data_mem_location,
				  wq_loc = params->wq_mem_location;
	assert_in_range(data_loc, 0, ARRAY_SIZE(location_names) - 1);
	assert_in_range(wq_loc, 0, ARRAY_SIZE(location_names) - 1);
	assert_in_range(cfg->cmpl, 0, ARRAY_SIZE(completion_names) - 1);

	I("Test iteration: %zu, data on: %s, wq on: %s, completion_type: %s", iteration,
	  location_names[data_loc], location_names[wq_loc], completion_names[cfg->cmpl]);

	if (cfg->cmpl == CQ_USR) {
		enum hltests_nic_cq_type cq_type = params->cq_type;

		assert_in_range(cq_type, 0, ARRAY_SIZE(cq_type_names) - 1);

		I("CQ type: %s", cq_type_names[cq_type]);
	}

	if (params->test_ctx->funcs->print_iteration_info)
		params->test_ctx->funcs->print_iteration_info(params);

	return 0;
}

static int open_device(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hbldv_ucontext_attr attr = {};
	struct ibv_device_attr_ex dev_attr;
	struct hltests_device *hdev;
	struct ibv_context *ibctx;
	enum hl_pci_ids device_id;
	struct ibv_pd *ibpd;
	int fd, rc;

	fd = params->fd;
	hdev = get_hdev_from_fd(fd);

	attr.ports_mask = hltests_nic_to_ibdev_port_mask(fd, cfg->ports_mask);
	attr.core_fd = fd;

	ibctx = hbldv_open_device(hdev->ibdev, &attr);
	assert_non_null(ibctx);

	rc = hlibv_query_device_ex(ibctx, NULL, &dev_attr);
	assert_int_equal(rc, 0);

	device_id = hlthunk_get_device_id_from_fd(fd);
	assert_int_equal(dev_attr.orig_attr.vendor_part_id, device_id);

	ibpd = hlibv_alloc_pd(ibctx);
	assert_non_null(ibpd);

	rc = hdev->asic_funcs->nic_funcs->asic_priv_init(hdev, ibctx, cfg->ports_mask);
	assert_int_equal(rc, 0);

	params->ibctx = ibctx;
	params->ibpd = ibpd;

	hltests_nic_print_time_elapsed(&params->base, "open IB device", cfg->verbose);

	return 0;
}

static int eq_poll(struct hltests_nic_test_params *params)
{
	struct hltests_nic_eq *eq;

	if (!params->cfg->eq_poll)
		return 0;

	eq = &params->eq;
	eq->ports_mask = params->cfg->ports_mask;

	return nic_eq_poll(params->fd, eq, params->ibctx);
}

static inline uint32_t get_num_wqes_in_wq(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t num_wqes_in_wq = params->num_wqes_in_wq;

	/* number of wq entries must be ^2 */
	num_wqes_in_wq = next_pow2(num_wqes_in_wq);

	if (num_wqes_in_wq < WQES_MIN)
		num_wqes_in_wq = WQES_MIN;

	if (IS_RDV(cfg->features_bitmap) && hltests_is_gaudi2(params->fd)) {
		/* SW-61290: Since there is a HW bug in WR-RDV/RD-RDV, the sender WQ size must be
		 * at least 4 times bigger than receiver side.
		 */
		num_wqes_in_wq <<= 2;
	}

	return num_wqes_in_wq;
}

static uint32_t get_max_supported_qps_per_port(struct hltests_nic_test_params *params)
{
	struct hltests_nic_asic_funcs *nic_funcs;
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t port, max_supported_qps_per_port = 0, val;
	int fd, port_idx;

	fd = params->fd;
	nic_funcs = get_hdev_from_fd(fd)->asic_funcs->nic_funcs;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];

		val = (uint32_t)nic_funcs->get_max_num_of_qps(fd, port);
		if (val > max_supported_qps_per_port)
			max_supported_qps_per_port = val;
	}

	return max_supported_qps_per_port;
}

static int32_t get_max_num_of_wqs(struct hltests_nic_test_params *params, uint32_t port,
				  enum hbldv_wq_array_type type)
{
	enum hltests_nic_test_type test_type = params->test_ctx->type;
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_asic_funcs *nic_funcs;
	uint32_t max_num_of_wqs = 0;
	int fd = params->fd;
	bool is_context = (test_type == NIC_TEST_TYPE_COLL) && cfg->coll_type == COLL_TYPE_CONTEXT;

	nic_funcs = get_hdev_from_fd(fd)->asic_funcs->nic_funcs;

	switch (type) {
	case HBLDV_WQ_ARRAY_TYPE_GENERIC: {
		bool has_coll_qps = (test_type == NIC_TEST_TYPE_COLL) &&
				    (cfg->coll_qps_count[COLL_QP_TYPE_SCALE_UP] ||
				     cfg->coll_qps_count[COLL_QP_TYPE_SCALE_OUT]);
		bool has_qps = (params->num_qps_per_port[port] || (is_context && has_coll_qps));

		/* If force PMMU and we have one of the QPs, then use the maximum per port */
		if (cfg->force_wq_with_pmmu && has_qps) {
			max_num_of_wqs = get_max_supported_qps_per_port(params);
			break;
		}

		/* If the port has regular QPs, add them to the maximum */
		if (params->num_qps_per_port[port])
			max_num_of_wqs = (uint32_t)params->num_qps_per_port[port];

		/* Take into account also migration QPs  */
		if (cfg->migration.enable && cfg->migration.new_port == port)
			switch (params->test_ctx->type) {
			case NIC_TEST_TYPE_BASIC:
				/* We want the same amount of QPS as in the old port */
				max_num_of_wqs += (uint32_t)
					params->num_qps_per_port[cfg->migration.old_port];
				break;
			case NIC_TEST_TYPE_COLL:
				/* All coll ports have same amount of QPs */
				max_num_of_wqs += (uint32_t)cfg->coll_qps_count[cfg->coll_type];
				break;
			default:
				fail_msg("QP Migration not implemented for test type %u",
					 params->test_ctx->type);
				return -ENOTSUP;
			}

		/* Context patcher uses regular QPs, so add them to the tally */
		if (is_context) {
			enum hltests_nic_coll_qp_type coll_qp_type;

			for (coll_qp_type = 0; coll_qp_type < COLL_QP_TYPE_MAX; coll_qp_type++)
				max_num_of_wqs += (uint32_t)cfg->coll_qps_count[coll_qp_type];
		}

		/* +1 due to ethernet QP */
		if (max_num_of_wqs)
			max_num_of_wqs++;

		break;
	}
	case HBLDV_WQ_ARRAY_TYPE_COLLECTIVE:
		/* Context patcher uses regular QPs, don't count it here */
		if (!is_context) {
			if (cfg->coll_qps_count[COLL_QP_TYPE_SCALE_UP]) {
				if (cfg->force_wq_with_pmmu)
					max_num_of_wqs =
						nic_funcs->get_max_num_of_coll_qps(fd,
							false);
				else
					max_num_of_wqs = (uint32_t)
						cfg->coll_qps_count[COLL_QP_TYPE_SCALE_UP];
			}
		}

		if ((params->test_ctx->type == NIC_TEST_TYPE_LAG) && !cfg->lag.scale_out)
			max_num_of_wqs += (uint32_t)cfg->lag.qps_count;

		break;
	case HBLDV_WQ_ARRAY_TYPE_SCALE_OUT_COLLECTIVE:
		/* Context patcher uses regular QPs, don't count it here */
		if (!is_context) {
			if (cfg->coll_qps_count[COLL_QP_TYPE_SCALE_OUT]) {
				if (cfg->force_wq_with_pmmu)
					max_num_of_wqs =
						nic_funcs->get_max_num_of_coll_qps(fd, true);
				else
					max_num_of_wqs = (uint32_t)
						cfg->coll_qps_count[COLL_QP_TYPE_SCALE_OUT];
			}
		}

		if ((params->test_ctx->type == NIC_TEST_TYPE_LAG) && cfg->lag.scale_out)
			max_num_of_wqs += (uint32_t)cfg->lag.qps_count;

		break;
	default:
		break;
	}

	return (int32_t)max_num_of_wqs;
}

static int set_ports_ex(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_test_ctx *test_ctx;
	struct hltests_nic_ib_app_params app_params;
	struct ibv_context *ibctx = params->ibctx;
	struct hbldv_wq_array_attr *wq_arr_attr;
	struct hbldv_port_ex_attr attr;
	int fd, port_idx, rc, i;
	int32_t max_num_of_wqs;
	uint32_t port;

	fd = params->fd;
	test_ctx = params->test_ctx;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];

		memset(&attr, 0, sizeof(attr));

		memset(&app_params, 0, sizeof(app_params));
		test_ctx->funcs->fill_port_app_params(params, port, &app_params);

		attr.port_num = hltests_nic_to_ibdev_port_num(fd, port);
		attr.caps = app_params.advanced ? HBLDV_PORT_CAP_ADVANCED : 0;
		memcpy(attr.qp_wq_bp_offs, app_params.bp_offs, sizeof(attr.qp_wq_bp_offs));
		memcpy(attr.atomic_fna_fifo_offs, app_params.fna_fifo_offs,
			sizeof(attr.atomic_fna_fifo_offs));
		attr.atomic_fna_mask_size = app_params.fna_mask_size;

		for (i = 0 ; i < HBLDV_WQ_ARRAY_TYPE_MAX ; i++) {
			wq_arr_attr = &attr.wq_arr_attr[i];

			max_num_of_wqs = get_max_num_of_wqs(params, port, i);
			if (max_num_of_wqs <= 0)
				continue;

			wq_arr_attr->max_num_of_wqs = (uint32_t)max_num_of_wqs;
			wq_arr_attr->max_num_of_wqes_in_wq = get_num_wqes_in_wq(params);
			wq_arr_attr->mem_id = params->wq_mem_location == LOC_HOST ?
							HBLDV_MEM_HOST : HBLDV_MEM_DEVICE;
			wq_arr_attr->swq_granularity = cfg->rdv_type == HLTESTS_NIC_RDV_MS ?
							HBLDV_SWQE_GRAN_64B : HBLDV_SWQE_GRAN_32B;
		}

		rc = hbldv_set_port_ex(ibctx, &attr);
		assert_int_equal(rc, 0);
	}

	hltests_nic_print_time_elapsed(&params->base, "set app params and create WQ arrays",
					cfg->verbose);

	return 0;
}

/* create rd CQ put that cqid in wqe
 * in poll check for rd_cq based on cqid
 */
static int create_rd_cqs(struct hltests_nic_test_params *params)
{
	struct hltests_nic_cq *rd_cqs = params->rd_cqs;
	int i;

	if (!rd_cqs)
		return 0;

	/* The following loop's end condition is based on the HACK that
	 * `params->cq == &params->cqs[last_index]`
	 */

	i = -1;
	do {
		i++;

		rd_cqs[i].ibctx = params->ibctx;

		assert_int_equal(hltests_nic_cq_create(params->fd, &rd_cqs[i]), 0);
	} while (&rd_cqs[i] != params->rd_cq);

	hltests_nic_print_time_elapsed(&params->base, "create RD CQs", params->cfg->verbose);

	return 0;
}

static int create_cqs(struct hltests_nic_test_params *params)
{
	struct hltests_nic_cq *cqs = params->cqs;
	int i;

	if (!cqs)
		return 0;

	/* The following loop's end condition is based on the HACK that
	 * `params->cq == &params->cqs[last_index]`
	 */

	i = -1;
	do {
		i++;

		cqs[i].ibctx = params->ibctx;

		assert_int_equal(hltests_nic_cq_create(params->fd, &cqs[i]), 0);
	} while (&cqs[i] != params->cq);

	hltests_nic_print_time_elapsed(&params->base, "create CQs", params->cfg->verbose);

	return 0;
}

static struct hltests_nic_db_fifo_data *
__create_user_fifo_per_port(struct hltests_nic_test_params *params, enum hbldv_usr_fifo_type type)
{
	struct hltests_nic_db_fifo_data *user_fifo, *user_fifo_arr;
	struct hbldv_usr_fifo *hbldv_usr_fifo;
	enum hbldv_usr_fifo_type ib_db_type;
	struct hltests_nic_test_cfg *cfg;
	struct hbldv_usr_fifo_attr attr;
	uint32_t port, sob_id_base = 0;
	bool is_patcher_op;
	int fd, port_idx;

	fd = params->fd;
	cfg = params->cfg;

	ib_db_type = type;

	is_patcher_op = (ib_db_type == HBLDV_USR_FIFO_TYPE_COLL_OPS_SHORT) ||
			(ib_db_type == HBLDV_USR_FIFO_TYPE_COLL_OPS_LONG) ||
			(ib_db_type == HBLDV_USR_FIFO_TYPE_COLL_DIR_OPS_SHORT) ||
			(ib_db_type == HBLDV_USR_FIFO_TYPE_COLL_DIR_OPS_LONG);

	if (is_patcher_op) {
		sob_id_base = DB_FIFO_SOB_ID + hltests_get_first_avail_sob(fd);
	}

	user_fifo_arr = hlthunk_malloc(params->max_num_of_ports * sizeof(*user_fifo_arr));
	assert_non_null_ret_ptr(user_fifo_arr);

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];
		user_fifo = &user_fifo_arr[port];
		user_fifo->ib_db_type = ib_db_type;

		memset(&attr, 0, sizeof(attr));

		attr.port_num = hltests_nic_to_ibdev_port_num(fd, port);
		attr.usr_fifo_type = ib_db_type;

		/* Per SW policy, collective operations are to be enabled with DB fifo LBW(SOB) CI
		 * and DUP interface.
		 */
		if (is_patcher_op) {
			user_fifo->sob_id = sob_id_base + port;
			user_fifo->is_dup_enabled = true;

			attr.base_sob_addr =
				lower_32_bits(hltests_get_sob_lbw_offset(fd, user_fifo->sob_id));
			D("Setting FIFO base_sob_addr: %#010x, user_fifo->sob_id: %4u",
			  attr.base_sob_addr, user_fifo->sob_id);
			attr.num_sobs = user_fifo->num_sobs = 1;
		}

		hbldv_usr_fifo = hbldv_create_usr_fifo(params->ibctx, &attr);
		assert_non_null_ret_ptr(hbldv_usr_fifo);

		user_fifo->hbldv_usr_fifo = hbldv_usr_fifo;
		user_fifo->id = hbldv_usr_fifo->usr_fifo_num;
		user_fifo->fifo_size = hbldv_usr_fifo->size;
		user_fifo->fifo_bp_thresh = hbldv_usr_fifo->bp_thresh;
		user_fifo->regs_offset = hbldv_usr_fifo->regs_offset;
		user_fifo->ci_cpu_ptr = hbldv_usr_fifo->ci_cpu_addr;
		user_fifo->regs_cpu_ptr = hbldv_usr_fifo->regs_cpu_addr;
		user_fifo->pi = 0;
	}

	return user_fifo_arr;
}

static int create_user_fifos(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_ctx *test_ctx = params->test_ctx;
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_db_fifo_data **user_fifos;
	uint32_t num_fifos;

	num_fifos = test_ctx->funcs->get_user_fifo_num(params);

	user_fifos = hlthunk_malloc(num_fifos * sizeof(void *));
	params->user_fifos = user_fifos;

	for (uint32_t i = 0; i < num_fifos; i++) {
		enum hbldv_usr_fifo_type type = test_ctx->funcs->get_user_fifo_type(params, i);

		user_fifos[i] = __create_user_fifo_per_port(params, type);
		if (!user_fifos[i])
			return -ENOMEM;
	}

	hltests_nic_print_time_elapsed(&params->base, "create user FIFOs", cfg->verbose);

	return 0;
}

static int set_encap(struct hltests_nic_qp *qp_p)
{
	struct hltests_nic_test_params *params;
	struct hltests_nic_requester_conn_ctx *req_ctx;
	struct hltests_nic_responder_conn_ctx *res_ctx;
	struct hbldv_encap_attr encap_attr = {};
	struct hltests_nic_test_cfg *cfg;
	struct hltests_nic_vxlan_header vxlan_hdr = {};
	struct hltests_nic_gre_header gre_hdr = {};
	struct hbldv_encap *encap_data;
	uint32_t port = qp_p->port;
	int fd;

	params = qp_p->test_params;
	fd = params->fd;
	cfg = params->cfg;

	encap_attr.port_num = hltests_nic_to_ibdev_port_num(fd, port);
	/* This will work as long 1-1 mapping between these two enum types are maintained */
	encap_attr.encap_type = cfg->encap_type;

	switch (cfg->encap_type) {
	case HL_NIC_ENCAP_NONE:
		encap_attr.ipv4_addr = cfg->src_ip_addr;
		break;
	case HL_NIC_ENCAP_OVER_UDP:
		hltests_nic_build_vxlan_header(&vxlan_hdr);
		encap_attr.udp_dst_port = VXLAN_PORT_NUM;
		encap_attr.tnl_hdr_size = hltests_is_gaudi2(fd) ? 32 : sizeof(vxlan_hdr);
		encap_attr.tnl_hdr_ptr = (uint64_t) &vxlan_hdr;
		break;
	case HL_NIC_ENCAP_OVER_IPV4:
		hltests_nic_build_gre_header(&gre_hdr);
		encap_attr.ip_proto = GRE_PROTOCOL_NUMBER;
		encap_attr.tnl_hdr_size = sizeof(gre_hdr);
		encap_attr.tnl_hdr_ptr = (uint64_t) &gre_hdr;
		break;
	default:
		break;
	}

	encap_data = hbldv_create_encap(params->ibctx, &encap_attr);
	assert_non_null(encap_data);

	qp_p->encap_data = encap_data;

	req_ctx = &qp_p->req_ctx;
	res_ctx = &qp_p->res_ctx;

	res_ctx->encap_id = (uint8_t)encap_data->encap_num;
	req_ctx->encap_id = res_ctx->encap_id;
	req_ctx->encap_en = res_ctx->encap_en = cfg->encap_type != HL_NIC_ENCAP_NONE;

	return 0;
}

int nic_common_fill_qp_attr(struct hltests_nic_qp *qp_p)
{
	struct hltests_nic_test_params *params;
	struct hltests_nic_test_ctx *test_ctx;
	struct hltests_nic_test_cfg *cfg;
	struct hltests_nic_requester_conn_ctx *req_ctx;
	struct hltests_nic_responder_conn_ctx *res_ctx;
	uint32_t port = qp_p->port, num_wqes_in_wq;
	uint8_t cq_number, *addr;
	int fd, rc;

	params = qp_p->test_params;
	test_ctx = params->test_ctx;
	fd = params->fd;
	cfg = params->cfg;
	req_ctx = &qp_p->req_ctx;
	res_ctx = &qp_p->res_ctx;

	switch (params->cq->type) {
	case HLTESTS_NIC_CQ_TYPE_PORT:
		cq_number = (uint8_t)params->cq->user_cq.port_cq[port].id;
		break;
	case HLTESTS_NIC_CQ_TYPE_DEVICE:
		cq_number = (uint8_t)params->cq->user_cq.port_cq[0].id;
		break;
	default:
		E("Invalid cq type: %u", params->cq->type);
		fail();
		return -1;
	}

	num_wqes_in_wq = params->num_wqes_in_wq;
	addr = test_ctx->tests_state->mac_addrs[port].addr;

	if (IS_RDV(cfg->features_bitmap)) {
		bool is_rdv_send = qp_p->id & 1;

		if (is_rdv_send) {
			req_ctx->wq_type = cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE ?
					HBLDV_WQ_SEND_RDV : HBLDV_WQ_READ_RDV_ENDP;

			req_ctx->swq_granularity = cfg->rdv_type == HLTESTS_NIC_RDV_MS ?
					HBLDV_SWQE_GRAN_64B : HBLDV_SWQE_GRAN_32B;

			req_ctx->wq_size = hltests_is_gaudi2(fd) ?
						num_wqes_in_wq << 2 : num_wqes_in_wq;
			req_ctx->wq_remote_log_size = 1;
		} else {
			req_ctx->wq_type = HBLDV_WQ_RECV_RDV;

			if (cfg->rdv_type == HLTESTS_NIC_RDV_MS && !hltests_is_gaudi2(fd))
				req_ctx->swq_granularity = HBLDV_SWQE_GRAN_64B;
			else
				req_ctx->swq_granularity = HBLDV_SWQE_GRAN_32B;

			req_ctx->wq_size = num_wqes_in_wq;
			req_ctx->wq_remote_log_size = (uint8_t)(hltests_is_gaudi2(fd) ?
					HL_LOG2(num_wqes_in_wq << 2) : HL_LOG2(num_wqes_in_wq));
		}

		if (!hltests_is_gaudi2(fd))
			res_ctx->wq_peer_size = req_ctx->wq_size;

		res_ctx->rdv = is_rdv_send;
	} else {
		req_ctx->wq_type = HBLDV_WQ_WRITE;
		req_ctx->swq_granularity = HBLDV_SWQE_GRAN_32B;
		req_ctx->wq_size = num_wqes_in_wq;
	}

	req_ctx->cq_number = cq_number;
	res_ctx->cq_number = cq_number;
	req_ctx->mtu = cfg->mtu;
	req_ctx->compression_en = cfg->compression_en;
	req_ctx->timer_granularity = NIC_QP_TIMER_GRAN;

	/* Default coll lag size to 1 */
	req_ctx->coll_lag_size = 1;

	if (cfg->assign_qp_priority) {
		/* Assign QP priority as 1,2,3 to every QP in round robin */
		req_ctx->priority = (uint8_t)(1 + qp_p->id % 3);

		/* In Gaudi3, requester side of LPBK QP supports priorites 0,1 */
		if (hltests_is_gaudi3(fd) && qp_p->is_lpbk)
			req_ctx->priority = qp_p->id % 2;
	} else {
		req_ctx->priority = 1;
	}

	req_ctx->loopback = qp_p->is_lpbk;
	res_ctx->loopback = qp_p->is_lpbk;

	req_ctx->sack_en = cfg->sack_en;
	res_ctx->sack_en = cfg->sack_en;

	hltests_nic_copy_mac_reverse(req_ctx->dst_mac_addr, addr);
	hltests_nic_copy_mac_reverse(res_ctx->dst_mac_addr, addr);

	if (cfg->encap_en) {
		rc = set_encap(qp_p);
		if (rc)
			return rc;
	}

	qp_p->req_ctx.congestion_en = cfg->cc_mode != CC_MODE_DISABLED;

	test_ctx->funcs->fill_qp_attr(qp_p);

	return 0;
}

static int nic_common_alloc_qp(struct hltests_nic_qp *qp_p)
{
	struct hltests_nic_test_params *params;
	struct hltests_nic_test_cfg *cfg;
	struct hltests_nic_requester_conn_ctx *req_ctx;
	struct ibv_qp_init_attr qp_init_attr = {};
	struct hbldv_query_qp_attr dv_qp_attr = {};
	struct hbldv_qp_attr dv_qp_init_attr = {};
	struct ibv_pd *ibpd;
	struct ibv_qp *ibqp;
	struct ibv_qp_attr qp_attr = {};
	struct hltests_nic_port_cq *port_cq;
	uint32_t port;
	int rc, fd;

	params = qp_p->test_params;
	fd = params->fd;
	cfg = params->cfg;
	req_ctx = &qp_p->req_ctx;
	ibpd = params->ibpd;
	port = qp_p->port;

	switch (params->cq->type) {
	case HLTESTS_NIC_CQ_TYPE_PORT:
		port_cq = &params->cq->user_cq.port_cq[port];
		break;
	case HLTESTS_NIC_CQ_TYPE_DEVICE:
		port_cq = &params->cq->user_cq.port_cq[0];
		break;
	default:
		E("Invalid cq type: %u", params->cq->type);
		fail();
		return -1;
	}

	/* 1. Create QP in RESET state. */

	/* Set requestor and responder CQ. Note, test configures same CQ for both */
	qp_init_attr.send_cq = port_cq->ibvcq;
	qp_init_attr.recv_cq = port_cq->ibvcq;

	/* Reliable connection. */
	qp_init_attr.qp_type = IBV_QPT_RC;

	qp_init_attr.cap.max_send_wr = req_ctx->wq_size;

	ibqp = hlibv_create_qp(ibpd, &qp_init_attr);
	assert_non_null(ibqp);

	/* 2. Transition QP from RESET to INIT state. */

	qp_attr.qp_state = IBV_QPS_INIT;
	qp_attr.port_num = (uint8_t)hltests_nic_to_ibdev_port_num(fd, port);

	dv_qp_init_attr.caps |= qp_p->is_coll ? HBLDV_QP_CAP_COLL : 0;
	dv_qp_init_attr.qp_num_hint = qp_p->hint;

	dv_qp_init_attr.wq_type = req_ctx->wq_type;
	dv_qp_init_attr.wq_granularity = req_ctx->swq_granularity;

	/* Partition key. Though we support only one partition,
	 * it's a mandatory field for IB QP RESET to INIT transition.
	 */
	qp_attr.pkey_index = 0;

	qp_attr.qp_access_flags = IBV_ACCESS_REMOTE_WRITE;
	rc = hbldv_modify_qp(ibqp, &qp_attr,
			      IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS,
			      &dv_qp_init_attr);
	assert_true(rc == 0 || rc == EBUSY);

	qp_p->ibqp = ibqp;

	rc = hbldv_query_qp(ibqp, &dv_qp_attr);
	assert_true(rc == 0 || rc == EBUSY);

	qp_p->conn_id = dv_qp_attr.qp_num;

	return rc;
}

static int set_responder_ctx(struct hltests_nic_qp *qp_p)
{
	struct hltests_nic_requester_conn_ctx *req_ctx;
	struct hltests_nic_responder_conn_ctx *res_ctx;
	struct ibv_qp_attr ibv_qp_attr = {};
	struct hbldv_qp_attr hl_qp_attr = {};
	struct ibv_qp *ibqp;
	uint32_t port;
	int fd, attr_mask, rc;

	fd = qp_p->test_params->fd;
	req_ctx = &qp_p->req_ctx;
	res_ctx = &qp_p->res_ctx;
	port = qp_p->port;
	ibqp = qp_p->ibqp;

	ibv_qp_attr.qp_state = IBV_QPS_RTR;
	ibv_qp_attr.dest_qp_num = res_ctx->dst_conn_id;

	/* Setup AH and GRH. */
	ibv_qp_attr.ah_attr.is_global = 1;
	ibv_qp_attr.ah_attr.grh.hop_limit = 0xff;

	/* IB core calculates source GID using AH attribute port and GRH sgid_index. */
	ibv_qp_attr.ah_attr.port_num = (uint8_t)hltests_nic_to_ibdev_port_num(fd, port);
	ibv_qp_attr.path_mtu = hltests_nic_convert_mtu_to_ibv_mtu(req_ctx->mtu);

	if (!qp_p->test_params->cfg->e2e.enabled) {
		ibv_qp_attr.ah_attr.grh.sgid_index = 0;

		rc = hlibv_query_gid(ibqp->context, ibv_qp_attr.ah_attr.port_num,
				     ibv_qp_attr.ah_attr.grh.sgid_index,
				     &ibv_qp_attr.ah_attr.grh.dgid);
		assert_int_equal(rc, 0);
	} else {
		rc = get_dgid_for_qp(qp_p, &ibv_qp_attr.ah_attr.grh.dgid,
				     &ibv_qp_attr.ah_attr.grh.sgid_index);
		assert_int_equal(rc, 0);
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

static int set_requester_ctx(struct hltests_nic_qp *qp_p)
{
	struct hltests_nic_requester_conn_ctx *req_ctx;
	struct ibv_qp_attr ibv_qp_attr = {};
	struct hbldv_qp_attr hl_qp_attr = {};
	struct ibv_qp *ibqp;
	int attr_mask;

	req_ctx = &qp_p->req_ctx;
	ibqp = qp_p->ibqp;

	ibv_qp_attr.qp_state = IBV_QPS_RTS;
	ibv_qp_attr.dest_qp_num = req_ctx->dst_conn_id;
	ibv_qp_attr.timeout = req_ctx->timer_granularity;

	hl_qp_attr.priority = req_ctx->priority;
	hl_qp_attr.caps |= req_ctx->loopback ? HBLDV_QP_CAP_LOOPBACK : 0; /* QP loopback. */
	/* Selective acknowledgment. */
	hl_qp_attr.caps |= req_ctx->sack_en ? HBLDV_QP_CAP_SACK : 0;
	hl_qp_attr.caps |= req_ctx->compression_en ? HBLDV_QP_CAP_COMPRESSION : 0;
	hl_qp_attr.caps |= req_ctx->congestion_en ? HBLDV_QP_CAP_CONG_CTRL : 0;
	hl_qp_attr.caps |= req_ctx->encap_en ? HBLDV_QP_CAP_ENCAP : 0;
	hl_qp_attr.dest_wq_size = BIT(req_ctx->wq_remote_log_size);
	hl_qp_attr.congestion_wnd = req_ctx->congestion_wnd;
	hl_qp_attr.coll_lag_idx = req_ctx->coll_lag_idx;
	hl_qp_attr.coll_last_in_lag = req_ctx->coll_last_in_lag;
	hl_qp_attr.coll_lag_size = req_ctx->coll_lag_size;

	hl_qp_attr.encap_num = req_ctx->encap_id;

	/* IB core mandates below QP attribute mask. */
	attr_mask = IBV_QP_STATE | IBV_QP_MAX_QP_RD_ATOMIC | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
			IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN;

	return hbldv_modify_qp(ibqp, &ibv_qp_attr, attr_mask, &hl_qp_attr);
}

int nic_common_set_qp(struct hltests_nic_qp *qp_p, struct hltests_nic_qp **qps_array)
{
	struct hltests_nic_test_params *params = qp_p->test_params;
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_test_ctx *test_ctx;
	uint32_t dst_conn_id;
	int rc;

	test_ctx = params->test_ctx;

	if (!params->cfg->e2e.enabled) {
		if (IS_RDV(cfg->features_bitmap)) {
			uint32_t port = qp_p->port, qp_id = qp_p->id;

			dst_conn_id = qp_id & 0x1 ? qps_array[port][qp_id - 1].conn_id :
					    qps_array[port][qp_id + 1].conn_id;

			qp_p->req_ctx.dst_conn_id = dst_conn_id;
			qp_p->res_ctx.dst_conn_id = dst_conn_id;
			qp_p->res_ctx.conn_peer = qp_p->conn_id;
		} else {
			dst_conn_id = qp_p->conn_id;

			qp_p->req_ctx.dst_conn_id = dst_conn_id;
			qp_p->res_ctx.dst_conn_id = dst_conn_id;
		}
	} else {
		const uint8_t *dmac = get_dst_mac_for_port(cfg, qp_p->port);
		uint32_t dip;

		rc = get_dst_ip_for_port(cfg, qp_p->port);
		if (rc < 0) {
			errno = EINVAL;
			E("Cannot get dst IP address, invalid port %d", qp_p->port);

			return -errno;
		}

		dip = (uint32_t)rc;

		rc = get_dst_conn_id_for_qp(cfg, qp_p);
		if (rc < 0) {
			errno = EINVAL;
			E("Cannot get dst conn id, invalid port %d", qp_p->port);

			return -errno;
		}
		dst_conn_id = (uint32_t)rc;
		qp_p->req_ctx.dst_conn_id = dst_conn_id;
		qp_p->res_ctx.dst_conn_id = dst_conn_id;
		hltests_nic_copy_mac_reverse(qp_p->req_ctx.dst_mac_addr, dmac);
		hltests_nic_copy_mac_reverse(qp_p->res_ctx.dst_mac_addr, dmac);
		qp_p->req_ctx.dst_ip_addr = dip;
		qp_p->res_ctx.dst_ip_addr = dip;
	}

	rc = set_responder_ctx(qp_p);
	if (rc)
		return rc;

	rc = set_requester_ctx(qp_p);
	if (rc)
		return rc;

	rc = test_ctx->funcs->set_wq_buffers(qp_p);

	return rc;
}

int nic_common_alloc_qp_mem_buffers(struct hltests_nic_test_params *params,
				    struct hltests_nic_qp *qp)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	const uint64_t data_size = params->data_size;
	const uint64_t dst_data_size = params->dst_data_size;
	const bool is_write_rdv = cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE;
	const int fd = params->fd;
	void *src_buf = NULL, *dst_buf = NULL, *dst_buf_ref = NULL, *dst_buf_orig = NULL;
	int rc;

	if (cfg->odp_en)
		src_buf = hltests_allocate_host_mem_aligned_flags(fd, data_size, NOT_HUGE_MAP, 0,
								  HL_MEM_ODP);
	else
		src_buf = hltests_allocate_host_mem(fd, data_size, NOT_HUGE_MAP);

	assert_non_null(src_buf);

	rc = hltests_nic_hmem_list_push(src_buf);
	assert_int_equal(rc, 0);

	if (cfg->odp_en)
		dst_buf = hltests_allocate_host_mem_aligned_flags(fd, dst_data_size, NOT_HUGE_MAP,
								  0, HL_MEM_ODP);
	else
		dst_buf = hltests_allocate_host_mem(fd, dst_data_size, NOT_HUGE_MAP);

	assert_non_null(dst_buf);

	rc = hltests_nic_hmem_list_push(dst_buf);
	assert_int_equal(rc, 0);

	if (cfg->reduction_en) {
		dst_buf_ref = hltests_allocate_host_mem(fd, dst_data_size, NOT_HUGE_MAP);
		assert_non_null(dst_buf_ref);

		rc = hltests_nic_hmem_list_push(dst_buf_ref);
		assert_int_equal(rc, 0);

		memset(dst_buf_ref, 0x0, dst_data_size);
	}

	fill_buffers(params, qp->port, src_buf, dst_buf);

	if (cfg->reduction_en) {
		void *_src_buf, *_dst_buf, *_dst_buf_ref;

		if (is_write_rdv && (qp->is_rdv_sender)) {
			_src_buf = src_buf;
			_dst_buf = qp->rdv_recv_qp->host_dst_buf;
			_dst_buf_ref = qp->rdv_recv_qp->host_dst_buf_ref;
		} else {
			_src_buf = src_buf;
			_dst_buf = dst_buf;
			_dst_buf_ref = dst_buf_ref;
		}

		calc_reduction_reference(_src_buf, _dst_buf, _dst_buf_ref, data_size, cfg->red_dt,
					 cfg->red_op);
	}

	/* Save the original dst_buf in order to memset it before every iteration */
	dst_buf_orig = hltests_allocate_host_mem(fd, dst_data_size, NOT_HUGE_MAP);
	assert_non_null(dst_buf_orig);

	rc = hltests_nic_hmem_list_push(dst_buf_orig);
	assert_int_equal(rc, 0);

	memcpy(dst_buf_orig, dst_buf, dst_data_size);

	qp->host_src_buf = src_buf;
	qp->host_dst_buf = dst_buf;
	qp->host_dst_buf_ref = dst_buf_ref;
	qp->host_dst_buf_orig = dst_buf_orig;

	return 0;
}

/**
 * create_qp() - Creates a single qp and associates it with the hardware.
 * @params:         Test parameters struct.
 * @port:           The port to associate with the qp.
 * @lag_index:      The lag index to associate with the qp.
 * @coll_qp_number: The collective qp id/number.
 * @qp_p:           In+out, pointer to the qp structure.
 * @coll_qp:        Whether this is a collective qp and has a reserved number.
 *
 * Return: 0 on success.
 */
static int create_qp(struct hltests_nic_test_params *params, uint32_t port, uint32_t lag_index,
		     uint32_t coll_qp_number, struct hltests_nic_qp *qp_p, bool coll_qp)
{
	uint32_t retry;
	int rc = 0, fd;

	fd = params->fd;

	if (coll_qp) {
		qp_p->coll_qp_number = coll_qp_number;
		qp_p->hint = coll_qp_number + hltests_nic_get_coll_qps_offset(fd, port);
	} else {
		qp_p->coll_qp_number = 0;
		qp_p->hint = 0;
	}

	qp_p->lag_index = lag_index;

	nic_common_fill_qp_attr(qp_p);

	for (retry = 1; retry <= QP_ALLOC_RETRIES; retry++) {
		rc = nic_common_alloc_qp(qp_p);

		/* Retry on EBUSY */
		if (rc != EBUSY)
			break;

		sleep(retry);
	}

	assert_int_equal(rc, 0);

	return rc;
}

static int create_generic_qps(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_qp **qps_db;
	size_t port_idx;

	if (params->use_generic_qps) {
		qps_db = params->qps;

		for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
			uint32_t port, qp, qps_per_port;

			port = cfg->ports[port_idx];
			qps_per_port = (uint32_t)params->num_qps_per_port[port];

			for (qp = 0; qp < qps_per_port; qp++) {
				/* lag index and qp number don't matter for generic QPs */
				int rc = create_qp(params, port, 0, 0, &qps_db[port][qp], false);

				assert_int_equal(rc, 0);
			}

			/* This is done in a separate loop, after all the QPs have been created, as
			 * some of the QPs depend on their pairs having already been created
			 */
			for (qp = 0; qp < qps_per_port; qp++) {
				struct hltests_nic_qp *qp_p;
				int rc;

				qp_p = &qps_db[port][qp];

				rc = nic_common_set_qp(qp_p, qps_db);
				assert_int_equal(rc, 0);
			}
		}
	}

	if (cfg->migration.enable) {
		uint32_t qp_idx, qps_per_port;

		switch (params->test_ctx->type) {
		case NIC_TEST_TYPE_BASIC:
			qps_per_port = (uint32_t)params->num_qps_per_port[cfg->migration.old_port];
			break;
		case NIC_TEST_TYPE_COLL:
			qps_per_port = (uint32_t)cfg->coll_qps_count[cfg->coll_type];
			break;
		default:
			fail_msg("QP Migration not implemented for test type %u",
				 params->test_ctx->type);
			return -ENOTSUP;
		}

		for (qp_idx = 0; qp_idx < qps_per_port; qp_idx++) {
			struct hltests_nic_qp *qp_p = &params->migration.qps[qp_idx];

			/* lag index and qp number don't matter for generic QPs */
			int rc = create_qp(params, (uint32_t)cfg->migration.new_port, 0, 0, qp_p,
					   false);

			assert_int_equal(rc, 0);
		}

		for (qp_idx = 0; qp_idx < qps_per_port; qp_idx++) {
			struct hltests_nic_qp *qp_p = &params->migration.qps[qp_idx];
			uint32_t dst_conn_id;

			if (IS_RDV(cfg->features_bitmap)) {
				uint32_t qp_id = qp_p->id;

				dst_conn_id = qp_id & 0x1 ?
						      params->migration.qps[qp_id - 1].conn_id :
						      params->migration.qps[qp_id + 1].conn_id;

				qp_p->res_ctx.conn_peer = qp_p->conn_id;
			} else {
				dst_conn_id = qp_p->conn_id;
			}

			qp_p->req_ctx.dst_conn_id = dst_conn_id;
			qp_p->res_ctx.dst_conn_id = dst_conn_id;
		}
	}

	return 0;
}

static int create_qps(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_ctx *test_ctx = params->test_ctx;
	int rc;

	rc = create_generic_qps(params);
	if (rc)
		return rc;

	rc = test_ctx->funcs->create_qps(params);
	if (rc)
		return rc;

	hltests_nic_print_time_elapsed(&params->base, "create QPs", params->cfg->verbose);

	return 0;
}

static int create_ccqs(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hbldv_query_cq_attr cq_query_attr = {};
	struct hbldv_cq_attr cq_attr = {};
	struct hltests_nic_ccq *ccqs;
	struct ibv_cq *ibvcq;
	uint32_t port;
	int port_idx;
	int rc;

	ccqs = params->ccqs;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];

		cq_attr.port_num = (uint8_t)hltests_nic_to_ibdev_port_num(params->fd, port);
		cq_attr.cq_type = HBLDV_CQ_TYPE_CC;

		ibvcq = hbldv_create_cq(params->ibctx, USER_CCQ_MAX_ENTRIES, NULL, 0, &cq_attr);
		assert_ptr_not_equal(ibvcq, NULL);

		rc = hbldv_query_cq(ibvcq, &cq_query_attr);
		assert_int_equal(rc, 0);

		memset(&ccqs[port], 0, sizeof(*ccqs));

		ccqs[port].ibvcq = cq_query_attr.ibvcq;
		ccqs[port].cc_sq = &params->cc_user_fifos[port];
		ccqs[port].ccq_buf = cq_query_attr.mem_cpu_addr;
		ccqs[port].ccq_buf_len = USER_CCQ_MAX_ENTRIES;
		ccqs[port].ccq_pi_mem = cq_query_attr.pi_cpu_addr;
		ccqs[port].port = port;
	}

	return 0;
}

static int create_cc_resources(struct hltests_nic_test_params *params)
{
	struct hltests_nic_db_fifo_data *cc_user_fifos;
	struct hltests_nic_test_cfg *cfg = params->cfg;
	int rc;

	cc_user_fifos = __create_user_fifo_per_port(params, HBLDV_USR_FIFO_TYPE_CC);
	if (!cc_user_fifos)
		return -ENOMEM;

	hltests_nic_print_time_elapsed(&params->base, "create CC user FIFOs", cfg->verbose);

	params->cc_user_fifos = cc_user_fifos;

	rc = create_ccqs(params);
	if (rc)
		return rc;

	hltests_nic_print_time_elapsed(&params->base, "create CCQs", cfg->verbose);

	return 0;
}

static int hw_init(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	int rc;

	rc = open_device(params);
	if (rc)
		return rc;

	if (params->test_ctx->funcs->init) {
		rc = params->test_ctx->funcs->init(params);
		if (rc)
			return rc;
	}

	rc = eq_poll(params);
	if (rc)
		return rc;

	rc = set_ports_ex(params);
	if (rc)
		return rc;

	rc = create_cqs(params);
	if (rc)
		return rc;

	if (cfg->submission == USER_FIFO) {
		rc = create_user_fifos(params);
		if (rc)
			return rc;
	}

	rc = create_qps(params);
	if (rc)
		return rc;

	if (cfg->rd_en) {
		rc = create_rd_cqs(params);
		if (rc)
			return rc;
	}

	if (cfg->cc_mode != CC_MODE_DISABLED) {
		rc = create_cc_resources(params);
		if (rc)
			return rc;
	}

	return 0;
}

static int generic_copy_host_to_dev_src_memory(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	size_t port_idx;

	if (!params->use_generic_qps)
		return 0;

	for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
		size_t qp_idx;
		uint32_t port = cfg->ports[port_idx];
		uint32_t qps_per_port = cfg->single_alloc ? 1 :
					(uint32_t)params->num_qps_per_port[port];

		for (qp_idx = 0; qp_idx < qps_per_port; qp_idx++) {
			struct hltests_nic_qp *qp_p = &params->qps[port][qp_idx];
			int rc = nic_common_copy_buff_host_to_dev(params, qp_p->host_src_buf,
								  &qp_p->dev_mem,
								  qp_p->local_dev_mem_offset,
								  params->data_size);

			assert_int_equal(rc, 0);
		}
	}

	hltests_nic_print_time_elapsed(&params->base, "copy host memory to device", cfg->verbose);

	return 0;
}

/**
 * nic_common_copy_buff_between_host_and_dev() - Copies a buffer from host memory do device memory,
 *						 or does the reverse (device memory to host memory)
 * @params:	   Test parameters.
 * @host_buff:	   Host memory buffer to copy from/to.
 * @dev_buff_addr: Address of the buffer in device memory to copy to/from.
 * @size:	   How many bytes to copy.
 * @is_reverse:	   Should a reverse operation be performed (copy from device to host)
 */
int nic_common_copy_buff_between_host_and_dev(struct hltests_nic_test_params *params,
					      void *host_buff, const struct hltests_memory *mem,
					      size_t mem_offset, uint64_t size, bool is_dev_to_host)
{
	const struct hltests_asic_funcs *asic = get_hdev_from_fd(params->fd)->asic_funcs;
	struct hltests_pkt_info pkt_info = { 0 };
	void *cb;
	uint64_t host_buff_va, total_dma_size, seq, timeout;
	uint32_t cb_size = 0, dma_size;
	uint32_t pdma_qid;
	int fd = params->fd, rc;

	if (asic->dma_transfer) {
		uint64_t src_va, dst_va;

		if (is_dev_to_host) {
			src_va = mem->device_virt_addr + mem_offset;
			dst_va = hltests_get_device_va_for_host_ptr(params->fd, host_buff);
		} else {
			src_va = hltests_get_device_va_for_host_ptr(params->fd, host_buff);
			dst_va = mem->device_virt_addr + mem_offset;
		}

		assert_true(src_va != 0);
		assert_true(dst_va != 0);

		rc = asic->dma_transfer(params->fd, src_va, dst_va, size);
		assert_int_equal(rc, 0);

		return rc;
	} else if (mem->host_ptr) {
		assert_true(mem_offset + size <= mem->size);

		if (is_dev_to_host) {
			/* Copy from the mmapped device buffer to the host buffer */
			memcpy(host_buff, ((uint8_t *)mem->host_ptr) + mem_offset, size);

			/* Left sleep in, in case this fallback is used */
			sleep(1);
		} else {
			/* Copy from the host buffer to the mmapped device buffer */
			memcpy(((uint8_t *)mem->host_ptr) + mem_offset, host_buff, size);

			/* Left sleep in, in case this fallback is used */
			sleep(1);
		}

		return 0;
	}

	pdma_qid = hltests_get_dma_down_qid(fd, STREAM0);

	cb = hltests_create_cb(fd, HL_MAX_CB_SIZE, EXTERNAL, 0);
	assert_non_null(cb);

	host_buff_va = hltests_get_device_va_for_host_ptr(fd, host_buff);

	pkt_info.qid = pdma_qid;
	pkt_info.eb = EB_FALSE;
	pkt_info.mb = MB_TRUE;
	pkt_info.dma.dma_dir =
		is_dev_to_host ?
			/* reverse - copy device to host */
			(params->data_mem_location == LOC_HBM ? DMA_DIR_DRAM_TO_HOST :
								DMA_DIR_SRAM_TO_HOST) :
			/* not reverse - copy host to device */
			(params->data_mem_location == LOC_HBM ? DMA_DIR_HOST_TO_DRAM :
								DMA_DIR_HOST_TO_SRAM);

	total_dma_size = 0;

	while (total_dma_size < size) {
		/* Split DMA into chunks of UINT32_MAX, i.e. max supported size in PDMA CB packet */
		dma_size = (uint32_t)MIN(UINT32_MAX, size - total_dma_size);

		pkt_info.dma.src_addr =
			/* In reverse the source address is the device buffer */
			(is_dev_to_host ? mem->device_virt_addr + mem_offset : host_buff_va) +
			total_dma_size;
		pkt_info.dma.dst_addr =
			/* In reverse the destination address is the host buffer */
			(is_dev_to_host ? host_buff_va : mem->device_virt_addr + mem_offset) +
			total_dma_size;
		pkt_info.dma.size = dma_size;
		cb_size = hltests_add_dma_pkt(fd, cb, cb_size, &pkt_info);

		total_dma_size += dma_size;
	}

	rc = hltests_submit_cb(fd, cb, cb_size, pdma_qid, 0, &seq);

	assert_int_equal(rc, 0);

	timeout = hltests_is_pldm(fd) ? NIC_PDMA_TIMEOUT_PLDM_USEC : NIC_PDMA_TIMEOUT_USEC;
	rc = hltests_wait_for_cs(fd, seq, timeout);
	assert_int_equal(rc, HL_WAIT_CS_STATUS_COMPLETED);

	rc = hltests_destroy_cb(fd, cb);
	assert_int_equal(rc, 0);

	return 0;
}

static void reset_generic_qps_pi(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t port, qp, qps_per_port;
	int port_idx;

	if (!params->use_generic_qps)
		return;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];
		qps_per_port = (uint32_t)params->num_qps_per_port[port];

		for (qp = 0 ; qp < qps_per_port ; qp++) {
			params->qps[port][qp].curr_pi = 0;
			params->qps[port][qp].dest_pi = 0;
		}
	}
}

static int pre_runtime(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_ctx *test_cxt = params->test_ctx;
	int rc;

	if (params->data_mem_location != LOC_HOST) {
		rc = generic_copy_host_to_dev_src_memory(params);
		assert_int_equal(rc, 0);
	}

	reset_generic_qps_pi(params);

	test_cxt->funcs->pre_runtime(params);

	return 0;
}

static int destroy_ccqs(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_ccq *ccqs = params->ccqs;
	uint32_t port;
	int port_idx, rc;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];

		if (!ccqs[port].ccq_buf)
			continue;

		rc = hlibv_destroy_cq(ccqs[port].ibvcq);
		assert_int_equal(rc, 0);
	}

	return 0;
}

static int __destroy_user_fifo_per_port(struct hltests_nic_test_params *params,
					struct hltests_nic_db_fifo_data *user_fifo)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t port;
	int rc, port_idx;

	for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
		port = cfg->ports[port_idx];

		rc = hbldv_destroy_usr_fifo(user_fifo[port].hbldv_usr_fifo);
		assert_int_equal(rc, 0);
	}

	free(user_fifo);

	return 0;
}

int destroy_cc_resources(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	int rc;

	rc = destroy_ccqs(params);
	if (rc)
		return rc;

	hltests_nic_print_time_elapsed(&params->base, "destroy CCQs", cfg->verbose);

	rc = __destroy_user_fifo_per_port(params, params->cc_user_fifos);
	if (rc)
		return rc;
	params->cc_user_fifos = NULL;

	hltests_nic_print_time_elapsed(&params->base, "destroy CC user FIFOs", cfg->verbose);

	return 0;
}

int nic_common_destroy_qp(struct hltests_nic_qp *qp_p)
{
	struct hltests_nic_test_params *params = qp_p->test_params;
	struct hltests_nic_test_ctx *test_cxt = params->test_ctx;
	int rc;

	test_cxt->funcs->free_wq_buffers(qp_p);

	if (params->cfg->encap_en) {
		rc = hbldv_destroy_encap(qp_p->encap_data);
		assert_int_equal(rc, 0);
	}

	return hlibv_destroy_qp(qp_p->ibqp);
}

static int destroy_generic_qps(struct hltests_nic_test_params *params)
{
	uint32_t port, qp, qps_per_port, max_qps_per_port = 0;
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_qp *qp_p;
	int rc, port_idx;

	if (cfg->migration.enable) {
		uint32_t qp_idx;

		switch (params->test_ctx->type) {
		case NIC_TEST_TYPE_BASIC:
			qps_per_port = (uint32_t)params->num_qps_per_port[cfg->migration.old_port];
			break;
		case NIC_TEST_TYPE_COLL:
			qps_per_port = (uint32_t)cfg->coll_qps_count[cfg->coll_type];
			break;
		default:
			fail_msg("QP Migration not implemented for test type %u",
				 params->test_ctx->type);
			return -ENOTSUP;
		}

		for (qp_idx = 0; qp_idx < qps_per_port; qp_idx++) {
			I("destroying migration qp");
			rc = nic_common_destroy_qp(&params->migration.qps[qp_idx]);
			assert_int_equal(rc, 0);
		}
	}

	if (!params->use_generic_qps)
		return 0;

	/* Here we destroy the QPs connection by connection for all the ports in parallel, instead
	 * of destroying all the QPs port by port.
	 * The reason for that is that there is a lock per port that protects from parallel accesses
	 * to the port's GW, so it's better to destroy connections from all ports in parallel and by
	 * that to utilize better the GWs and saving a lot of time.
	 */

	for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
		port = cfg->ports[port_idx];
		qps_per_port = (uint32_t)params->num_qps_per_port[port];

		if (qps_per_port > max_qps_per_port)
			max_qps_per_port = qps_per_port;
	}

	for (qp = 0; qp < max_qps_per_port; qp++) {
		for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
			port = cfg->ports[port_idx];
			qps_per_port = (uint32_t)params->num_qps_per_port[port];

			if (qp >= qps_per_port)
				continue;

			qp_p = &params->qps[port][qp];

			rc = nic_common_destroy_qp(qp_p);
			if (rc)
				return rc;
		}
	}

	return 0;
}

static int destroy_qps(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_ctx *test_ctx = params->test_ctx;
	int rc;

	rc = destroy_generic_qps(params);
	if (rc)
		return rc;

	rc = test_ctx->funcs->destroy_qps(params);
	if (rc)
		return rc;

	hltests_nic_print_time_elapsed(&params->base, "destroy QPs", params->cfg->verbose);

	return 0;
}

static int destroy_user_fifos(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_ctx *test_ctx = params->test_ctx;
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t num_fifos;
	int rc;

	num_fifos = test_ctx->funcs->get_user_fifo_num(params);

	for (uint32_t i = 0; i < num_fifos; i++) {
		rc = __destroy_user_fifo_per_port(params, params->user_fifos[i]);
		if (rc)
			return rc;
	}

	hlthunk_free(params->user_fifos);
	params->user_fifos = NULL;

	hltests_nic_print_time_elapsed(&params->base, "destroy user FIFOs", cfg->verbose);

	return 0;
}

static int destroy_cqs(struct hltests_nic_test_params *params)
{
	struct hltests_nic_cq *cqs = params->cqs;
	uint32_t user_cq_idx;
	int fd, rc, i;

	user_cq_idx = params->cfg->user_cq_idx;
	fd = params->fd;

	for (i = 0 ; i <= user_cq_idx ; i++) {
		rc = hltests_nic_cq_destroy(fd, &cqs[i]);
		if (rc)
			return rc;
	}

	hltests_nic_print_time_elapsed(&params->base, "destroy CQs", params->cfg->verbose);

	return 0;
}

static int stop_eq_poll(struct hltests_nic_test_params *params)
{
	struct hltests_nic_eq *eq;

	if (!params->cfg->eq_poll)
		return 0;

	eq = &params->eq;

	return nic_eq_poll_stop(eq);
}

static int close_device(struct hltests_nic_test_params *params)
{
	int rc;

	rc = hlibv_dealloc_pd(params->ibpd);
	assert_int_equal(rc, 0);

	rc = hlibv_close_device(params->ibctx);
	assert_int_equal(rc, 0);

	hltests_nic_print_time_elapsed(&params->base, "close IB device", params->cfg->verbose);

	return 0;
}

static int hw_fini(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	int rc;

	if (cfg->cc_mode != CC_MODE_DISABLED) {
		rc = destroy_cc_resources(params);
		if (rc)
			return rc;
	}

	rc = destroy_qps(params);
	if (rc)
		return rc;

	if (cfg->submission == USER_FIFO) {
		rc = destroy_user_fifos(params);
		if (rc)
			return rc;
	}

	rc = destroy_cqs(params);
	if (rc)
		return rc;

	rc = stop_eq_poll(params);
	if (rc)
		return rc;

	if (params->test_ctx->funcs->fini)
		params->test_ctx->funcs->fini(params);

	rc = close_device(params);
	if (rc)
		return rc;

	return 0;
}

static int destroy_host_mem_buffers(struct hltests_nic_test_params *params)
{
	void *host_buf;
	int fd = params->fd, rc;

	while (1) {
		host_buf = hltests_nic_hmem_list_pop();
		if (!host_buf)
			break;

		rc = hltests_free_host_mem(fd, host_buf);
		assert_int_equal(rc, 0);
	}

	hltests_nic_print_time_elapsed(&params->base, "free host memory", params->cfg->verbose);

	return 0;
}

static int destroy_device_mem(struct hltests_nic_test_params *params)
{
	void *device_buf;
	int fd = params->fd, rc;

	while (1) {
		device_buf = hltests_nic_dmem_list_pop();
		if (!device_buf)
			break;

		rc = hltests_free_device_mem(fd, device_buf);
		assert_int_equal(rc, 0);
	}

	hltests_nic_print_time_elapsed(&params->base, "free device memory", params->cfg->verbose);

	return 0;
}

static void destroy_generic_qps_db(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t port, qps_per_port;
	int port_idx;

	if (cfg->migration.enable)
		hlthunk_free(params->migration.qps);

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		qps_per_port = cfg->qps_per_port[port_idx];
		if (!qps_per_port)
			continue;

		port = cfg->ports[port_idx];

		if (cfg->cmpl == CQ_USR) {
			struct hltests_nic_qp *qp_p;
			uint32_t qp;

			for (qp = 0 ; qp < qps_per_port ; qp++) {
				qp_p = &params->qps[port][qp];

				hlthunk_free(qp_p->req_comp_params.cmpl_map);
				hlthunk_free(qp_p->res_comp_params.cmpl_map);
			}
		}

		hlthunk_free(params->qps[port]);
	}
}

static void destroy_qps_db(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_ctx *test_ctx = params->test_ctx;

	test_ctx->funcs->destroy_qps_db(params);

	destroy_generic_qps_db(params);
}

static int test_ctx_fini(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_ctx *test_ctx = params->test_ctx;
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_device *hdev;
	struct timespec base;
	uint8_t verbose;
	int fd, rc;

	fd = params->fd;
	hdev = get_hdev_from_fd(fd);

	rc = destroy_host_mem_buffers(params);
	if (rc)
		return rc;

	if (cfg->data_loc != LOC_HOST) {
		rc = destroy_device_mem(params);
		if (rc)
			return rc;
	}

	destroy_qps_db(params);

	/* Save base and verbose before freeing params and cfg structures */
	base = params->base;
	verbose = cfg->verbose;

	hlthunk_free(cfg);
	hlthunk_free(params);
	hlthunk_free(test_ctx);
	hdev->nic_test_ctx = NULL;

	hltests_nic_print_time_elapsed(&base, "cleanup test resources", verbose);

	return 0;
}

int nic_common_generic_set_device_wq_buffers(struct hltests_nic_qp *qp_p)
{
	uint32_t wq_size, swq_size, rwq_size;
	int fd;

	fd = qp_p->test_params->fd;

	wq_size = qp_p->req_ctx.wq_size;

	swq_size = wq_size * hltests_nic_get_swqe_size(fd);
	qp_p->swq_buf = hlthunk_malloc(swq_size);
	assert_non_null(qp_p->swq_buf);

	rwq_size = wq_size * hltests_nic_get_rwqe_size(fd);
	qp_p->rwq_buf = hlthunk_malloc(rwq_size);
	assert_non_null(qp_p->rwq_buf);

	return 0;
}

int nic_common_generic_set_user_wq_buffers(struct hltests_nic_qp *qp_p)
{
	struct ibv_qp *ibqp = qp_p->ibqp;
	struct hbldv_query_qp_attr dv_qp_attr = {};
	int rc;

	rc = hbldv_query_qp(ibqp, &dv_qp_attr);
	assert_int_equal(rc, 0);

	qp_p->swq_buf = dv_qp_attr.swq_cpu_addr;
	assert_ptr_not_equal(qp_p->swq_buf, MAP_FAILED);

	qp_p->rwq_buf = dv_qp_attr.rwq_cpu_addr;
	assert_ptr_not_equal(qp_p->rwq_buf, MAP_FAILED);

	return 0;
}

void nic_common_clear_sobs(struct hltests_nic_test_params *params)
{
	struct hltests_nic_sob_params *sob_params;
	struct hltests_nic_test_cfg *cfg;
	uint32_t port;
	uint16_t used_sobs;
	int fd, port_idx;

	cfg = params->cfg;
	fd = params->fd;
	used_sobs = (uint16_t)params->max_num_of_ports;

	hltests_clear_sobs_offset(fd, used_sobs, LOCAL_SOB_ID);
	hltests_clear_sobs_offset(fd, used_sobs, REMOTE_SOB_ID);

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];
		sob_params = &params->sob_params[port];

		sob_params->local_sob_val = 0;
		sob_params->remote_sob_val = 0;
	}

	hltests_nic_print_time_elapsed(&params->base, "clear SOBs", params->cfg->verbose);
}

/**
 * reset_dst_buffers() - Resets the destination buffers to their original values.
 * @params: Test parameters.
 * @qps_db: Pointer to array of QPs.
 * @coll_qps_count: Count of QPs in collective mode (In basic, fna and bp mode will be 0).
 *
 * Return: 0 on success.
 */
int nic_common_reset_dst_buffers(struct hltests_nic_test_params *params,
				 struct hltests_nic_qp **qps_db, uint32_t coll_qps_count)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_qp *qp_p;
	uint32_t port, port_idx, qp_idx, qps_per_port;
	int rc;

	/**
	 * TODO - SW-114993: once we have scale up/scale out ports, transition to
	 * using them instead of the generic ports
	 */
	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];

		if (params->test_ctx->type != NIC_TEST_TYPE_COLL)
			qps_per_port = (uint32_t)params->num_qps_per_port[port];
		else
			qps_per_port = coll_qps_count;

		for (qp_idx = 0; qp_idx < qps_per_port; qp_idx++) {
			qp_p = &qps_db[port][qp_idx];

			if (cfg->single_alloc && qp_idx) {
				qp_p->host_dst_buf = qps_db[port][0].host_dst_buf;
				continue;
			}

			memcpy(qp_p->host_dst_buf, qp_p->host_dst_buf_orig, params->dst_data_size);

			if (params->data_mem_location != LOC_HOST) {
				/* Copy newly memset'd buffer to device */
				rc = nic_common_copy_buff_host_to_dev(params, qp_p->host_dst_buf,
								      &qp_p->dev_mem,
								      qp_p->remote_dev_mem_offset,
								      params->dst_data_size);
				assert_int_equal(rc, 0);
			}
		}
	}

	hltests_nic_print_time_elapsed(&params->base, "reset dst buffers", cfg->verbose);

	return 0;
}

/**
 * config_generic_wqes() - Configures a specific WQ's WQEs.
 * @qp_p: QP parameters struct.
 * @port_idx: The index of the port that the qp belongs to.
 *
 * Configures the WQEs, their buffers, their sizes and other flags.
 */
void nic_common_config_wqes(struct hltests_nic_qp *qp_p, uint32_t port_idx)
{
	struct hltests_nic_test_params *params = qp_p->test_params;
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_wqe_params wqe_params;
	enum hltests_nic_cmpl cmpl;
	void *swq_buf, *rwq_buf;
	uint64_t local_conn_base, remote_conn_base, local_addr_wqe, remote_addr_wqe;
	uint32_t port, pi, wqe, wqe_idx, wq_size, wqe_size, wqes_in_wq, coll_wqe_count, offset,
		 coll_wq_offset;
	uint16_t sob_id;
	int fd = params->fd;

	port = qp_p->port;
	wq_size = qp_p->req_ctx.wq_size;
	wqe_size = (uint32_t)params->wqe_size;
	wqes_in_wq = params->num_wqes_in_wq;
	coll_wqe_count = MAX(wqes_in_wq, WQES_MIN);

	/* In patcher we use a single SOB */
	sob_id = hltests_get_first_avail_sob(fd) + (uint16_t)port_idx;

	if (params->data_mem_location != LOC_HOST) {
		local_conn_base = qp_p->dev_mem.device_virt_addr + qp_p->local_dev_mem_offset;
		remote_conn_base = qp_p->dev_mem.device_virt_addr + qp_p->remote_dev_mem_offset;
	} else {
		local_conn_base = hltests_get_device_va_for_host_ptr(fd, qp_p->host_src_buf);
		remote_conn_base = hltests_get_device_va_for_host_ptr(fd, qp_p->host_dst_buf);
	}


	for (pi = qp_p->curr_pi ; pi < qp_p->dest_pi ; pi++) {
		wqe_idx = pi & (wq_size - 1);
		wqe = wqe_idx & (wqes_in_wq - 1);

		local_addr_wqe = local_conn_base + (wqe * wqe_size);

		if (params->upscale_en)
			remote_addr_wqe = remote_conn_base + ((wqe * wqe_size) << 1);
		else if (params->downscale_en)
			remote_addr_wqe = remote_conn_base + ((wqe * wqe_size) >> 1);
		else
			remote_addr_wqe = remote_conn_base + wqe * wqe_size;

		cmpl = cfg->cmpl;

		/* In case of single CQ completion, all the WQEs that are not the last in the
		 * cycle should be set to not receive completion
		 */
		if (cfg->single_cmpl && cfg->cmpl == CQ_USR && pi < (qp_p->dest_pi - 1))
			cmpl = NONE;

		memset(&wqe_params, 0, sizeof(wqe_params));

		if (params->test_ctx->type == NIC_TEST_TYPE_COLL) {
			coll_wq_offset = hltests_nic_get_wq_offset(fd, (int)port, qp_p->conn_id);
			offset = coll_wqe_count * (qp_p->conn_id - coll_wq_offset) + wqe_idx;
			swq_buf = params->swqe_arr[port];
			rwq_buf = params->rwqe_arr[port];
		} else {
			offset = wqe_idx;
			swq_buf = qp_p->swq_buf;
			rwq_buf = qp_p->rwq_buf;
		}

		wqe_params.sq_wqe = hltests_nic_get_swqe(fd, swq_buf, offset);
		wqe_params.rq_wqe = hltests_nic_get_rwqe(fd, rwq_buf, offset);
		wqe_params.size = wqe_size;
		wqe_params.ackreq = !(wqe_idx % 64);
		wqe_params.wqe_index = (int)wqe_idx;
		wqe_params.tag = (int)GET_TAG(port, qp_p->id, wq_size, wqe_idx);
		D("Generated tag: %u, port: %u, qp_id: %u, wqe_idx: %u", wqe_params.tag, port,
		  qp_p->conn_id, wqe_idx);
		wqe_params.local_sob_id = (int)sob_id;
		wqe_params.remote_sob_id = (int)sob_id;
		wqe_params.cmpl = cmpl;
		wqe_params.test_opcode = cfg->test_opcode;
		wqe_params.local_address = local_addr_wqe;
		wqe_params.remote_address = remote_addr_wqe;
		wqe_params.reduction_cfg = params->reduction_cfg;
		wqe_params.downscale_en = params->downscale_en;
		wqe_params.upscale_en = params->upscale_en;
		wqe_params.qp = qp_p->id;
		wqe_params.cache_en = params->data_mem_location == LOC_HBM;
		wqe_params.fna_cmpl = cfg->atomic_fna_cmpl;
		wqe_params.fna_op_addr = params->atomic_fna_op_addr;
		wqe_params.compression_en = cfg->compression_en;
		wqe_params.rdv_remote_pi = pi;
		wqe_params.keys_en = cfg->keys_en;

		if (cfg->rd_en) {
			wqe_params.cq_id = params->rd_cqs->user_cq.port_cq[port_idx].id;
			wqe_params.rd_enable = cfg->rd_en;
		}

		if (cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
			wqe_params.is_wr_rdv_send = qp_p->is_rdv_sender;

		hltests_nic_fill_wqe(fd, &wqe_params);
	}
}

void nic_common_generic_config_wqes(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t port, qp, qps_per_port, port_idx;
	struct hltests_nic_qp *qp_p;
	bool is_rdv_rd;

	is_rdv_rd = cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		port = cfg->ports[port_idx];

		qps_per_port = (uint32_t)params->num_qps_per_port[port];

		for (qp = 0 ; qp < qps_per_port ; qp++) {
			qp_p = &params->qps[port][qp];

			/* For RD-RDV, there is no WQE to be posted for the send side */
			if (is_rdv_rd && qp_p->is_rdv_sender)
				continue;

			qp_p->curr_pi = qp_p->dest_pi;
			qp_p->dest_pi = qp_p->curr_pi + params->wqes_in_cycle;

			nic_common_config_wqes(qp_p, port_idx);
		}
	}

	hltests_nic_print_time_elapsed(&params->base, "config generic wqes", cfg->verbose);
}

int nic_common_generic_submit_user_fifo_db_qp(struct hltests_nic_qp *qp_p)
{
	struct hltests_nic_db_fifo_packet user_fifo_packet;
	struct hltests_nic_test_params *params;
	struct hltests_device *hdev;
	uint32_t port, max_pi, pi;
	int fd, rc;

	params = qp_p->test_params;
	fd = params->fd;
	hdev = get_hdev_from_fd(fd);
	port = qp_p->port;
	max_pi = hdev->asic_funcs->nic_funcs->get_max_pi(qp_p);
	pi = qp_p->dest_pi & (max_pi - 1);

	rc = hltests_nic_create_db_packet(&user_fifo_packet, pi, qp_p->conn_id, port);
	if (rc)
		return rc;

	rc = hltests_nic_submit_user_fifo(params, port, &user_fifo_packet);

	hlthunk_free(user_fifo_packet.packet);

	return rc;
}

static uint32_t get_qps_per_port_max(struct hltests_nic_test_cfg *cfg)
{
	uint32_t qps_per_port, qps_per_port_max = 0;
	int port_idx;

	for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
		qps_per_port = cfg->qps_per_port[port_idx];

		if (qps_per_port > qps_per_port_max)
			qps_per_port_max = qps_per_port;
	}

	return qps_per_port_max;
}

int nic_common_generic_submit_user_fifo_db(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_qp *qp_p;
	uint32_t port, qp, qps_per_port, qps_per_port_max;
	bool port_has_qp;
	int rc, port_idx;

	qps_per_port_max = get_qps_per_port_max(cfg);

	for (qp = 0, port_has_qp = true ; qp < qps_per_port_max && port_has_qp ; qp++) {
		port_has_qp = false;

		for (port_idx = 0 ; port_idx < cfg->ports_num ; port_idx++) {
			port = cfg->ports[port_idx];
			qps_per_port = (uint32_t)params->num_qps_per_port[port];

			if (qp >= qps_per_port)
				continue;

			port_has_qp = true;
			qp_p = &params->qps[port][qp];

			/* Skip in case there is no work to be submitted */
			if (qp_p->dest_pi == qp_p->curr_pi)
				continue;

			rc = nic_common_generic_submit_user_fifo_db_qp(qp_p);
			if (rc)
				return rc;
		}
	}

	hltests_nic_print_time_elapsed(&params->base, "submit db via user fifo", cfg->verbose);

	return 0;
}

/**
 * data_compare_rdv() - Compares data between the recv_qp and send_qp after a RDV operation.
 * @recv_qp: Receive QP.
 * @send_qp: Send QP.
 *
 * Return: 0 on success.
 */
static int nic_common_generic_data_compare_rdv(struct hltests_nic_qp *recv_qp,
					       struct hltests_nic_qp *send_qp)
{
	struct hltests_nic_test_params *params = recv_qp->test_params;
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint64_t data_size = params->dst_data_size;
	int rc;

	if (params->reduction_cfg) {
		rc = hltests_mem_compare(recv_qp->host_dst_buf_ref, recv_qp->host_dst_buf,
					 data_size);
	} else {
		if (cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) {
			rc = hltests_mem_compare(recv_qp->host_src_buf, recv_qp->host_dst_buf,
						 data_size);
			assert_int_equal(rc, 0);
		} else {
			rc = hltests_mem_compare(send_qp->host_src_buf, recv_qp->host_dst_buf,
						 data_size);
			assert_int_equal(rc, 0);
		}
	}

	return rc;
}

/**
 * data_compare_write() - Compares data between the QP's source and destination buffers.
 * @qp: QP whose buffers to compare.
 *
 * Return: 0 on success.
 */
static int nic_common_generic_data_compare_write(struct hltests_nic_qp *qp)
{
	struct hltests_nic_test_params *params = qp->test_params;
	uint64_t data_size = params->dst_data_size;
	int rc;

	if (params->reduction_cfg) {
		rc = hltests_mem_compare(qp->host_dst_buf_ref, qp->host_dst_buf, data_size);
		assert_int_equal(rc, 0);
	} else {
		rc = hltests_mem_compare(qp->host_src_buf, qp->host_dst_buf, data_size);
		assert_int_equal(rc, 0);
	}

	return 0;
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

/**
 * data_compare() - Compares the transferred data to the expected result.
 * @params: Test parameters.
 * @qps: QPs to be compared
 * @coll_qps_count: Count of QPs in collective mode (In basic mode will be 0)
 *
 * Return: 0 on success.
 */
int nic_common_data_compare(struct hltests_nic_test_params *params, struct hltests_nic_qp **qps,
			    uint32_t coll_qps_count)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_qp *qp_p;
	uint32_t port, ports_num, qp_index, port_idx, qps_per_port, qps_jump;
	int rc;
	bool is_rdv;

	is_rdv = IS_RDV(cfg->features_bitmap);
	qps_jump = is_rdv ? 2 : 1;

	/* In all collective modes except legacy, the ports collectively transmit the data,
	 * thus we only compare the buffer of the first port.
	 */
	if (cfg->coll_op > COLL_OP_MODE_LEGACY)
		ports_num = 1;
	else
		ports_num = cfg->ports_num;

	for (port_idx = 0; port_idx < ports_num; port_idx++) {
		port = cfg->ports[port_idx];

		if (params->test_ctx->type != NIC_TEST_TYPE_COLL)
			qps_per_port = (uint32_t)params->num_qps_per_port[port];
		else
			qps_per_port = coll_qps_count;

		for (qp_index = 0; qp_index < qps_per_port; qp_index += qps_jump) {
			qp_p = &qps[port][qp_index];

			if (params->data_mem_location != LOC_HOST) {
				rc = nic_common_copy_buff_dev_to_host(params, &qp_p->dev_mem,
								      qp_p->remote_dev_mem_offset,
								      qp_p->host_dst_buf,
								      params->dst_data_size);
				assert_int_equal(rc, 0);
			}

			D("Comparing data for qp: [%4u], port: [%2u]", qp_index, port);

			if (is_rdv) {
				rc = nic_common_generic_data_compare_rdv(qp_p, qp_p->rdv_send_qp);

				assert_int_equal(rc, 0);
			} else {
				/* Plain RDMA does not allow responder CQE, so we pre-defined
				 * guard data values to signal write completion.
				 */
				if (params->cfg->plain_rdma_en) {
					uint64_t timeout_us = hltests_is_pldm(params->fd) ?
						NIC_CQ_TIMEOUT_PLDM_USEC : NIC_CQ_TIMEOUT_USEC;

					rc = wait_for_transfer_completion(qp_p->host_dst_buf,
								params->data_size, timeout_us);
					assert_int_equal(rc, 0);
				}

				rc = nic_common_generic_data_compare_write(qp_p);

				assert_int_equal(rc, 0);
			}
		}
	}

	return 0;
}

/**
 * nic_common_fill_qp_completion_params() - Fills the QP's completion parameters.
 * @qp: The QP whose parameters to fill.
 *
 * Return: 0 on success.
 */
static int nic_common_fill_qp_completion_params(struct hltests_nic_qp *qp)
{
	struct hltests_nic_test_params *params = qp->test_params;
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_test_funcs *funcs = params->test_ctx->funcs;

	int rc, fd = params->fd;
	const struct hltests_device *hdev = get_hdev_from_fd(fd);

	struct hltests_nic_comp_params *req_comp = &qp->req_comp_params;
	struct hltests_nic_comp_params *res_comp = &qp->res_comp_params;

	uint32_t max_pi;

	assert_non_null(req_comp->cmpl_map);
	assert_non_null(res_comp->cmpl_map);
	memset(req_comp->cmpl_map, 0, req_comp->cmpl_map_length * sizeof(*req_comp->cmpl_map));
	memset(res_comp->cmpl_map, 0, res_comp->cmpl_map_length * sizeof(*res_comp->cmpl_map));

	req_comp->recv_cqes = 0;
	res_comp->recv_cqes = 0;

	assert_non_null(funcs->get_cqes_per_qp);
	rc = funcs->get_cqes_per_qp(qp, &req_comp->total_cqes, &res_comp->total_cqes);
	if (rc)
		return rc;

	max_pi = hdev->asic_funcs->nic_funcs->get_max_pi(qp);

	req_comp->base_cqe = qp->curr_pi & (max_pi - 1);
	res_comp->base_cqe = qp->curr_pi & (qp->req_ctx.wq_size - 1);

	/* In case of WR-RDV, the Rx completions for the sender QP should be according to the
	 * receiver QP ring.
	 * In case of RD-RDV, there are no completions for the sender QP.
	 */
	if (cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE) {
		if (qp->is_rdv_sender) {
			struct hltests_nic_qp *recv_qp = qp->rdv_recv_qp;

			res_comp->base_cqe = recv_qp->curr_pi & (recv_qp->req_ctx.wq_size - 1);
		} else {
			res_comp->total_cqes = 0;
		}
	} else if ((cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_READ) && qp->is_rdv_sender) {
		/* Sender will not get any CQEs */
		req_comp->total_cqes = 0;
		res_comp->total_cqes = 0;
	}

	return 0;
}

/**
 * nic_common_calculate_total_cqes() - Calculates the total amount of CQEs that are supposed to
 *                                     arrive.
 * @params: Test parameters.
 * @qps: Pointer to array of QPs.
 * @qps_count: How many QPs per port - should be either a single value used for all ports (for the
 *             collective patcher case, where all ports must have the same amount of QPs), or an
 *             array mapping for each port (for all other cases).
 * @qps_count_len: Length of @qps_count.
 * @total_req_cqes: Out, will be updated to contain the total expected amount of requester CQEs.
 * @total_res_cqes: Out, will be updated to contain the total expected amount of responder CQEs.
 * Return: 0 on success.
 *
 * Additionally, initializes each QP's completion params.
 */
int nic_common_calculate_total_cqes(struct hltests_nic_test_params *params,
				    struct hltests_nic_qp **qps, const size_t *qps_count,
				    size_t qps_count_len, uint32_t *total_req_cqes,
				    uint32_t *total_res_cqes)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_qp *qp_p;
	uint32_t port, qp_idx, qps_per_port;
	int rc, port_idx;

	for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
		port = cfg->ports[port_idx];

		if (qps_count_len != 1) {
			assert_true(port < qps_count_len);
			qps_per_port = (uint32_t)qps_count[port];
		} else {
			qps_per_port = (uint32_t)(*qps_count);
		}

		for (qp_idx = 0; qp_idx < qps_per_port; qp_idx++) {
			qp_p = &qps[port][qp_idx];

			rc = nic_common_fill_qp_completion_params(qp_p);
			assert_int_equal(rc, 0);

			*total_req_cqes += qp_p->req_comp_params.total_cqes;
			*total_res_cqes += qp_p->res_comp_params.total_cqes;
		}
	}

	return 0;
}

int nic_common_migrate_qps(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_qp *old_qps, *new_qps;
	size_t qps_count;

	switch (params->test_ctx->type) {
	case NIC_TEST_TYPE_BASIC:
		old_qps = params->qps[cfg->migration.old_port];
		qps_count = params->num_qps_per_port[cfg->migration.old_port];
		break;
	case NIC_TEST_TYPE_COLL:
		old_qps = params->coll_qps[cfg->coll_type][cfg->migration.old_port];
		qps_count = cfg->coll_qps_count[cfg->coll_type];
		break;
	default:
		fail_msg("QP Migration not implemented for test type %u", params->test_ctx->type);
		return -ENOTSUP;
	}

	new_qps = params->migration.qps;

	for (size_t qp_idx = 0; qp_idx < qps_count; qp_idx++) {
		struct hltests_nic_qp *old_qp = &old_qps[qp_idx], *new_qp = &new_qps[qp_idx];
		struct hbldv_qp_attr dv_qp_init_attr = {};
		struct ibv_qp_attr ibv_qp_attr = {};
		int rc;

		I("Migrating port %u qp %u conn_id: %u -> port %u qp %u conn_id: %u", old_qp->port,
		  old_qp->id, old_qp->conn_id, new_qp->port, new_qp->id, new_qp->conn_id);

		/* Setup AH and GRH. */
		ibv_qp_attr.ah_attr.is_global = 1;
		ibv_qp_attr.ah_attr.grh.hop_limit = 0xff;

		/* IB core calculates source GID using AH attribute port and GRH sgid_index. */
		ibv_qp_attr.ah_attr.port_num = (uint8_t)
						hltests_nic_to_ibdev_port_num(params->fd,
									      new_qp->port);
		ibv_qp_attr.ah_attr.grh.sgid_index = 0;
		rc = hlibv_query_gid(new_qp->ibqp->context, ibv_qp_attr.ah_attr.port_num,
				     ibv_qp_attr.ah_attr.grh.sgid_index,
				     &ibv_qp_attr.ah_attr.grh.dgid);
		assert_int_equal(rc, 0);

		ibv_qp_attr.dest_qp_num = new_qp->res_ctx.dst_conn_id;

		/* Add migration info */
		dv_qp_init_attr.caps |= HBLDV_QP_CAP_MIGRATE;
		dv_qp_init_attr.qp_to_migrate = old_qp->ibqp;

		/* RTR */
		ibv_qp_attr.qp_state = IBV_QPS_RTR;
		rc = hbldv_modify_qp(new_qp->ibqp, &ibv_qp_attr,
				     IBV_QP_STATE | IBV_QP_AV | IBV_QP_DEST_QPN, &dv_qp_init_attr);
		assert_int_equal(rc, 0);

		/* RTS */
		ibv_qp_attr.qp_state = IBV_QPS_RTS;
		rc = hbldv_modify_qp(new_qps[qp_idx].ibqp, &ibv_qp_attr, IBV_QP_STATE,
				     &dv_qp_init_attr);
		assert_int_equal(rc, 0);

		new_qp->migration_old_qp = old_qp;
	}

	for (size_t qp_idx = 0; qp_idx < qps_count; qp_idx++) {
		struct hltests_nic_qp *new_qp = &new_qps[qp_idx];
		int rc;

		rc = hbldv_migrate_qp(new_qp->ibqp);
		if (rc) {
			E("Failed to migrate QP, port: %u, qp: %u", new_qp->port, new_qp->conn_id);
			return rc;
		}
	}

	return 0;
}

/**
 * complete_handle_requester_cqe() - Handles the requester CQE, updates counters and verifies that
 *				     the CQE arrived as expected.
 * @cqe: The CQE that arrived.
 * @qp_p: The QP that the CQE belongs to.
 *
 * Return: 0 on success.
 */
static int nic_common_handle_requestor_cqe(struct hl_nic_cqe *cqe, struct hltests_nic_qp *qp_p)
{
	struct hltests_nic_test_params *params = qp_p->test_params;
	struct hltests_nic_comp_params *req_comp;
	size_t cmpl_map_idx;
	uint32_t start_req_cqe, cqe_wqe;

	D("\t\twqe index: %u", cqe->requester.wqe_index);

	req_comp = &qp_p->req_comp_params;
	assert_true(req_comp->total_cqes);

	start_req_cqe = req_comp->base_cqe;
	cqe_wqe = cqe->requester.wqe_index;

	if (params->cfg->single_cmpl) {
		assert_int_equal(cqe_wqe, start_req_cqe + params->wqes_in_cycle - 1);
	} else {
		/* Make sure that the CQEs come in order and match the expected WQEs. */
		assert_int_equal(cqe_wqe, start_req_cqe + req_comp->recv_cqes);
	}

	cmpl_map_idx = cqe_wqe - start_req_cqe;
	assert_in_range(cmpl_map_idx, 0, req_comp->cmpl_map_length - 1);
	assert_false(req_comp->cmpl_map[cmpl_map_idx]);

	req_comp->cmpl_map[cmpl_map_idx] = true;
	req_comp->recv_cqes++;

	assert_false(req_comp->recv_cqes > req_comp->total_cqes);

	return 0;
}

/**
 * complete_handle_responder_cqe() - Handles the responder CQE, updates counters and verifies that
 *				     the CQE arrived as expected.
 * @cqe: The CQE that arrived.
 * @qp_p: The QP that the CQE belongs to.
 *
 * Return: 0 on success.
 */
static int nic_common_handle_responder_cqe(struct hl_nic_cqe *cqe, struct hltests_nic_qp *qp_p)
{
	const struct hltests_nic_test_params *params = qp_p->test_params;
	const struct hltests_nic_test_funcs *funcs = params->test_ctx->funcs;
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	struct hltests_nic_comp_params *res_comp;
	size_t wq_size, cmpl_map_idx;
	uint32_t cqe_tag, cqe_wqe, start_res_cqe, tag;
	int fd = params->fd;

	D("\t\tmsg id:    %u", cqe->responder.msg_id);

	/* In WR-RDV, the responder CQE is for the sender QP, but the QP in the CQE itself is of the
	 * receiver QP.
	 */
	if (cfg->test_opcode == TEST_OPCODE_RENDEZVOUS_WRITE)
		res_comp = &qp_p->rdv_send_qp->res_comp_params;
	else
		res_comp = &qp_p->res_comp_params;

	assert_true(res_comp->total_cqes);

	wq_size = qp_p->req_ctx.wq_size;

	cqe_tag = cqe->responder.msg_id;
	cqe_wqe = (uint32_t)(cqe_tag & (wq_size - 1));
	start_res_cqe = res_comp->base_cqe;

	if (cfg->single_cmpl) {
		assert_int_equal(cqe_wqe, start_res_cqe + params->wqes_in_cycle - 1);
	} else if (cfg->sack_en) {
		assert_in_range(cqe_wqe, start_res_cqe,
				start_res_cqe + params->wqes_in_cycle - 1);
	} else {
		assert_int_equal(cqe_wqe, start_res_cqe + res_comp->recv_cqes);
	}

	cmpl_map_idx = cqe_wqe - start_res_cqe;
	assert_in_range(cmpl_map_idx, 0, res_comp->cmpl_map_length - 1);
	assert_false(res_comp->cmpl_map[cmpl_map_idx]);

	/* Gaudi2 plain_rdma provides responder CQEs but tags won't match,
	 * so skip tag matching.
	 */
	if (!(hltests_is_gaudi2(fd) && cfg->plain_rdma_en)) {
		if (funcs->get_custom_tag)
			tag = funcs->get_custom_tag(cqe, qp_p);
		else
			tag = GET_TAG(qp_p->port, qp_p->id, wq_size, cqe_wqe);

		/*
		 * For e2e we do not check the tag, since we do not know the peer port number
		 * encoded in the cqe tag.
		 */
		if (!params->cfg->e2e.enabled)
			assert_int_equal(tag, cqe_tag);
	}

	res_comp->cmpl_map[cmpl_map_idx] = true;
	res_comp->recv_cqes++;

	/* Make sure we didn't get too many CQEs */
	assert_false(res_comp->recv_cqes > res_comp->total_cqes);

	return 0;
}

/**
 * nic_common_complete_poll_and_handle_cqes() - Polls for CQEs and handles any CQEs that arrived,
 *                                              counts the requester and responder CQEs and verifies
 *                                              that all expected CQEs arrived, returns on error or
 *                                              once all CQEs have arrived.
 * @params: Test parameters.
 * @total_req_cqes: How many requester CQEs are expected.
 * @total_res_cqes: How many responder CQEs are expected.
 *
 * Return: 0 on success.
 */
static int nic_common_complete_poll_and_handle_cqes(struct hltests_nic_test_params *params,
						    size_t total_req_cqes, size_t total_res_cqes)
{
	struct hltests_nic_test_funcs *funcs = params->test_ctx->funcs;
	char f_req_path[PATH_MAX], f_res_path[PATH_MAX];
	uint32_t cqe_idx, cqe_buf_len, cqe_buf_size;
	struct hl_nic_cqe *cqe_buf, *cqe;
	uint32_t recv_req_cqes_count = 0;
	uint32_t recv_res_cqes_count = 0;
	struct hltests_nic_qp *qp_p;
	uint32_t max_num_of_qps = 0;
	uint64_t cq_timeout_us;
	int fd, rc;

	assert_non_null(funcs->find_qp_by_port_and_qpn);

	fd = params->fd;
	cqe_buf_len = (uint32_t)(total_req_cqes + total_res_cqes);
	cqe_buf_size = cqe_buf_len * sizeof(struct hl_nic_cqe);

	cqe_buf = hlthunk_malloc(cqe_buf_size);
	assert_non_null(cqe_buf);

	cq_timeout_us = hltests_is_pldm(fd) ? NIC_CQ_TIMEOUT_PLDM_USEC : NIC_CQ_TIMEOUT_USEC;

	if (hltests_get_verbose_enabled()) {
		sprintf(f_req_path, "/tmp/req-cqe_0x%lx.csv", params->cfg->ports_mask);
		sprintf(f_res_path, "/tmp/res-cqe_0x%lx.csv", params->cfg->ports_mask);
		for (int i = 0; i < params->max_num_of_ports; i++) {
			if (!(BIT(i) & params->cfg->ports_mask))
				continue;

			if (max_num_of_qps < (uint32_t)params->num_qps_per_port[i])
				max_num_of_qps = (uint32_t)params->num_qps_per_port[i];
		}
	}

	while (true) {
		uint32_t poll_recv_cqes_count;
		uint32_t rd_poll_recv_cqes_count;

		memset(cqe_buf, 0, cqe_buf_size);

		/* In case there is an error event arrived to the EQ we should fail */
		assert_int_equal(params->eq.is_error_event, 0);

		rc = hltests_nic_cq_poll(params->fd, params->cq, cqe_buf_len, cqe_buf,
					 &poll_recv_cqes_count, cq_timeout_us);
		assert_int_equal(rc, 0);

		D("Got %u completions.", poll_recv_cqes_count);

		for (cqe_idx = 0; cqe_idx < poll_recv_cqes_count; cqe_idx++) {
			cqe = &cqe_buf[cqe_idx];
			D("Got completion, port: %u, qp_id: %u, type: %s", cqe->port,
			  cqe->qp_number,
			  cqe->type == HL_NIC_CQE_TYPE_REQ ? "requestor" : "responder");
			qp_p = funcs->find_qp_by_port_and_qpn(params, cqe->port, cqe->qp_number);

			assert_non_null(qp_p);

			if (cqe->type == HL_NIC_CQE_TYPE_REQ) {
				rc = nic_common_handle_requestor_cqe(cqe, qp_p);
				assert_int_equal(rc, 0);

				recv_req_cqes_count++;
			} else {
				rc = nic_common_handle_responder_cqe(cqe, qp_p);
				assert_int_equal(rc, 0);

				recv_res_cqes_count++;
			}
		}

		if (params->cfg->rd_en) {
			rc = hltests_nic_cq_poll(params->fd, params->rd_cq, cqe_buf_len, cqe_buf,
						 &rd_poll_recv_cqes_count, cq_timeout_us);
			assert_int_equal(rc, 0);

			for (cqe_idx = 0; cqe_idx < rd_poll_recv_cqes_count; cqe_idx++) {
				cqe = &cqe_buf[cqe_idx];
				qp_p = funcs->find_qp_by_port_and_qpn(params, cqe->port,
						cqe->qp_number);

				assert_non_null(qp_p);

			D("Got completion, port: %u, qp_id: %u, type: %s", cqe->port,
			  cqe->qp_number,
			  cqe->type == HL_NIC_CQE_TYPE_REQ ? "requestor" : "responder");
			qp_p = funcs->find_qp_by_port_and_qpn(params, cqe->port, cqe->qp_number);

			assert_non_null(qp_p);

				if (cqe->type == HL_NIC_CQE_TYPE_REQ) {
					rc = nic_common_handle_requestor_cqe(cqe, qp_p);
					assert_int_equal(rc, 0);

					recv_req_cqes_count++;
				} else {
					rc = nic_common_handle_responder_cqe(cqe, qp_p);
					assert_int_equal(rc, 0);

					recv_res_cqes_count++;
				}
			}
		}

		if (hltests_get_verbose_enabled())
			dump_cqes_status_to_file(params, f_req_path, f_res_path, max_num_of_qps);

		if (recv_req_cqes_count == total_req_cqes && recv_res_cqes_count == total_res_cqes)
			break;
	}

	return 0;
}

/**
 * nic_common_complete_cq() - Waits until the current operation is completed and verifies that all
 *                            transactions have been completed as expected, and all CQEs came in the
 *                            correct order.
 * @params: Test parameters.
 *
 * Return: 0 on success.
 */
int nic_common_complete_cq(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_funcs *funcs = params->test_ctx->funcs;
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t total_req_cqes = 0;
	uint32_t total_res_cqes = 0;
	int rc;

	assert_non_null(funcs->calculate_total_cqes);
	rc = funcs->calculate_total_cqes(params, &total_req_cqes, &total_res_cqes);
	assert_int_equal(rc, 0);

	rc = nic_common_complete_poll_and_handle_cqes(params, total_req_cqes, total_res_cqes);
	assert_int_equal(rc, 0);

	hltests_nic_print_time_elapsed(&params->base, "complete CQ", cfg->verbose);

	return 0;
}

/**
 * nic_common_complete_sob() - Waits until the current operation is completed and verifies that all
 *			       transactions have been completed as expected (using SOBs).
 * @params: Test parameters.
 *
 * Return: 0 on success.
 */
static int nic_common_complete_sob(struct hltests_nic_test_params *params)
{
	struct hltests_state *tests_state = params->test_ctx->tests_state;
	struct hltests_nic_test_funcs *funcs = params->test_ctx->funcs;
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t ports_num, port, port_idx, first_sob;
	struct hltests_nic_sob_params *sob_params;
	int fd, rc;
	bool wait_for_local_sob = cfg->test_opcode != TEST_OPCODE_RENDEZVOUS_READ;

	fd = params->fd;
	first_sob = hltests_get_first_avail_sob(fd);

	/* In all collective modes except legacy, the ports collectively transmit the data,
	 * thus we only compare the buffer of the first port.
	 * Same thing with lag.
	 */
	if ((params->test_ctx->type == NIC_TEST_TYPE_COLL && cfg->coll_op > COLL_OP_MODE_LEGACY) ||
	    (params->test_ctx->type == NIC_TEST_TYPE_LAG))
		ports_num = 1;
	else
		ports_num = cfg->ports_num;

	for (port_idx = 0 ; port_idx < ports_num ; port_idx++) {
		port = cfg->ports[port_idx];
		sob_params = &params->sob_params[port];

		funcs->get_expected_sob_val(params, port);

		/* Local SOB */
		if (wait_for_local_sob) {
			rc = hltests_nic_wait_on_sob(fd,
						     (first_sob + LOCAL_SOB_ID
						     + port_idx),
						     tests_state,
						     (int32_t)sob_params->local_sob_val,
						     &params->eq);
			assert_int_equal(rc, 0);
		}

		/* Remote SOB */
		rc = hltests_nic_wait_on_sob(fd, (first_sob + REMOTE_SOB_ID + port_idx),
					     tests_state, (int32_t)sob_params->remote_sob_val,
					     &params->eq);
		assert_int_equal(rc, 0);
	}

	hltests_nic_print_time_elapsed(&params->base, "complete SOB", cfg->verbose);

	return 0;
}

/**
 * nic_common_complete() - Waits until the current operation is completed and verifies that all
 *			   transactions have been completed as expected.
 *			   In fna - only SOB is supported.
 * @params: Test parameters.
 *
 * Return: 0 on success.
 */
int nic_common_complete(struct hltests_nic_test_params *params)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	int rc;

	if (cfg->cmpl == CQ_USR)
		rc = nic_common_complete_cq(params);
	else
		rc = nic_common_complete_sob(params);

	return 0;
}

/**
 * enum config_iter_type - Configuration iteration type, basically the type of the configuration
 *                         to iterate over.
 * @CONFIG_ITER_TYPE_DATA_LOC: The data location.
 * @CONFIG_ITER_TYPE_WQ_LOC: The work queue location.
 * @CONFIG_ITER_TYPE_LAG_RCT: Lag remote completion enable.
 * @CONFIG_ITER_TYPE_CQ_TYPE: CQ type (port/device).
 * @CONFIG_ITER_TYPE_NUM: How many different configurations to iterate over.
 */
enum config_iter_type {
	CONFIG_ITER_TYPE_DATA_LOC,
	CONFIG_ITER_TYPE_WQ_LOC,
	CONFIG_ITER_TYPE_LAG_RCT,
	CONFIG_ITER_TYPE_CQ_TYPE,
	CONFIG_ITER_TYPE_NUM,
};

int nic_common_lpbk_flow(void **state, enum hltests_nic_test_type test_type)
{
	struct hltests_state *tests_state = (struct hltests_state *) *state;
	struct hltests_nic_test_ctx *test_cxt;
	struct hltests_nic_test_params *params;
	struct hltests_nic_test_cfg *cfg;
	int fd = tests_state->fd, rc;

	rc = test_ctx_init(tests_state, test_type);
	if (rc)
		return rc;

	assert_int_equal(rc, 0);

	test_cxt = get_nic_ctx_from_fd(fd);
	params = test_cxt->params;
	cfg = params->cfg;

	struct config_limit config_limits[CONFIG_ITER_TYPE_NUM] = {
		/* SRAM seems unused ¯\_(ツ)_/¯ */
		[CONFIG_ITER_TYPE_DATA_LOC] = {
			.start = cfg->data_loc == LOC_ALL ? LOC_HOST : cfg->data_loc,
			.end = cfg->data_loc == LOC_ALL ? LOC_HBM : cfg->data_loc,
		},
		/* SRAM seems unused ¯\_(ツ)_/¯ */
		[CONFIG_ITER_TYPE_WQ_LOC] = {
			.start = cfg->wq_loc == LOC_ALL ? LOC_HOST : cfg->wq_loc,
			.end = cfg->wq_loc == LOC_ALL ? LOC_HBM : cfg->wq_loc,
		},
		/* Iterate over lag remote completion types if we're running a lag test.
		 * otherwise default to 0.
		 */
		[CONFIG_ITER_TYPE_LAG_RCT] = {
			.start = false,
			.end =  test_type == NIC_TEST_TYPE_LAG,
		},
		/* Only iterate over CQ types if the completion is set to use CQ
		 * and the CQ type is set to ALL
		 */
		[CONFIG_ITER_TYPE_CQ_TYPE] = {
			.start = (cfg->cq_type == HLTESTS_NIC_CQ_TYPE_ALL) ?
					HLTESTS_NIC_CQ_TYPE_PORT : cfg->cq_type,
			.end =  (cfg->cq_type == HLTESTS_NIC_CQ_TYPE_ALL) ?
					HLTESTS_NIC_CQ_TYPE_DEVICE : cfg->cq_type,
		},
	};

	struct config_iterator *iter =
		config_iterator_init(config_limits, ARRAY_SIZE(config_limits));

	size_t i = 0;

	for (const size_t *configs = config_iterator_current(iter); configs;
	     configs = config_iterator_next(iter), i++) {
		params->data_mem_location = configs[CONFIG_ITER_TYPE_DATA_LOC];
		params->wq_mem_location = configs[CONFIG_ITER_TYPE_WQ_LOC];
		if (test_type == NIC_TEST_TYPE_LAG)
			params->lag.use_remote_completion = configs[CONFIG_ITER_TYPE_LAG_RCT];
		params->cq_type = configs[CONFIG_ITER_TYPE_CQ_TYPE];

		print_iteration_info(params, i);

		rc = set_cq_params(params);
		assert_int_equal(rc, 0);

		rc = hw_init(params);
		assert_int_equal(rc, 0);

		rc = pre_runtime(params);
		assert_int_equal(rc, 0);

		rc = test_cxt->funcs->runtime(params);
		assert_int_equal(rc, 0);

		if (!cfg->cleanup)
			goto out;

		if (cfg->wait_for_cleanup)
			hltests_nic_wait_for_cleanup();

		rc = hw_fini(params);
		assert_int_equal(rc, 0);

		unset_cq_params(params);
	}

	config_iterator_destroy(iter);

	printf("\n");

	rc = test_ctx_fini(params);
	assert_int_equal(rc, 0);

	return 0;

out:
	config_iterator_destroy(iter);
	return 0;
}

/**
 * nic_patcher_reserve_coll_qps() - Reserves QP ids for collective QPs.
 * @ibpd:         Pointer to ibv_pd handle structure.
 * @qp_number:    Output, returns the qp number reserved for the collective qps.
 * @is_scale_out: Whether to reserve for scale out or scale up collective qps.
 * @coll_ports_mask: Mask of ports to be used in the collective connection.
 *
 * Return: 0 on success.
 */
int nic_patcher_reserve_coll_qps(struct ibv_pd *ibpd, uint32_t *qp_number, bool is_scale_out,
				 uint64_t coll_ports_mask)
{
	struct hbldv_coll_qp_attr coll_qp_attr = {
		.is_scale_out = is_scale_out,
		.ports_mask = coll_ports_mask,
	};
	struct hbldv_coll_qp coll_qp = {};
	uint32_t retry;
	int rc;

	for (retry = 1; retry <= QP_ALLOC_RETRIES; retry++) {
		rc = hbldv_reserve_coll_qps(ibpd, &coll_qp_attr, &coll_qp);

		if (rc == 0)
			*qp_number = coll_qp.qp_num;

		/* Retry on EBUSY */
		if (rc != EBUSY)
			break;

		sleep(retry);
	}

	assert_int_equal(rc, 0);

	return 0;
}

/**
 * nic_patcher_allocate_device_data_buffers() - Allocates data buffers on the device memory.
 * @params:               Test parameters.
 * @buffers_count:        How many buffers are necessary for source and destination, size is taken
 *                        from params.
 * @mem:                  Out, memory block that contains the local and remote buffers together.
 * @source_offset:        Out, the offset of the allocated local buffer.
 * @destination_offset:   Out, the offset of the allocated remote buffer.
 *
 * Return: 0 on success.
 */
int nic_patcher_allocate_device_data_buffers(const struct hltests_nic_test_params *params,
					     size_t buffers_count, struct hltests_memory *mem,
					     uint64_t *source_offset, uint64_t *destination_offset)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	const struct hlthunk_hw_ip_info *hw_ip = &params->test_ctx->tests_state->hw_ip;
	uint64_t data_size, total_size;
	int fd = params->fd;

	data_size = params->data_size;
	total_size = buffers_count * (data_size + params->dst_data_size);
	assert_true(total_size);

	/* Allocate one big buffer and split it into source and destination buffers.*/

	switch (cfg->data_loc) {
	case LOC_ALL:
	case LOC_HBM: {
		const struct hltests_memory *device_mem;
		int rc;

		/* Compression: Source and destination address should be 128 bytes aligned.
		 * Allocate extra space to align the addresses later.
		 */
		if (cfg->compression_en)
			total_size += 2 * SZ_128;

		assert_true(total_size <= hw_ip->dram_size);

		/* We'll be pushing the virtual address into the dmem list, it will be popped and
		 * freed in `destroy_device_mem`
		 */
		device_mem = hltests_allocate_device_mem_ret_mem(fd, total_size, 0, CONTIGUOUS);
		assert_non_null(device_mem);

		*mem = *device_mem;

		static_assert(sizeof(void *) >= sizeof(mem->device_virt_addr),
			      "The cast to `void *` can be fatal on 32bit systems, whoever decided to return a `void *` clearly wasn't thinking straight.");
		rc = hltests_nic_dmem_list_push((void *)(uintptr_t)mem->device_virt_addr);
		assert_int_equal(rc, 0);

		*source_offset = 0;
		*destination_offset = (*source_offset) + (buffers_count * data_size);

		if (cfg->compression_en) {
			uint64_t alignment =
				ALIGN_UP(mem->device_virt_addr, SZ_128) - mem->device_virt_addr;

			*source_offset = alignment;
			*destination_offset =
				alignment + ALIGN_UP(buffers_count * data_size, SZ_128);
		}

		break;
	}
	case LOC_SRAM: {
		assert_true(total_size <= hw_ip->sram_size);

		mem->device_virt_addr = hw_ip->sram_base_address;
		mem->host_ptr = NULL;

		*source_offset = 0;
		*destination_offset = (*source_offset) + (buffers_count * data_size);

		break;
	}
	default:
		fail();
	}

	return 0;
}

/**
 * nic_patcher_create_qps() - Allocates patcher QP numbers, creates matching QPs for each port, then
 *                            initializes the QPs.
 * @params:       Test parameters.
 * @qps:          Array of qps per port.
 * @qps_count:    How many qps are per port.
 * @is_scale_out: Are these scale out qps.
 * @reserve_qps:  Is qp number reservation necessary.
 *
 * Return: 0 on success
 */
int nic_patcher_create_qps(struct hltests_nic_test_params *params,
			   struct hltests_nic_qp **qps, size_t qps_count,
			   bool is_scale_out, bool reserve_qps)
{
	const struct hltests_nic_test_cfg *cfg = params->cfg;
	size_t qp_idx;

	for (qp_idx = 0; qp_idx < qps_count; qp_idx++) {
		uint32_t port_idx, qp_number = 0;
		int rc;

		if (reserve_qps) {
			uint64_t ibdev_port_mask = hltests_nic_to_ibdev_port_mask(params->fd,
										  cfg->ports_mask);

			/* Reserve a collective qp id */
			rc = nic_patcher_reserve_coll_qps(params->ibpd, &qp_number, is_scale_out,
							  ibdev_port_mask);
			assert_int_equal(rc, 0);
		}

		/* Create and configure the qp for all the ports using the collective id */
		for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
			struct hltests_nic_qp *qp;
			uint32_t port;

			port = cfg->ports[port_idx];
			qp = &qps[port][qp_idx];

			rc = create_qp(params, port, port_idx, qp_number, qp,
				       reserve_qps);
			assert_int_equal(rc, 0);
		}
	}

	/* This is done in a separate loop, after all the QPs have been created, as some of the QPs
	 * depend on their pairs having already been created
	 */
	for (qp_idx = 0; qp_idx < qps_count; qp_idx++) {
		uint32_t port_idx;

		for (port_idx = 0; port_idx < cfg->ports_num; port_idx++) {
			struct hltests_nic_qp *qp;
			uint32_t port = cfg->ports[port_idx];
			int rc;

			qp = &qps[port][qp_idx];

			rc = nic_common_set_qp(qp, qps);
			assert_int_equal(rc, 0);
		}
	}

	return 0;
}

/**
 * nic_lag_is_port_in_operation() - Checks if this port partakes in the LAG operation.
 * @cfg:          Test configuration.
 * @lag_port_idx: The lag index of the port.
 *
 * Return: true if the port partakes, false otherwise.
 */
bool nic_lag_is_port_in_operation(const struct hltests_nic_test_cfg *cfg, size_t lag_port_idx)
{
	/* The port idx is basically the port's lag index */
	if (cfg->lag.last_index >= cfg->lag.first_index) {
		if (cfg->lag.first_index <= lag_port_idx && lag_port_idx <= cfg->lag.last_index)
			return true;
	} else if (lag_port_idx <= cfg->lag.last_index || cfg->lag.first_index <= lag_port_idx)
		return true;

	return false;
}

/**
 * nic_common_migration_check_event() - Trigger link shutdown event and check we receive it.
 * @params:          Test params.
 *
 * Return: 0 on success.
 */
int nic_common_migration_check_event(struct hltests_nic_test_params *params)
{
	struct hltests_nic_test_cfg *cfg = params->cfg;
	uint32_t count, max_count = 10;
	int rc;

	params->eq.link_shutdown_port = -1;
	rc = hltests_nic_debugfs_trigger_link_shutdown_event(params->test_ctx->tests_state->fd,
							     (uint32_t)cfg->migration.old_port);
	if (rc)
		return rc;

	/* poll for the reception of the link shutdown event */
	for (count = 0; count < max_count; count++) {
		usleep(20000);
		if (params->eq.link_shutdown_port >= 0)
			break;
	}

	D("count: %u link_shutdown_port: %d", count, params->eq.link_shutdown_port);

	assert_true(count < max_count);
	assert_true(params->eq.link_shutdown_port == cfg->migration.old_port);

	return 0;
}

/**
 * nic_common_get_coll_qp_type() - Return the currently active collection qp type,
 *                                 assuming, that only one type is active for a test.
 * @params:          Test params.
 *
 * Return: 0 on success.
 */
enum hltests_nic_coll_qp_type nic_common_get_coll_qp_type(const struct hltests_nic_test_params *p)
{
	struct hltests_nic_test_cfg *cfg = p->cfg;

	if (cfg->coll_qps_count[COLL_QP_TYPE_SCALE_UP])
		return COLL_QP_TYPE_SCALE_UP;
	else
		return COLL_QP_TYPE_SCALE_OUT;
}
