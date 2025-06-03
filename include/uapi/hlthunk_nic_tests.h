/* SPDX-License-Identifier: MIT
 *
 * Copyright 2019-2023 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef HLTHUNK_NIC_TESTS_H
#define HLTHUNK_NIC_TESTS_H

#include "hlthunk.h"
#include "hlthunk_tests.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include <infiniband/verbs.h>
#include <infiniband/hbldv.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define MAX_NIC_NUMBER_OF_PORTS		48

/* Set this to the max QPs size between all Gaudis (currently it's 16K like in Gaudi3).
 * Note that this value is just for our static allocations.
 */
#define MAX_NUM_OF_QPS			(1 << 14)
#define WQES_MIN			16
#define DB_SOB_ID			0
#define LOCAL_SOB_ID			(DB_SOB_ID + MAX_NIC_NUMBER_OF_PORTS)
#define REMOTE_SOB_ID			(LOCAL_SOB_ID + MAX_NIC_NUMBER_OF_PORTS * \
								DB_ITER_PER_CYCLE)
#define DB_FIFO_SOB_ID			(REMOTE_SOB_ID + MAX_NIC_NUMBER_OF_PORTS * \
								DB_ITER_PER_CYCLE)

/* Relevant for all ASICs */
#define MAX_SOB_VAL			((1 << 15) - 1)

/* Relevant for G3 and above - CI register is free run 11 bits counter */
#define DB_FIFO_CI_FREE_RUN		(1 << 11)

#define CS_MON_ID			0
#define FNA_MON_ID			(CS_MON_ID + MAX_NIC_NUMBER_OF_PORTS)
#define BP_MON_ID			(FNA_MON_ID + AFA_MAX_NUM_OF_CMPL_REGS)

#define WQES_MIN			16

#define E2E_PRINT_LEN			32

#define MAC_STR_LEN			(ETH_ALEN * 2 + (ETH_ALEN - 1))

#define QP_ALLOC_RETRIES		5

#define DB_ITER_PER_CYCLE		4

/* NIC completion type */
#define CQ_SLEEP_USEC			1000
#define NIC_CQ_TIMEOUT_USEC		120000000 /* 2 minutes */
#define NIC_CQ_TIMEOUT_PLDM_USEC	1200000000 /* 20 minutes */

#define NIC_QP_TIMER_GRAN		13 /* 32.768 ms */

#define NIC_PDMA_TIMEOUT_USEC		120000000 /* 2 minutes */
#define NIC_PDMA_TIMEOUT_PLDM_USEC	600000000 /* 10 minutes */

#define VXLAN_PORT_NUM			4789
#define GRE_PROTOCOL_NUMBER		0x2F
#define GRE_ETHERNET_BRIDGING		0x6558

/* For older kernel versions which miss this define */
#ifndef SPEED_200000
#define SPEED_200000			200000
#endif

#define MAX_COLL_COMM_GROUPS		256
#define MAX_COLL_COMM_GROUPS_DIRECT	512
#define MAX_COLL_COMM_RANKS		2

#define CC_CQE_SIZE			16

/* dma_alloc can only allocate 2M */
#define USER_CCQ_MAX_ENTRIES		((1 << 21) / CC_CQE_SIZE)

#define DEFAULT_GID_SUBNET_PREFIX	0xfe80000000000000ULL

#define PLAIN_RDMA_MAGIC		((uint64_t)0xfeedface01facadeULL)
#define PLAIN_RDMA_MAGIC_SIZE		sizeof(PLAIN_RDMA_MAGIC)

#define IS_RDV(bmap)			((bmap) & (BIT_ULL(OP_RDV_WRITE) | BIT_ULL(OP_RDV_READ)))
#define GET_TAG(port, qp, wq_size, wqe) ((port) << 24 | (qp) << HL_LOG2(wq_size) | (wqe))

#define DEVICE_CQ_PORT_IDX	((uint8_t)-1)

#define KNRM	"\x1B[0m"
#define KRED	"\x1B[1m\033[31m"
#define KGRN	"\x1B[1m\033[32m"
#define KYEL	"\x1B[1m\033[33m"
#define KBLU	"\x1B[1m\033[34m"
#define KMAG	"\x1B[1m\033[35m"
#define KCYN	"\x1B[1m\033[36m"
#define KWHT	"\x1B[1m\033[37m"

enum hltests_nic_verbose_level {
	VERBOSE_NONE,
	VERBOSE_INFO,
	VERBOSE_DEBUG
};

enum hltests_nic_id {
	HLTESTS_NIC_E2E_LPBK = 1,
	HLTESTS_NIC_GEN_TEST = 2,
};

/* hltests_nic_coll_comm_node: Collective group node
 * @db_fifo: Doorbell fifo.
 * @comm_group: Associated collective communication group.
 * @conn_id: Port QP id.
 * @rank: Collective rank of the node.
 * @port_id: Port ID.
 * @is_last_rank: If node belongs to last rank.
 */
struct hltests_nic_coll_comm_node {
	struct hltests_nic_db_fifo_data *db_fifo;
	struct hltests_nic_coll_comm_group *comm_group;
	uint32_t conn_id;
	uint32_t rank;
	uint32_t port_id;
	bool is_last_rank;
};

/* hltests_nic_coll_comm_group: Collective communication group.
 * @nodes: Collective nodes in the group.
 * @tests_state: Hl-thunk test context.
 * @in_params: NIC test input params.
 * @nodes_mask: Mask of nodes in the group.
 * @id: Collective context ID.
 * @nodes_per_rank: Number of nodes per collective rank.
 * @n_ranks: Number of ranks in the group.
 * @allocated: Is collective context allocated.
 */
struct hltests_nic_coll_comm_group {
	struct hltests_nic_coll_comm_node nodes[MAX_NIC_NUMBER_OF_PORTS];
	struct hltests_state *tests_state;
	struct hltests_nic_in_params *in_params;
	uint64_t nodes_mask;
	uint32_t id;
	uint32_t nodes_per_rank;
	uint32_t n_ranks;
	bool allocated;
};

/* hltests_nic_coll_comm_node: Collective group node
 * @db_fifo: Doorbell fifo.
 * @comm_group: Associated collective communication group.
 * @qp_id: Port QP id.
 * @rank: Collective rank of the node.
 * @port_id: Port ID.
 * @is_last_rank: If node belongs to last rank.
 */
struct hltests_nic_coll_comm_node_new {
	struct hltests_nic_db_fifo_data *db_fifo;
	struct hltests_nic_coll_comm_group_new *comm_group;
	uint32_t conn_id;
	uint32_t rank;
	uint32_t port_id;
	bool is_last_rank;
};

/* hltests_nic_coll_comm_group: Collective communication group.
 * @nodes: Collective nodes in the group.
 * @tests_state: Hl-thunk test context.
 * @in_params: NIC test input params.
 * @nodes_mask: Mask of nodes in the group.
 * @id: Collective context ID.
 * @nodes_per_rank: Number of nodes per collective rank.
 * @n_ranks: Number of ranks in the group.
 * @allocated: Is collective context allocated.
 */
struct hltests_nic_coll_comm_group_new {
	struct hltests_nic_coll_comm_node_new nodes[MAX_NIC_NUMBER_OF_PORTS];
	struct hltests_state *tests_state;
	const struct hltests_nic_test_params *params;
	uint64_t nodes_mask;
	uint32_t id;
	uint32_t nodes_per_rank;
	uint32_t n_ranks;
	bool allocated;
};

/**
 * struct hltests_nic_lag_op_params: Lag operation parameters.
 * @params: Test parameters.
 * @coll_qp_number: Collective ID of the QP to use in the lag descriptor.
 * @local_base_addr: "source" buffer base address (either in host or device memory).
 * @remote_base_addr: "destination" buffer base address (either in host or device memory).
 */
struct hltests_nic_lag_op_params {
	const struct hltests_nic_test_params *params;
	uint32_t coll_qp_number;
	uint64_t local_base_addr;
	uint64_t remote_base_addr;
};

/**
 * struct hltests_nic_lag_op_params: Lag operation parameters.
 * @params: Test parameters.
 * @coll_qp_number: Collective ID of the QP to use in the lag descriptor.
 * @tag: Tag to put in the descriptor, same value should be received in remote side CQE tag.
 */
struct hltests_nic_lag_completion_op_params {
	const struct hltests_nic_test_params *params;
	uint32_t coll_qp_number;
	uint32_t tag;
};

enum hltests_nic_cmpl {
	NONE = 0x0,
	SOB = 0x1,
	CQ_USR = 0x4
};

enum hltests_nic_cq_type {
	HLTESTS_NIC_CQ_TYPE_PORT, /* This is also the default */
	HLTESTS_NIC_CQ_TYPE_DEVICE,
	HLTESTS_NIC_CQ_TYPE_ALL,
};

enum hltests_nic_submission {
	USER_FIFO,
	QMAN
};

enum hltests_nic_data_loc {
	DATA_LOC_ALL,
	DATA_LOC_HOST,
	DATA_LOC_DRAM,
	DATA_LOC_SRAM
};

enum hltests_nic_wq_loc {
	WQ_LOC_HOST,
	WQ_LOC_DEVICE,
	WQ_LOC_ALL
};

enum hltests_nic_test {
	LPBK,
	E2E,
};

struct hltests_nic_user_db {
	uint32_t wqe_pi:22;
	uint32_t reserved:10;
	uint32_t qpn:24;
	uint32_t port:8;
};

struct hltests_nic_port_eq {

	uint32_t port;
};

struct hltests_nic_eq {
	struct ibv_context *ibctx;
	uint64_t ports_mask;
	pthread_t thread_id;
	uint32_t num_of_ports;
	int is_error_event;
	int fd;
	int link_shutdown_port;
};

struct hltests_nic_db_fifo_packet {
	void *packet;
	uint32_t size;
};


struct hltests_nic_port_cq {
	pthread_t thread_id;
	bool enabled;
	void *cq_buf;
	void *cq_buf_raw;
	void *regs_ptr;
	void *pi_ptr;
	struct ibv_cq *ibvcq;
	size_t cq_buf_len;
	int port;
	uint32_t id;
	uint32_t regs_offset;
	struct {
		void *cq;
		int port;
	} thread_params;
};

struct hltests_nic_cq {
	struct hltests_state *tests_state;
	struct ibv_context *ibctx;
	void *cq_buf;
	size_t cq_buf_len;
	uint32_t cq_pi;
	uint32_t cq_ci;
	enum hltests_nic_cq_type type;
	int fd;
	bool fna;

	struct {
		struct hltests_nic_port_cq *port_cq;
		pthread_spinlock_t cq_lock;
		void *(*user_cq_port_poll)(void *args);
		uint32_t thread_count;
		uint64_t port_mask[2];
		uint32_t cq_buf_len;
		uint32_t cqe_cnt;
		uint32_t cq_pi;
		uint32_t cq_ci;
		uint32_t raw_cqe_size;
	} user_cq;
};

/**
 * struct hltests_nic_ccqs_poll_info - Holds info for polling ccqs the following members are used to
 * calculate the number of pkts.
 * @ccqs: Pointer to an array of ccq.
 * @port_mask: Mask on which ports ccqs were created.
 * @qps_per_port: The number of qps attached to the port.
 * @max_n_ports: The number of ports.
 */
struct hltests_nic_ccqs_poll_info {
	struct hltests_nic_ccq *ccqs;
	uint64_t port_mask;
	uint32_t qps_per_port;
	int max_n_ports;
};

/**
 * struct hltests_nic_db_fifo_data - Holds info for user doorbell fifo usage.
 * @hbldv_usr_fifo: Pointer to the IB fifo structure.
 * @regs_cpu_ptr: Pointer to the fifo's mapped address.
 * @ci_cpu_ptr: Pointer to the fifo's mapped consumer index address.
 * @regs_handle: Handle for fifo returned from user-db-fifo-set to use with mmap.
 * @ci_handle: Handle for ci returned from user-db-fifo-set to use with mmap.
 * @id: This fifo id.
 * @pi: Producer index for user's usage.
 * @fifo_size: Total size in bytes.
 * @fifo_bp_thresh: Back-pressure threshold in bytes.
 * @regs_offset: Offset to the db-fifo registers.
 * @sob_id: The ID of the SOB to use instead of memory CI.
 * @num_sobs: Number of LBW SOB CIs.
 * @ib_db_type: The type of the DB fifo.
 * @is_dup_enabled: Enable DUP interface. Default is UMR.
 */
struct hltests_nic_db_fifo_data {
	struct hbldv_usr_fifo *hbldv_usr_fifo;
	void *regs_cpu_ptr;
	void *ci_cpu_ptr;
	uint64_t regs_handle;
	uint64_t ci_handle;
	uint32_t id;
	uint32_t pi;
	uint32_t fifo_size;
	uint32_t fifo_bp_thresh;
	uint32_t regs_offset;
	uint32_t sob_id;
	uint32_t num_sobs;
	enum hbldv_usr_fifo_type ib_db_type;
	bool is_dup_enabled;
};

/**
 * struct hltests_nic_ccq - Holds info for one congestion control queue.
 * @ibvcq: Pointer to the IB CC CQ structure.
 * @cc_sq: CC submission queue.
 * @ccq_buf: Memory of mapped CCQ buffer.
 * @ccq_buf_len: CCQ number of entries.
 * @ccq_pi_handle: Handle for CCQ PI mapping.
 * @ccq_handle: Handle for CCQ mapping.
 * @ccq_pi_mem: Memory for mapped producer index.
 * @ccq_ci: Consumer index.
 * @ccq_pi: Producer index.
 * @port: The port number for this CCQ.
 * @fd: File descriptor.
 */
struct hltests_nic_ccq {
	struct ibv_cq *ibvcq;
	struct hltests_nic_db_fifo_data *cc_sq;
	void *ccq_buf;
	size_t ccq_buf_len;
	uint64_t ccq_pi_handle;
	uint64_t ccq_handle;
	uint32_t *ccq_pi_mem;
	uint32_t ccq_ci;
	uint32_t ccq_pi;
	uint32_t port;
	int fd;
};

struct hltests_nic_ccqe {
	union {
		struct {
			__u64 ecn:24;
			__u64 off25:5;
			__u64 phase:1;
			__u64 drop:1;
			__u64 valid:1;
			__u64 qpn:24;
			__u64 off55:8;
			__u64 rtt:24;
			__u64 off87:8;
			__u64 psn_del:24;
			__u64 gap119:8;
		} bits;

		__u8 data[16];
	};
};

struct hltests_nic_cc_sq_bbr_msg {
	union {
		struct {
			__u64 burst_size:22;
			__u64 msg:2;
			__u64 sqn:8;
			__u64 cong_win:24;
			__u64 res_24_31:8;
			__u64 pace_time:16;
			__u64 res_80_95:16;
			__u64 qp:24;
			__u64 valid_mask:4;
			__u64 res_124_127:4;
		} bits;

		__u8 data[16];
	};
};

/**
 * struct hltests_nic_post_swift_msg - holds a cc submission message.
 * @burst_size: burst size.
 * @cong_win: congestion window.
 * @pace_time: delay between sending packets.
 * @sqn: send queue number.
 * @qp: the qp for this message.
 * @port: the port for this message.
 */
struct hltests_nic_post_cc_bbr_msg {
	uint32_t burst_size;
	uint32_t cong_win;
	uint32_t pace_time;
	uint32_t sqn;
	uint32_t qp;
	uint32_t port;
};

struct hltests_nic_cc_sq_swift_msg {
	union {
		struct {
			__u64 ai:8;
			__u64 res_8_21:14;
			__u64 msg:2;
			__u64 max_mdf:8;
			__u64 target_delay:22;
			__u64 res_56_63:8;
			__u64 beta_nom:8;
			__u64 beta_denom:8;
			__u64 res_80_95:16;
			__u64 qp:24;
			__u64 valid_mask:4;
			__u64 res_124_127:4;
		} bits;

		__u8 data[16];
	};
};

/**
 * struct hltests_nic_requester_conn_ctx - set up a requester connection context
 * @dst_ip_addr: Destination IP address in native endianness
 * @dst_conn_id: Destination connection ID
 * @last_index: Index of last entry [2..(2^22)-1]. NOTE: relevant for Gaudi1 (only)
 * @congestion_wnd: Congestion-Window size
 * @wq_size: Max number of elements in the work queue. NOTE: relevant for Gaudi2 (or higher)
 * @remote_key: Remote-key to be used to generate on outgoing packets
 * @mtu: Max Transmit Unit
 * @dst_mac_addr: Destination MAC address
 * @priority: Connection priority [0..3]
 * @timer_granularity: Timer granularity [0..127]
 * @swq_granularity: SWQ granularity [0 for 32B or 1 for 64B]
 * @wq_type: Work queue type [1..3]
 * @cq_number: Completion queue number
 * @wq_remote_log_size: Remote Work queue log size [2^QPC] Rendezvous
 * @congestion_en: Enable/disable Congestion-Control
 * @encap_en: used as boolean; indicates if this QP has encapsulation support
 * @encap_id: Encapsulation-id; valid only if 'encap_en' is set
 * @loopback: used as boolean; indicates if this QP used for loopback mode.
 * @coll_lag_idx: (Gaudi3 and above) The index of the specific NIC within the LAG. Note that the
 *                advanced flag must be enabled in case it's being set.
 * @coll_last_in_lag: (Gaudi3 and above) Is the specific NIC the last one within the collective LAG.
 *                    Note that the advanced flag must be enabled in case it's being set.
 * @compression_en: Enable compression
 * @sack_en: (Gaudi3 and above) Enable Selective Acknowledgment (SACK)
 * @coll_lag_size: The collective LAG size (i.e. number of ports in this LAG).
 */
struct hltests_nic_requester_conn_ctx {
	uint32_t dst_ip_addr;
	uint32_t dst_conn_id;
	uint32_t last_index;
	uint32_t congestion_wnd;
	uint32_t wq_size;
	uint32_t remote_key;
	uint16_t mtu;
	uint8_t dst_mac_addr[ETH_ALEN];
	uint8_t priority;
	uint8_t timer_granularity;
	uint8_t swq_granularity;
	uint8_t wq_type;
	uint8_t cq_number;
	uint8_t wq_remote_log_size;
	uint8_t congestion_en;
	uint8_t encap_en;
	uint8_t encap_id;
	uint8_t loopback;
	uint8_t coll_lag_idx;
	uint8_t coll_last_in_lag;
	uint8_t compression_en;
	uint8_t sack_en;
	uint8_t coll_lag_size;
};

/**
 * struct hltests_nic_responder_conn_ctx - set up a responder connection context
 * @dst_ip_addr: Destination IP address in native endianness
 * @dst_conn_id: Destination connection ID
 * @conn_peer: Connection peer
 * @wq_peer_size: size of the peer Work queue
 * @local_key: Local-key to be used to validate against incoming packets
 * @dst_mac_addr: Destination MAC address
 * @priority: Connection priority [0..3]
 * @wq_peer_granularity: Work queue granularity
 * @cq_number: Completion queue number
 * @rdv: used as boolean; indicates if this QP is RDV (WRITE or READ)
 * @loopback: used as boolean; indicates if this QP used for loopback mode.
 * @encap_en: used as boolean; indicates if this QP has encapsulation support
 * @encap_id: Encapsulation-id; valid only if 'encap_en' is set
 * @sack_en: (Gaudi3 and above) Enable Selective Acknowledgment (SACK)
 */
struct hltests_nic_responder_conn_ctx {
	uint32_t dst_ip_addr;
	uint32_t dst_conn_id;
	uint32_t conn_peer;
	uint32_t wq_peer_size;
	uint32_t local_key;
	uint8_t dst_mac_addr[ETH_ALEN];
	uint8_t priority;
	uint8_t wq_peer_granularity;
	uint8_t cq_number;
	uint8_t rdv;
	uint8_t loopback;
	uint8_t encap_en;
	uint8_t encap_id;
	uint8_t sack_en;
};

/**
 * struct hltests_nic_post_cc_swift_msg - holds a cc submission message.
 * @ai: Additive increase factor.
 * @max_mdf: Maximum Multiplicative decrease factor.
 * @target_delay: compared with the RTT value measured.
 * @beta_nom: Multiplicative decrease factor - numerator.
 * @beta_denom: Multiplicative decrease factor - denominator.
 * @qp: the qp for this message.
 * @port: the port for this message.
 */
struct hltests_nic_post_cc_swift_msg {
	uint32_t ai;
	uint32_t max_mdf;
	uint32_t target_delay;
	uint32_t beta_nom;
	uint32_t beta_denom;
	uint32_t qp;
	uint32_t port;
};

/* Align hltests_nic_test_opcode to the WQE Opcodes number so that its easy to comprehend which
 * opcode is being tested by which test
 */
enum hltests_nic_test_opcode {
	TEST_OPCODE_NOP = 0x0,
	TEST_OPCODE_SEND = 0x01,
	TEST_OPCODE_LINEAR_WRITE = 0x02,
	TEST_OPCODE_LCL_MULTI_STRIDE = 0x03,
	TEST_OPCODE_MULTI_STRIDE_SINGLE = 0x04,
	TEST_OPCODE_RENDEZVOUS_WRITE = 0x05,
	TEST_OPCODE_RENDEZVOUS_READ = 0x06,
	TEST_OPCODE_ATOMIC_FETCH_ADD = 0x07,
	TEST_OPCODE_MULTI_STRIDE_DUAL = 0x08,
	TEST_OPCODE_ATOMIC_FETCH_ADD_WRITE = 0x09,
	TEST_OPCODE_ATOMIC_FETCH_ADD_READ = 0x0A,
	TEST_OPCODE_FIFO_ALLOC = 0x0B,
	TEST_OPCODE_FIFO_PUSH = 0x0C
};

/* These are the only data types supported by the test. This will not map exactly to the
 * actual reduction data types supported by ASIC
 */
enum hltests_nic_reduction_datatype {
	HLTESTS_NIC_REDUCTION_INT8                 = 0x0,
	HLTESTS_NIC_REDUCTION_BF16                 = 0x1,
	HLTESTS_NIC_REDUCTION_FP32                 = 0x2,
	HLTESTS_NIC_REDUCTION_UPSCALING_BF16       = 0x3,
	HLTESTS_NIC_REDUCTION_DOWNSCALING_TO_BF16  = 0x4,
	HLTESTS_NIC_REDUCTION_BF16_DOWN_AND_UP     = 0x5,
	HLTESTS_NIC_REDUCTION_DT_INVALID           = 0xFF
};

enum hltests_nic_reduction_operation {
	HLTESTS_NIC_REDUCTION_OP_ADDITION     = 0x0,
	HLTESTS_NIC_REDUCTION_OP_SUBTRACTION  = 0x1,
	HLTESTS_NIC_REDUCTION_OP_MINIMUM      = 0x2,
	HLTESTS_NIC_REDUCTION_OP_MAXIMUM      = 0x3,
	HLTESTS_NIC_REDUCTION_OP_INVALID      = 0xFF
};

/**
 * enum hltests_nic_coll_op_mode - Patcher test modes
 * @COLL_OP_DISABLED: Disable patcher HW.
 * @COLL_OP_MODE_LEGACY: Use patcher HW for legacy operation.
 *                       i.e Each port/QP transmits data independently.
 * @COLL_OP_MODE_MULTI_LAG: Use single rank. All ports are part of this rank.
 * @COLL_OP_MODE_MULTI_RANK: Use multiple ranks. Distribute available
 *                           ports equally among all ranks.
 * @COLL_OP_MODE_MULTI_CONTEXT: Use multiple collective contexts.
 */
enum hltests_nic_coll_op_mode {
	COLL_OP_DISABLED = 0,
	COLL_OP_MODE_LEGACY = 1,
	COLL_OP_MODE_MULTI_LAG = 2,
	COLL_OP_MODE_MULTI_RANK = 3,
	COLL_OP_MODE_MULTI_CONTEXT = 4,
};

/**
 * enum hltests_nic_afa_cmpl_mode - FnA completion modes
 * @AFA_REG_CMPL: FnA register completion mode
 * @AFA_CQ_USR_CMPL: user CQ FnA completion mode
 */
enum hltests_nic_afa_cmpl_mode {
	AFA_REG_CMPL,
	AFA_CQ_USR_CMPL,
	AFA_CMPL_MODE_MAX,
};

/**
 * enum hltests_nic_afa_op_mode - FnA operation modes
 * @AFA_OP_DRAM: FnA operation will occur on a DRAM address
 * @AFA_OP_SRAM: FnA operation will occur on an SRAM address
 */
enum hltests_nic_afa_op_mode {
	AFA_OP_DRAM,
	AFA_OP_SRAM,
	AFA_OP_MAX,
};

/* enum hltests_nic_cc_mode - Congestion control mode.
 * @CC_DISABLED: CC is disabled.
 * @CC_BBR: BBR algorithm with HW acceleration off.
 * @CC_SWIFT: SWIFT algorithm with HW acceleration on. Gaudi3 and up.
 */
enum hltests_nic_cc_mode {
	CC_MODE_DISABLED = 0,
	CC_MODE_BBR = 1,
	CC_MODE_SWIFT = 2,
};

enum hltests_nic_qp_lpbk_mode {
	QP_LPBK_DISABLED = 0,
	QP_LPBK_ENABLED = 1,
	QP_LPBK_MIXED = 2,
};

enum hltests_nic_coll_type {
	COLL_TYPE_CONTEXT = 0,
	COLL_TYPE_DIRECT = 1,
};

enum hltests_nic_rdv_type {
	HLTESTS_NIC_RDV_SND_RCV = 0x0,
	HLTESTS_NIC_RDV_MS = 0x1,
	HLTESTS_NIC_RDV_V_OP = 0x02,
};

enum hltests_nic_coll_data_type {
	HLTESTS_NIC_COLL_DATA_TYPE_REDUCTION = 0x0,
	HLTESTS_NIC_COLL_DATA_TYPE_128_BYTE = 0x1,
	HLTESTS_NIC_COLL_DATA_TYPE_256_BYTE = 0x2,
	HLTESTS_NIC_COLL_DATA_TYPE_4_BITS = 0x3,
	HLTESTS_NIC_COLL_DATA_TYPE_1_BYTE = 0x4,
	HLTESTS_NIC_COLL_DATA_TYPE_2_BYTES = 0x5,
	HLTESTS_NIC_COLL_DATA_TYPE_4_BYTES = 0x6,
	HLTESTS_NIC_COLL_DATA_TYPE_INVALID = 0xFF,
};

/* HW NIC completion types supported */
enum hltests_nic_comp_type {
	HLTESTS_NIC_NO_COMP = 0,
	HLTESTS_NIC_SOB_COMP = 1,
	HLTESTS_NIC_CQ_COMP = 2,
	HLTESTS_NIC_BOTH_COMP = 3
};

enum hltests_nic_coll_desc_axis_type {
	COLL_DESC_Z_AXIS = 0x0,
	COLL_DESC_X_AXIS = 0x1,
	COLL_DESC_Y_AXIS = 0x2,
	COLL_DESC_RESERVED = 0x3,
};

struct hltests_nic_lpbk_cfg {
	uint32_t ports[MAX_NIC_NUMBER_OF_PORTS];
	uint32_t qps_per_port[MAX_NIC_NUMBER_OF_PORTS];
	enum hltests_nic_wq_loc wq_loc;
	enum hltests_nic_data_loc data_loc;
	enum hltests_nic_cmpl cmpl;
	enum hltests_nic_test_opcode test_opcode;
	enum hltests_nic_reduction_datatype red_dt;
	enum hltests_nic_reduction_operation red_op;
	enum hl_nic_db_fifo_type db_fifo_mode;
	enum hltests_nic_coll_op_mode coll_op;
	enum hltests_nic_cc_mode cc_cq;
	enum hltests_nic_rdv_type rdv_type;
	enum hltests_nic_coll_type coll_type;
	enum hltests_nic_afa_cmpl_mode fna_cmpl;
	enum hltests_nic_coll_data_type coll_dt;
	enum hltests_nic_coll_desc_axis_type axis_rank;
	uint32_t iterations_mem;
	uint32_t iterations_db;
	uint32_t iterations_wq;
	uint32_t cq_buf_len_shift;
	uint32_t user_cq_buf_len_shift;
	uint32_t user_cq_idx;
	uint32_t verbose;
	uint32_t ports_num;
	uint32_t qps_per_port_num_elements;
	uint32_t max_qps_per_port;
	uint32_t src_ip_addr;
	uint32_t fna_thresh;
	uint16_t mtu;
	uint8_t wqe_size_shift;
	uint8_t data_size_shift;
	uint8_t data_cmp;
	uint8_t single_alloc;
	uint8_t cleanup;
	uint8_t wait_for_cleanup;
	uint8_t db_qman;
	uint8_t wtd_en;
	uint8_t eq_poll;
	uint8_t user_db;
	uint8_t encap_type;
	uint8_t reduction_en;
	uint8_t qp_loopback;
	uint8_t atomic_val_loc;
	uint8_t compression_en;
	uint8_t plain_rdma;
	uint8_t bp_offs;
	uint8_t sack_en;
	uint8_t err_inject_percent;
	uint8_t force_wq_with_pmmu;
	uint8_t odp;
	uint8_t single_cmpl;
	uint8_t assign_qp_priority;
	uint8_t number_of_ranks;
	uint8_t print_bw;
	uint8_t disregard_rank;
};

struct hltests_nic_e2e_cfg {
	uint32_t ports[MAX_NIC_NUMBER_OF_PORTS];
	uint32_t qps_per_port[MAX_NIC_NUMBER_OF_PORTS];
	uint32_t *dst_conn_ids;
	uint32_t *dst_ips;
	uint32_t *remote_sob_idx;
	uint32_t *remote_addr_idx;
	uint32_t *seed;
	uint32_t ports_num;
	uint32_t qps_per_port_num_elements;
	uint32_t dst_conn_ids_num;
	uint32_t dst_ips_num;
	uint32_t remote_sob_idx_num;
	uint32_t remote_addr_idx_num;
	uint32_t seed_num;
	uint32_t dst_macs_num;
	uint32_t iterations;
	uint32_t max_qps_per_port;
	uint32_t user_cq_buf_len_shift;
	uint32_t user_cq_idx;
	enum hltests_nic_wq_loc wq_loc;
	enum hltests_nic_cmpl cmpl;
	enum hltests_nic_verbose_level verbose;
	uint16_t mtu;
	uint8_t **dst_macs;
	uint8_t wqe_size_shift;
	uint8_t data_size_shift;
	uint8_t wq_on_hbm;
	uint8_t print_data;
	uint8_t wait_for_cleanup;
	uint8_t sleep_before_cleanup;
	uint8_t lazy;
	uint8_t doorbell_to;
	uint8_t rand_data;
	uint8_t data_cmp;
	uint8_t cleanup;
	uint8_t user_db;
	uint8_t cc_cq;
	uint8_t encap_type;
	uint32_t src_ip_addr;
	uint8_t plain_rdma;
};

struct hltests_nic_dna_cfg {
	uint32_t port;
	uint32_t num_iterations;
	uint8_t rank;
	uint8_t dump_buf;
};

struct hltests_nic_conn_in {
	int conn_per_port[MAX_NIC_NUMBER_OF_PORTS];
};

struct hltests_nic_conn_out {
	uint32_t conn_id[MAX_NIC_NUMBER_OF_PORTS][MAX_NUM_OF_QPS];
	void *swq_buf[MAX_NIC_NUMBER_OF_PORTS][MAX_NUM_OF_QPS];
	void *rwq_buf[MAX_NIC_NUMBER_OF_PORTS][MAX_NUM_OF_QPS];
	struct ibv_qp *ibqp[MAX_NIC_NUMBER_OF_PORTS][MAX_NUM_OF_QPS];
};

struct hltests_nic_contexts {
	struct hltests_nic_requester_conn_ctx req_ctx[MAX_NIC_NUMBER_OF_PORTS][MAX_NUM_OF_QPS];
	struct hltests_nic_responder_conn_ctx res_ctx[MAX_NIC_NUMBER_OF_PORTS][MAX_NUM_OF_QPS];
};

struct hltests_nic_in_params {
	struct hltests_nic_conn_out *nic_conn;
	struct hltests_nic_cq *cq;
	struct hltests_nic_cq *cqs;
	struct hltests_nic_coll_comm_group *comm_group;
	struct hltests_nic_db_fifo_data **db_fifos;
	struct hltests_nic_ib_in_params *ib_in_params;
	struct hltests_nic_contexts *nic_ctx;
	struct hltests_nic_eq *eq;
	struct timespec base;
	uint32_t fna_qp_send_data[MAX_NIC_NUMBER_OF_PORTS][MAX_NUM_OF_QPS];
	void *src_buf[MAX_NIC_NUMBER_OF_PORTS][MAX_NUM_OF_QPS];
	void *dst_buf[MAX_NIC_NUMBER_OF_PORTS][MAX_NUM_OF_QPS];
	void *dst_buf_ref[MAX_NIC_NUMBER_OF_PORTS][MAX_NUM_OF_QPS];
	void ***swqe_arr;
	void ***rwqe_arr;
	uint32_t qps_per_port[MAX_NIC_NUMBER_OF_PORTS];
	uint64_t local_dram_addr;
	uint64_t remote_dram_addr;
	uint64_t local_sram_addr;
	uint64_t remote_sram_addr;
	uint64_t port_mask;
	uint64_t cc_port_mask;
	uint64_t nic_ports_mask;
	uint64_t data_size;
	uint64_t reduction_cfg;
	uint64_t fna_op_addr;
	uint64_t dst_data_size;
	uint32_t wqe_size;
	uint32_t iterations;
	uint32_t *seed;
	uint32_t *tag;
	uint32_t *remote_sob_idx;
	uint32_t *remote_addr_idx;
	uint32_t *dst_conn_ids;
	uint32_t tag_buf_size;
	uint32_t max_qps_per_port;
	uint32_t n_ports;
	uint32_t fna_thresh;
	uint32_t n_db_fifos;
	uint32_t nwq;
	uint32_t max_coll_comm_groups;
	uint32_t num_of_wqs;
	enum hl_nic_mem_id wq_loc;
	enum hltests_nic_test test;
	enum hltests_nic_cmpl cmpl;
	enum hltests_nic_verbose_level verbose;
	enum hltests_nic_test_opcode test_opcode;
	enum hltests_nic_coll_op_mode coll_op;
	enum hltests_nic_rdv_type rdv_type;
	enum hltests_nic_coll_type coll_type;
	enum hltests_nic_coll_data_type coll_dt;
	enum hltests_nic_coll_desc_axis_type axis_rank;
	bool is_dram;
	bool single_alloc;
	bool db_qman;
	bool wtd_en;
	bool user_db;
	bool upscale_en;
	bool downscale_en;
	bool cache_en;
	bool is_sram;
	bool compression_en;
	uint8_t fna_cmpl;
	uint8_t atomic_val_loc;
	uint8_t bp_offs;
	bool sack_en;
	bool force_wq_with_pmmu;
	bool single_cmpl;
	bool is_plain_rdma;
	uint8_t number_of_ranks;
	uint8_t plain_rdma;
	uint8_t disregard_rank;
};

struct hltests_nic_ib_app_params {
	uint8_t advanced;
	uint32_t bp_offs[HL_NIC_USER_BP_OFFS_MAX];
	uint8_t deprecated;
	uint8_t fna_mask_size;
	uint32_t fna_fifo_offs[HL_NIC_FNA_CMPL_ADDR_NUM];
};

struct hltests_nic_ib_in_params {
	struct hltests_nic_in_params *in_params;
	struct ibv_context *ibctx;
	struct ibv_pd *ibpd;
	struct hltests_nic_cq *cqs;
	struct hltests_nic_ib_app_params ib_app_params;
	void *cfg;
	struct ibv_cq *ibcq;
	struct hltests_nic_eq *eq;
	int fd;
};

struct hltests_nic_wqe_params {
	void *sq_wqe;
	void *rq_wqe;
	uint64_t local_address;
	uint64_t remote_address;
	uint64_t reduction_cfg;
	uint64_t fna_op_addr;
	uint64_t size;
	uint32_t qp;
	uint32_t rdv_remote_pi;
	uint32_t cq_id;
	bool ackreq;
	int wqe_index;
	int tag;
	int local_sob_id;
	int remote_sob_id;
	enum hltests_nic_cmpl cmpl;
	uint8_t fna_cmpl;
	bool is_wr_rdv_send;
	enum hltests_nic_test_opcode test_opcode;
	bool downscale_en;
	bool cache_en;
	bool compression_en;
	bool upscale_en;
	bool keys_en;
	bool rd_enable;
};

struct hltests_nic_gen_test_cfg {
	enum hltests_nic_wq_loc wq_loc;
	uint32_t dst_conn_id;
	uint64_t num_wqs_shift;
	uint64_t num_wqes_shift;
	uint32_t num_iterations;
	uint32_t num_threads;
	bool is_pldm;
};

struct hltests_nic_gen_test_wq {
	int fd;
	uint32_t port;
	uint32_t num_wqs;
	uint32_t num_wq_entries;
	enum hl_nic_mem_id mem_id;
};

struct hltests_nic_vxlan_header {
	uint32_t flags:8;
	uint32_t reserved1:24;
	uint32_t vxlan_nw_id:24;
	uint32_t reserved:8;
};

struct hltests_nic_gre_header {
	uint32_t checksum:1;
	uint32_t reserved1:1;
	uint32_t key_present:1;
	uint32_t sequence:1;
	uint32_t reserved:9;
	uint32_t version:3;
	uint32_t protocol:16;
	uint32_t vsid:24;
	uint32_t flowid:8;
};

struct hltests_nic_user_fifo_params {
	struct hltests_state *tests_state;
	struct hltests_nic_db_fifo_data **fifos;
	struct hltests_nic_in_params *test_params;
	struct hltests_nic_contexts *nic_ctx;
	uint64_t port_mask;
	uint64_t fna_op_addr;
	uint32_t(*qp_ids)[MAX_NUM_OF_QPS];
	uint32_t *qps_per_port;
	uint32_t nwqs;
	uint32_t max_qps_per_port;
	int n_fifos;
	uint8_t *cmpl_mem_hdl;
	enum hltests_nic_test_opcode test_opcode;
};

struct hltests_nic_config_encap_params {
	uint32_t *qps_per_port;
	uint32_t *ports;
	uint64_t port_mask;
	uint32_t max_qps_per_port;
	uint32_t ports_num;
	uint32_t src_ip_addr;
	uint8_t encap_type;
};

union hltests_nic_encap {
	struct hbldv_encap *hbl_encap;
	uint32_t id;
};

enum hltests_nic_coll_patcher_opcode {
	COLL_PATCHER_OPCODE_GEN,
	COLL_PATCHER_OPCODE_VOP
};

enum hltests_nic_multi_stride_type {
	NIC_MS_TYPE_NONE,
	NIC_MS_TYPE_SINGLE,
	NIC_MS_TYPE_DUAL
};

enum hltests_nic_coll_qp_type {
	COLL_QP_TYPE_SCALE_UP,
	COLL_QP_TYPE_SCALE_OUT,

	COLL_QP_TYPE_MAX
};

enum hltests_nic_supported_features {
	OP_WRITE,
	OP_RDV_WRITE,
	OP_RDV_READ,
	WTD_DWQ,
	MS_TYPE_SINGLE,
	MS_TYPE_DUAL,
	ENCAP_TYPE_VXLAN,
	ENCAP_TYPE_GRE,
	ENCAP_TYPE_SRC_IP,
	COMPRESSION,
	ODP,
	REDUCTION,
	SACK,
	CC_BBR,
	CC_SWIFT,
	QP_LPBK,
	PLAIN_RDMA,
	RDMA_KEYS_IN_WQE,
};

enum hltests_nic_location {
	LOC_HOST,
	LOC_HBM,
	LOC_SRAM,
	LOC_ALL
};

struct hltests_nic_test_cfg {
	uint32_t runtime_iterations;

	enum hltests_nic_location data_loc;
	enum hltests_nic_location wq_loc;
	enum hltests_nic_cmpl cmpl;
	enum hltests_nic_cq_type cq_type;
	enum hltests_nic_submission submission;
	enum hltests_nic_test_opcode test_opcode;

	uint32_t ports[MAX_NIC_NUMBER_OF_PORTS];
	uint32_t ports_num;
	uint64_t ports_mask;

	uint32_t qps_per_port[MAX_NIC_NUMBER_OF_PORTS];
	uint32_t qps_per_port_num_elements;
	uint32_t lpbk_qps_per_port[MAX_NIC_NUMBER_OF_PORTS];
	uint32_t lpbk_qps_per_port_num_elements;

	/* Sizes */
	uint8_t data_size_shift;
	uint8_t wqe_size_shift;
	uint8_t cq_size_shift;
	uint16_t mtu;

	/* CQ */
	uint32_t cq_buf_len_shift;
	uint32_t user_cq_buf_len_shift;
	uint32_t user_cq_idx;

	/* General options */
	uint8_t data_cmp;
	uint8_t single_alloc;
	uint8_t single_cmpl;
	uint8_t eq_poll;
	uint8_t cleanup;
	uint8_t wait_for_cleanup;
	uint8_t force_wq_with_pmmu;
	uint8_t assign_qp_priority;
	uint8_t print_bw;
	uint8_t verbose;

	/* Features */
	uint8_t avx;
	/* WTD/DWQ */
	uint8_t wtd_en;

	/* Multi stride */
	enum hltests_nic_multi_stride_type ms_type;

	/* Reduction */
	uint8_t reduction_en;
	enum hltests_nic_reduction_datatype red_dt;
	enum hltests_nic_reduction_operation red_op;

	/* RDV */
	enum hltests_nic_rdv_type rdv_type;

	/* Encap */
	uint8_t encap_en;
	uint8_t encap_type;
	uint32_t src_ip_addr;

	/* CC */
	enum hltests_nic_cc_mode cc_mode;

	/* ODP */
	uint8_t odp_en;

	/* SACK */
	uint8_t sack_en;

	/* Compression */
	uint8_t compression_en;

	/* plain RDMA */
	uint8_t plain_rdma_en;

	/* RDMA keys in WQE */
	uint8_t keys_en;

	/* RD WQE */
	uint8_t rd_en;

	/* e2e */
	struct {
		uint8_t enabled;
		struct hlthunk_mac_addr dst_macs[MAX_NIC_NUMBER_OF_PORTS];
		uint32_t dst_ips[MAX_NIC_NUMBER_OF_PORTS];
		uint32_t dst_conn_ids[MAX_NIC_NUMBER_OF_PORTS];
		uint32_t rand_seed[MAX_NIC_NUMBER_OF_PORTS];
		uint32_t num_dst_macs;
		uint32_t num_dst_ips;
		uint32_t num_dst_conn_ids;
		uint32_t num_seeds;
		uint32_t seconds_to_wait_to_submit;
	} e2e;

	union {
		/* Collective */
		struct {
			size_t coll_qps_count[COLL_QP_TYPE_MAX];
			size_t coll_lpbk_qps_count[COLL_QP_TYPE_MAX];
			enum hltests_nic_coll_type coll_type;
			enum hltests_nic_coll_op_mode coll_op;
			enum hltests_nic_coll_patcher_opcode coll_patcher_op;
			enum hltests_nic_coll_data_type coll_data_type;
			enum hltests_nic_coll_desc_axis_type coll_rank_axis;
			uint8_t coll_ranks_num;
			bool disregard_rank;
		};

		/* Atomic FNA */
		struct {
			enum hltests_nic_afa_cmpl_mode atomic_fna_cmpl;
			uint32_t atomic_fna_thresh;
			uint8_t atomic_val_loc;
		};

		struct {
			size_t participating_ports_num;
			size_t qps_count;
			size_t lpbk_qps_count;
			uint32_t first_index;
			uint32_t last_index;
			bool scale_out;
			bool use_keys;
		} lag;
	};

	struct {
		int32_t old_port;
		int32_t new_port;
		uint32_t runtime_iterations_trigger;
		bool enable;
		bool check_event;
	} migration;

	uint64_t features_bitmap;
};

struct hltests_nic_test_ctx;
struct hltests_nic_test_params;

struct hltests_nic_comp_params {
	bool *cmpl_map;
	size_t cmpl_map_length;
	uint32_t total_cqes;
	uint32_t recv_cqes;
	uint32_t base_cqe;
};

struct hltests_nic_qp {
	struct hltests_nic_test_params *test_params;
	struct ibv_qp *ibqp;

	uint32_t id;
	uint32_t port;

	uint32_t conn_id;
	uint32_t curr_pi;
	uint32_t dest_pi;

	void *host_src_buf;
	void *host_dst_buf;
	void *host_dst_buf_orig;
	void *host_dst_buf_ref;

	struct hltests_memory dev_mem;
	size_t local_dev_mem_offset;
	size_t remote_dev_mem_offset;

	struct hltests_nic_requester_conn_ctx req_ctx;
	struct hltests_nic_responder_conn_ctx res_ctx;

	struct hltests_nic_comp_params req_comp_params;
	struct hltests_nic_comp_params res_comp_params;

	void *swq_buf;
	void *rwq_buf;

	struct hbldv_encap *encap_data;

	/* RDV */
	bool is_rdv_sender;
	union {
		struct hltests_nic_qp *rdv_recv_qp;
		struct hltests_nic_qp *rdv_send_qp;
	};

	struct hltests_nic_qp *migration_old_qp;

	bool is_lpbk;

	union {
		/* Patcher */
		struct {
			bool is_coll;
			uint32_t hint;
			uint32_t lag_index;
			uint32_t coll_qp_number;
		};

		/* Atomic FNA */
		struct {
			uint32_t atomic_fna_send_data;
			uint32_t atomic_fna_prev_cmpl;
		};
	};
};

struct hltests_nic_sob_params {
	uint32_t local_sob_val;
	uint32_t remote_sob_val;
};

enum hltests_lag_test_stage {
	HLTESTS_LAG_TEST_STAGE_LAG,
	HLTESTS_LAG_TEST_STAGE_LAG_COMPLETION,
};

struct hltests_nic_test_params {
	struct hltests_nic_test_ctx *test_ctx;
	int fd;
	struct hltests_nic_test_cfg *cfg;

	struct timespec base;

	enum hltests_nic_location data_mem_location;
	enum hltests_nic_location wq_mem_location;
	enum hltests_nic_cq_type cq_type;

	uint32_t max_num_of_ports;

	struct ibv_context *ibctx;
	struct ibv_pd *ibpd;
	struct ibv_cq *ibcq;

	struct hltests_nic_qp *qps[MAX_NIC_NUMBER_OF_PORTS];
	size_t num_qps_per_port[MAX_NIC_NUMBER_OF_PORTS];
	bool use_generic_qps;

	struct hltests_nic_cq *cqs;
	struct hltests_nic_cq *cq;
	struct hltests_nic_cq *rd_cqs;
	struct hltests_nic_cq *rd_cq;
	struct hltests_nic_eq eq;

	struct hltests_nic_db_fifo_data **user_fifos;

	uint64_t data_size;
	uint64_t dst_data_size;
	uint64_t wqe_size;
	uint32_t num_wqes_in_wq;
	uint32_t wqes_in_cycle;

	struct hltests_nic_sob_params sob_params[MAX_NIC_NUMBER_OF_PORTS];

	uint64_t reduction_cfg;
	bool upscale_en;
	bool downscale_en;

	struct hltests_nic_ccq ccqs[MAX_NIC_NUMBER_OF_PORTS];
	struct hltests_nic_db_fifo_data *cc_user_fifos;

	union {
		/* Collective */
		struct {
			struct hltests_nic_qp *coll_qps[COLL_QP_TYPE_MAX][MAX_NIC_NUMBER_OF_PORTS];
			struct hltests_nic_coll_comm_group_new *coll_comm_group;
			void ***swqe_arr;
			void ***rwqe_arr;
		};

		/* Atomic FNA */
		struct {
			uint64_t atomic_fna_op_addr;
			uint8_t *atomic_fna_cmpl_mem_hdl;
			uint32_t atomic_fna_cmpl_mem_size;
		};

		/* Back Pressure */
		struct {
			uint32_t bp_offs_base_id[MAX_NIC_NUMBER_OF_PORTS];
			uint32_t num_bp_offs[MAX_NIC_NUMBER_OF_PORTS];
			uint32_t bp_cmpl_mem_size;
			uint8_t *bp_cmpl_mem_hdl;
		};

		/* Lag */
		struct {
			struct hltests_nic_qp *qps[MAX_NIC_NUMBER_OF_PORTS];
			void *host_buffer_source;
			void *host_buffer_destination;
			struct hltests_memory dev_mem;
			uint64_t dev_mem_source_offset;
			uint64_t dev_mem_destination_offset;
			size_t nic_size;
			size_t nic_residue;
			enum hltests_lag_test_stage current_stage;
			bool use_remote_completion;
		} lag;
	};

	struct {
		struct hltests_nic_qp *qps;
	} migration;
};

enum hltests_nic_test_type {
	NIC_TEST_TYPE_BASIC,
	NIC_TEST_TYPE_COLL,
	NIC_TEST_TYPE_BP_OFFS,
	NIC_TEST_TYPE_ATOMIC_FNA,
	NIC_TEST_TYPE_PLAIN_RDMA,
	NIC_TEST_TYPE_LAG,
};

enum hltests_nic_lag_fifo_index {
	HLTESTS_NIC_LAG_FIFO_INDEX_LAG = 0,
	HLTESTS_NIC_LAG_FIFO_INDEX_LAG_COMPLETION = 1,
	HLTESTS_NIC_LAG_FIFO_INDEX_NUM,
};

static_assert(sizeof(enum hbldv_usr_fifo_type) <= sizeof(int),
	      "User fifo type should fit inside int, for get_user_fifo_type");

struct hltests_nic_test_funcs {
	uint64_t (*get_supported_features_mask)(int fd);
	int (*parse_cfg)(int fd, struct hltests_nic_test_cfg *cfg);
	int (*validate_cfg)(int fd, struct hltests_nic_test_cfg *cfg);
	void (*print_cfg)(const struct hltests_nic_test_cfg *cfg);
	void (*print_iteration_info)(const struct hltests_nic_test_params *params);
	void (*set_cq_params)(struct hltests_nic_test_params *params);
	int (*alloc_qps_db)(struct hltests_nic_test_params *params);
	int (*alloc_device_mem)(struct hltests_nic_test_params *params);
	int (*alloc_host_mem_buffers)(struct hltests_nic_test_params *params);
	void (*fill_port_app_params)(struct hltests_nic_test_params *params, uint32_t port,
					struct hltests_nic_ib_app_params *app_params);
	uint32_t (*get_user_fifo_num)(struct hltests_nic_test_params *params);
	int (*get_user_fifo_type)(struct hltests_nic_test_params *params, uint32_t fifo_idx);
	int (*create_qps)(struct hltests_nic_test_params *params);
	void (*get_expected_sob_val)(struct hltests_nic_test_params *params, uint32_t port);
	void (*fill_qp_attr)(struct hltests_nic_qp *qp_p);
	int (*get_cqes_per_qp)(const struct hltests_nic_qp *qp, uint32_t *total_req_cqes,
			       uint32_t *total_res_cqes);
	struct hltests_nic_qp *(*find_qp_by_port_and_qpn)(struct hltests_nic_test_params *params,
							  uint32_t port, uint32_t qp_num);
	int (*calculate_total_cqes)(struct hltests_nic_test_params *params,
				    uint32_t *total_req_cqes, uint32_t *total_res_cqes);
	int (*set_wq_buffers)(struct hltests_nic_qp *qp_p);
	int (*pre_runtime)(struct hltests_nic_test_params *params);
	int (*runtime)(struct hltests_nic_test_params *params);
	int (*destroy_qps)(struct hltests_nic_test_params *params);
	void (*free_wq_buffers)(struct hltests_nic_qp *qp_p);
	void (*destroy_qps_db)(struct hltests_nic_test_params *params);
	uint32_t (*get_custom_tag)(const struct hl_nic_cqe *cqe, const struct hltests_nic_qp *qp_p);
	/* General (un)initialization, called right after device open */
	int (*init)(struct hltests_nic_test_params *param);
	void (*fini)(struct hltests_nic_test_params *param);
};

struct hltests_nic_test_ctx {
	struct hltests_state *tests_state;
	enum hltests_nic_test_type type;
	struct hltests_nic_test_funcs *funcs;
	struct hltests_nic_test_params *params;
};

struct hltests_nic_asic_funcs {
	int (*asic_priv_init)(struct hltests_device *hdev, void *arg, uint64_t ctx_port_mask);
	int (*get_default_cfg)(void *cfg, enum hltests_nic_id id);
	int (*run_wtd)(int fd, void *p_in);
	int (*run_coll_op)(void *comm_group);
	int (*run_coll_op_new)(struct hltests_nic_coll_comm_group_new *comm_group);
	int (*run_lag_op)(const struct hltests_nic_lag_op_params *params);
	int (*run_lag_completion_op)(const struct hltests_nic_lag_completion_op_params *params);
	int (*get_max_num_of_ports)(void);
	uint64_t (*get_port_mask)(void);
	uint32_t (*get_base_qid)(void);
	uint32_t (*get_wq_offset)(int fd, int port, uint32_t conn_id);
	int (*fill_wqe)(int fd, void *p_in);
	void *(*get_swqe)(void *swq, int offset);
	void *(*get_rwqe)(void *rwq, int offset);
	uint8_t (*get_swqe_size)(void);
	uint8_t (*get_rwqe_size)(void);
	uint32_t (*get_max_pi)(struct hltests_nic_qp *qp_p);
	int (*get_min_conn_id)(int fd, uint32_t port);
	int (*get_max_conn_id)(int fd, uint32_t port);
	int (*get_max_num_of_qps)(int fd, uint32_t port);
	uint32_t (*get_min_coll_conn_id)(int fd, bool is_scale_out);
	uint32_t (*get_max_coll_conn_id)(int fd, bool is_scale_out);
	uint32_t (*get_coll_qps_offset)(int fd, uint32_t port);
	uint32_t (*get_max_num_of_coll_qps)(int fd, bool is_scale_out);
	void (*pre_setup_ctx)(int fd, struct hltests_nic_requester_conn_ctx *req_ctx);
	void (*pre_setup_default_ctx_rdv)(int fd, struct hltests_nic_requester_conn_ctx *req_ctx,
						enum hltests_nic_test_opcode test_opcode,
						bool is_rdv_send, bool swq_granularity);
	int (*setup_ctx_lpbk)(int fd, int port,
				struct hltests_nic_requester_conn_ctx *req_ctx,
				struct hltests_nic_responder_conn_ctx *res_ctx,
				uint32_t conn, struct hltests_nic_lpbk_cfg *cfg);
	int (*setup_ctx_e2e)(int fd, int port,
				struct hltests_nic_requester_conn_ctx *req_ctx,
				struct hltests_nic_responder_conn_ctx *res_ctx,
				struct hltests_nic_e2e_cfg *cfg);
	void (*setup_default_ctx_rdv)(int fd, int port,
					struct hltests_nic_requester_conn_ctx *req_ctx,
					struct hltests_nic_responder_conn_ctx *res_ctx,
					bool is_rdv_send, uint32_t conn_id, bool swq_granularity);
	uint32_t (*get_user_cqe)(int fd, struct hl_nic_cqe *cqe_sw,
				 struct hltests_nic_port_cq *port_cq, uint32_t hw_ci);
	int (*user_cq_create)(int fd, struct hltests_nic_cq *cq);
	int (*user_cq_destroy)(int fd, struct hltests_nic_cq *cq);
	uint32_t (*add_bulk_doorbell_pkt)(void *buf, uint32_t buf_size, int nic, uint64_t conn_id,
						uint64_t db_val);
	uint64_t (*get_db_fifo_umr)(int fd, uint32_t port, uint32_t db_fifo_id);
	uint64_t (*get_db_fifo_dup)(int fd, uint32_t port, uint32_t db_fifo_id);
	uint32_t (*get_db_fifo_entry_size)(void);
	uint8_t (*get_db_fifo_element_size)(void);
	uint32_t (*get_hw_wq_pi)(uint32_t nwqs, uint32_t wq_size, uint32_t iteration,
					uint32_t cmpl, bool is_bp_offs);
	int (*config_reduction)(int fd, enum hltests_nic_reduction_operation red_op,
				enum hltests_nic_reduction_datatype red_data_type,
				uint64_t *reduction);
	void (*clear_lbw_memory)(int fd, uint8_t *sm_obj_base, uint32_t idx, uint32_t num_elements);
	int (*create_dwq_packet)(struct hltests_nic_db_fifo_packet *wtd, void *swqe, void *rwqe,
					int qp_id);
	void (*parse_eqe_qp_syndrome)(uint32_t port, struct hlthunk_nic_eq_poll_out *eqe);
	uint32_t (*read_mem_cmpl)(int fd, uint32_t qp, uint8_t *blk);
	uint32_t (*get_mem_cmpl_addr)(int fd, uint32_t idx);
	uint8_t *(*map_lbw_block)(int fd, uint32_t *size);
	int (*unmap_lbw_block)(int fd, void *host_addr, uint32_t block_size);
	uint64_t (*get_half_port_mask)(int fd, uint64_t port_mask, bool is_upper_half);

	void (*fill_bp_offs_params)(int fd, uint32_t port, uint32_t *bp_offs_base_id,
					uint32_t *num_bp_offs);
	void (*ovrd_wqes_data_size)(void *swqe);
	int (*submit_wtd)(struct hltests_nic_test_params *params);
	int (*submit_db)(struct hltests_nic_test_params *params);
	void (*write_desc_to_db_fifo)(struct hltests_state *tests_state,
				      struct hltests_nic_db_fifo_data *db_fifo,
				      struct hltests_nic_db_fifo_packet *db_fifo_packet,
				      uint32_t port, bool is_dup);

};

static inline void *get_nic_ctx_from_fd(int fd)
{
	return get_hdev_from_fd(fd)->nic_test_ctx;
}

int hltests_nic_setup(void **state);
int hltests_nic_teardown(void **state);
int hltests_root_nic_setup(void **state);
int hltests_root_nic_teardown(void **state);

void hltests_nic_print_time_elapsed(struct timespec *base, char *str,
					enum hltests_nic_verbose_level verbose);

bool hltests_nic_is_ibdev(int fd);
int hltests_nic_to_ibdev_port_num(int fd, int hl_port_num);
int hltests_ibdev_to_nic_port_num(int ib_port_num);

uint64_t hltests_nic_to_ibdev_port_mask(int fd, uint64_t hl_port_mask);

uint32_t hltests_nic_convert_mtu_to_ibv_mtu(uint32_t mtu);

int hltests_nic_cb_list_push(void *cb);
void *hltests_nic_cb_list_pop(void);
int hltests_nic_hmem_list_push(void *buf);
void *hltests_nic_hmem_list_pop(void);
int hltests_nic_dmem_list_push(void *buf);
void *hltests_nic_dmem_list_pop(void);

int hltests_nic_debugfs_read(int fd, const char *name, const char *format, ...)
	__attribute__((format(scanf, 3, 4)));
int hltests_nic_debugfs_write(int fd, const char *name, const char *format, ...)
	__attribute__((format(printf, 3, 4)));
int hltests_nic_debugfs_set_coll_lag_size(int fd, uint32_t coll_lag_size);
int hltests_nic_debugfs_inject_rx_err(int fd, uint8_t drop_percent);
int64_t hltests_nic_debugfs_get_user_asid(struct hltests_state *test_state);
int hltests_nic_debugfs_trigger_link_shutdown_event(int fd, uint32_t hbl_port);

int hltests_nic_wait_for_cleanup(void);

void hltests_nic_parse_mac(uint8_t *mac, const char *value);
void hltests_nic_copy_mac_reverse(uint8_t *dst, const uint8_t *src);
void hltests_nic_stringify_mac(char *buf, uint8_t *mac);

int hltests_nic_get_default_cfg(int fd, void *cfg, enum hltests_nic_id id);

int hltests_nic_run_wtd(int fd, void *p_in);
int hltests_nic_run_coll_op(int fd, void *comm_group);
int hltests_nic_run_coll_op_new(int fd, struct hltests_nic_coll_comm_group_new *comm_group);
int hltests_nic_run_lag_op(struct hltests_nic_lag_op_params *params);
int hltests_nic_run_lag_completion_op(struct hltests_nic_lag_completion_op_params *params);

int hltests_nic_get_max_num_of_ports(int fd);
uint64_t hltests_nic_get_port_mask(int fd);
uint32_t hltests_nic_get_base_qid(int fd);

uint32_t hltests_nic_get_wq_offset(int fd, int port, uint32_t conn_id);
void hltests_nic_fill_wqe(int fd, void *p_in);
void *hltests_nic_get_swqe(int fd, void *swq, int offset);
void *hltests_nic_get_rwqe(int fd, void *rwq, int offset);
uint8_t hltests_nic_get_swqe_size(int fd);
uint8_t hltests_nic_get_rwqe_size(int fd);

int hltests_nic_get_min_conn_id(int fd, uint32_t port);
int hltests_nic_get_max_conn_id(int fd, uint32_t port);
int hltests_get_max_num_of_qps(int fd, uint32_t port);
uint32_t hltests_nic_get_min_coll_conn_id(int fd, bool is_scale_out);
uint32_t hltests_nic_get_max_coll_conn_id(int fd, bool is_scale_out);
uint32_t hltests_nic_get_coll_qps_offset(int fd, uint32_t port);

uint32_t hltests_nic_get_sob_value(struct hltests_state *tests_state, uint32_t sob_idx);
int hltests_nic_wait_on_sob(int fd, uint32_t sob_idx, struct hltests_state *tests_state, int value,
			    const struct hltests_nic_eq *eq);

void hltests_nic_pre_setup_ctx(int fd, struct hltests_nic_requester_conn_ctx *req_ctx);
void hltests_nic_pre_setup_default_ctx_rdv(int fd, struct hltests_nic_requester_conn_ctx *req_ctx,
					enum hltests_nic_test_opcode test_opcode, bool is_rdv_send,
					bool swq_granularity);
int hltests_nic_setup_ctx_lpbk(int fd, int port,
					struct hltests_nic_requester_conn_ctx *req_ctx,
					struct hltests_nic_responder_conn_ctx *res_ctx,
					uint32_t conn,
					struct hltests_nic_lpbk_cfg *cfg);
int hltests_nic_setup_ctx_e2e(int fd, int port,
					struct hltests_nic_requester_conn_ctx *req_ctx,
					struct hltests_nic_responder_conn_ctx *res_ctx,
					struct hltests_nic_e2e_cfg  *cfg);
void hltests_nic_setup_default_ctx_rdv(int fd, int port,
					struct hltests_nic_requester_conn_ctx *req_ctx,
					struct hltests_nic_responder_conn_ctx *res_ctx,
					bool is_rdv_send, uint32_t conn_id, bool swq_granularity);

void *hltests_nic_user_cq_port_poll(void *args);
int hltests_nic_user_cq_create(int fd, struct hltests_nic_cq *cq);
int hltests_nic_cq_create(int fd, struct hltests_nic_cq *cq);
int hltests_nic_user_cq_destroy(int fd, struct hltests_nic_cq *cq);
int hltests_nic_cq_destroy(int fd, struct hltests_nic_cq *cq);
int hltests_nic_cq_poll(int fd, struct hltests_nic_cq *cq, uint32_t num_cqes_req,
			void *cq_buf_out, uint32_t *num_cqes_out,
			uint64_t timeout_us);

int hltests_nic_ccqs_create(int fd, struct hltests_nic_ccq ccqs[], uint32_t ccq_buf_len,
				int max_n_ports, uint64_t port_mask,
				struct hltests_nic_db_fifo_data **db_fifos);
int hltests_nic_ccqs_destroy(int fd, struct hltests_nic_ccq ccqs[], int max_n_ports,
				uint64_t port_mask);
int hltests_nic_ccq_create_and_map(struct hltests_nic_ccq *ccq);
int hltests_nic_ccq_unmap_and_destroy(struct hltests_nic_ccq *ccq);
int hltests_nic_ccq_poll(struct hltests_nic_ccq *ccq, uint32_t starting_qp, uint32_t qps_per_port);
int hltests_nic_post_cc(struct hltests_state *tests_state, struct hltests_nic_ccqs_poll_info *info,
			uint32_t port, bool add_swift_msg, uint32_t qp);

int hltests_nic_create_db_packet(struct hltests_nic_db_fifo_packet *db, uint32_t wqe_pi,
					uint32_t qpn, uint32_t port);
uint32_t hltests_nic_add_bulk_doorbell_pkt(int fd, void *buf, uint32_t buf_size, int nic,
						uint64_t conn_id, uint64_t db_val);
uint64_t hltests_nic_get_db_fifo_umr(int fd, uint32_t port, uint32_t db_fifo_id);
uint64_t hltests_nic_get_db_fifo_dup(int fd, uint32_t port, uint32_t db_fifo_id);
void hltests_nic_write_descriptor_to_db_fifo(struct hltests_state *tests_state,
						struct hltests_nic_db_fifo_data *db_fifo,
						struct hltests_nic_db_fifo_packet *db_fifo_packet,
						uint32_t port, bool is_dup);
void hltests_nic_write_desc_to_db_fifo_default(struct hltests_state *tests_state,
					       struct hltests_nic_db_fifo_data *db_fifo,
					       struct hltests_nic_db_fifo_packet *db_fifo_packet,
					       uint32_t port, bool is_dup);
int hltests_nic_user_db_wait_entry_consume(struct hltests_nic_db_fifo_data *db_fifo,
					   uint32_t db_fifo_entry_size,
					   uint32_t pi_granularity, uint32_t extra_guard);
int hltests_nic_submit_user_fifo(struct hltests_nic_test_params *params, uint32_t port,
					struct hltests_nic_db_fifo_packet *user_fifo_packet);

int hltests_nic_config_reduction(int fd, enum hltests_nic_reduction_operation red_op,
					enum hltests_nic_reduction_datatype red_data_type,
					uint64_t *reduction);
int hltests_nic_get_mac_loopback_mask(int fd, uint64_t *mask);

void hltests_nic_build_vxlan_header(struct hltests_nic_vxlan_header *vxlan_hdr);
void hltests_nic_build_gre_header(struct hltests_nic_gre_header *gre_hdr);

int hltests_nic_submit_wtd(struct hltests_nic_test_params *params);
int hltests_nic_submit_db(struct hltests_nic_test_params *params);

/* NIC EQ */
int nic_eq_poll(int fd, struct hltests_nic_eq *eq, struct ibv_context *ibctx);
int nic_eq_poll_stop(struct hltests_nic_eq *eq);

/* NIC common */
int nic_common_generic_set_device_wq_buffers(struct hltests_nic_qp *qp_p);
int nic_common_generic_set_user_wq_buffers(struct hltests_nic_qp *qp_p);
void nic_common_clear_sobs(struct hltests_nic_test_params *params);
void nic_common_config_wqes(struct hltests_nic_qp *qp_p, uint32_t port);
int nic_common_reset_dst_buffers(struct hltests_nic_test_params *params,
				 struct hltests_nic_qp **qps_db, uint32_t coll_qps_count);
void nic_common_generic_config_wqes(struct hltests_nic_test_params *params);
int nic_common_generic_submit_user_fifo_db_qp(struct hltests_nic_qp *qp_p);
int nic_common_generic_submit_user_fifo_db(struct hltests_nic_test_params *params);
int nic_common_data_compare(struct hltests_nic_test_params *params, struct hltests_nic_qp **qps,
			    uint32_t coll_qps_count);
int nic_common_complete(struct hltests_nic_test_params *params);
int nic_common_complete_cq(struct hltests_nic_test_params *params);
int nic_common_lpbk_flow(void **state, enum hltests_nic_test_type test_type);
int nic_common_fill_qp_attr(struct hltests_nic_qp *qp_p);
int nic_common_destroy_qp(struct hltests_nic_qp *qp_p);
int nic_common_set_qp(struct hltests_nic_qp *qp_p, struct hltests_nic_qp **qps_array);
int nic_common_alloc_qp_mem_buffers(struct hltests_nic_test_params *params,
				    struct hltests_nic_qp *qp);
int nic_common_copy_buff_between_host_and_dev(struct hltests_nic_test_params *params,
					      void *host_buff, const struct hltests_memory *mem,
					      size_t mem_offset, uint64_t size,
					      bool is_dev_to_host);
int nic_common_calculate_total_cqes(struct hltests_nic_test_params *params,
				    struct hltests_nic_qp **qps, const size_t *qps_count,
				    size_t qps_count_len, uint32_t *total_req_cqes,
				    uint32_t *total_res_cqes);
int nic_common_migrate_qps(struct hltests_nic_test_params *params);
int nic_common_migration_check_event(struct hltests_nic_test_params *params);
static inline int nic_common_copy_buff_host_to_dev(struct hltests_nic_test_params *params,
						   void *host_buff,
						   const struct hltests_memory *mem,
						   size_t mem_offset, uint64_t size)
{
	return nic_common_copy_buff_between_host_and_dev(params, host_buff, mem, mem_offset, size,
							 false);
}

static inline int nic_common_copy_buff_dev_to_host(struct hltests_nic_test_params *params,
						   const struct hltests_memory *mem,
						   size_t mem_offset, void *host_buff,
						   uint64_t size)
{
	return nic_common_copy_buff_between_host_and_dev(params, host_buff, mem, mem_offset, size,
							 true);
}

int nic_patcher_reserve_coll_qps(struct ibv_pd *ibpd, uint32_t *qp_number, bool is_scale_out,
				 uint64_t coll_ports_mask);
int nic_patcher_allocate_device_data_buffers(const struct hltests_nic_test_params *params,
					     size_t buffers_count, struct hltests_memory *mem,
					     uint64_t *source_offset, uint64_t *destination_offset);
int nic_patcher_create_qps(struct hltests_nic_test_params *params,
			   struct hltests_nic_qp **qps, size_t qps_count,
			   bool is_scale_out, bool reserve_qps);
bool nic_lag_is_port_in_operation(const struct hltests_nic_test_cfg *cfg, size_t lag_port_idx);
enum hltests_nic_coll_qp_type nic_common_get_coll_qp_type(const struct hltests_nic_test_params *p);

/* NIC DNA */
int nic_dna_run(int fd);

/* Test specific */
void nic_afa_set_test_funcs(int fd);
void nic_basic_set_test_funcs(int fd);
void nic_bp_offs_set_test_funcs(int fd);
void nic_collective_set_test_funcs(int fd);

/* Log wrappers */
#if !defined(NDEBUG)
#define hlibv_create_qp(__pd, __qp_init_attr) __hlibv_create_qp_wrapper(__pd, __qp_init_attr)
#define hbldv_modify_qp(__ibqp, __attr, __attr_mask, __hl_attr) \
	__hbldv_modify_qp_wrapper(__ibqp, __attr, __attr_mask, __hl_attr)
#define hbldv_set_port_ex(__context, __attr) __hbldv_set_port_ex(__context, __attr)

struct ibv_qp *__hlibv_create_qp_wrapper(struct ibv_pd *pd, struct ibv_qp_init_attr *qp_init_attr);
int __hbldv_modify_qp_wrapper(struct ibv_qp *ibqp, struct ibv_qp_attr *attr, int attr_mask,
			      struct hbldv_qp_attr *hl_attr);
int __hbldv_set_port_ex(struct ibv_context *context, struct hbldv_port_ex_attr *attr);
#endif /* !defined (NDEBUG) */

void hltests_nic_hexdump(const uint8_t *buf, uint32_t buf_len, const char *fmt, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HLTHUNK_NIC_TESTS_H */
