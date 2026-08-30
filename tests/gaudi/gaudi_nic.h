/* SPDX-License-Identifier: MIT
 *
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef GAUDI_NIC_H
#define GAUDI_NIC_H

#include "hlthunk_nic_tests.h"
#include "gaudi/gaudi.h"
#include "gaudi/asic_reg/gaudi_regs.h"
#include "gaudi/gaudi_packets.h"
#include "ini.h"
#include <stdint.h>

#define GAUDI_NICS_MASK		0x3FF

#define NIC0_MAC_ADDRESS	0x102030400ull
#define NIC1_MAC_ADDRESS	0x102030401ull
#define NIC2_MAC_ADDRESS	0x102030402ull
#define NIC3_MAC_ADDRESS	0x102030403ull
#define NIC4_MAC_ADDRESS	0x102030404ull
#define NIC5_MAC_ADDRESS	0x102030405ull
#define NIC6_MAC_ADDRESS	0x102030406ull
#define NIC7_MAC_ADDRESS	0x102030407ull
#define NIC8_MAC_ADDRESS	0x102030408ull
#define NIC9_MAC_ADDRESS	0xBADBABA9ull

#define NIC_MIN_CONN_ID		1
#define NIC_MAX_CONN_ID		((1 << 10) - 1) /* 1K QPs */

#define NIC_NUMBER_OF_PORTS	NIC_NUMBER_OF_ENGINES
#define WQ_BUFFER_LOG_SIZE	16
#define WQ_BUFFER_SIZE		(1 << WQ_BUFFER_LOG_SIZE)
#define NUM_OF_WQES		(1ULL << WQ_BUFFER_LOG_SIZE)
#define DATA_BUFFER_SIZE	128
#define RAW_QPN			1
#define SCHEDQ			8
#define SCHEDQ_FREE_SIZE	256
#define TMR_GRANULARITY		32
#define TMR_FREE_SIZE		256
#define BURST_SIZE		16

#define BASE_SOB_ADDR		(CFG_BASE + \
				mmSYNC_MNGR_E_N_SYNC_MNGR_OBJS_SOB_OBJ_0)
#define LOCAL_SOB_ADDR		(BASE_SOB_ADDR + LOCAL_SOB_ID * 4)
#define REMOTE_SOB_ADDR		(BASE_SOB_ADDR + REMOTE_SOB_ID * 4)

#define NIC_MEM_SIZE		0x40000000ull /* 1GB */
#define REQ_QPC_BASE_ADDR	0x1000000
#define RES_QPC_BASE_ADDR	0x5000000
#define SWQ_BASE_ADDR		0x7000000
#define RWQ_BASE_ADDR		0xB000000
#define TMR_FSM_BASE_ADDR	0xD000000
#define TMR_BASE_ADDR		0xD800000
#define TMR_FREE_BASE_ADDR	0xE000000
#define DMA_FENCE0		0xF000000
#define SOB_DATA_ADDR		0x11000000
#define RAW_BASE_P0		0x12000000ull
#define RAW_BASE_P1		0x14000000ull
#define RAW_BASE_P2		0x16000000ull
#define RAW_BASE_P3		0x18000000ull
#define SQ_BASE_ADDR		0x1A000000
#define SQ_FREE_BASE_ADDR	0x1B000000
#define LOCAL_BASE_ADDR		0x0
#define REMOTE_BASE_ADDR	(NIC_MEM_SIZE >> 1)

#define NIC_MACRO_CFG_SIZE	(mmNIC1_QM0_GLBL_CFG0 - mmNIC0_QM0_GLBL_CFG0)

enum ts_type {
	TS_RC = 0,
	TS_RAW = 1
};

enum connection_state {
	CS_OPEN = 0,
	CS_CLOSE = 1,
	CS_RESYNC = 2,
	CS_ERROR = 3
};

enum cc_type {
	CC_DISABLE = 0,
	CC_HW_ENABLED = 1,
	CC_SW_ENABLED = 2,
	CC_RESERVED = 3
};

enum cc_state {
	CC_IDLE = 0,
	CC_ARM = 1,
	CC_TRIGGRED = 2
};

enum trust_level {
	UNSECURED = 0,
	SECURED = 1,
	PRIVILEGE = 2
};

enum wqe_opcode {
	WQE_NOP = 0,
	WQE_SEND = 1,
	WQE_LINEAR = 2,
	WQE_STRIDE = 3,
	WQE_MULTI_STRIDE = 4,
	WQE_RATE_UPDATE = 5
};

/* Configuration file structures */
struct pfc_recv_cfg {
	uint32_t port;
	uint32_t dst_macs_num;
	uint8_t dst_macs[MAX_NIC_NUMBER_OF_PORTS][ETH_ALEN];
	uint8_t wait_for_cleanup;
};

struct pfc_send_cfg {
	uint32_t ports[MAX_NIC_NUMBER_OF_PORTS];
	uint32_t ports_num;
	uint8_t dst_mac[ETH_ALEN];
	uint8_t use_cq;
	uint8_t wq_on_hbm;
	uint8_t wait_for_cleanup;
};

struct bw_cfg {
	uint32_t ports[MAX_NIC_NUMBER_OF_PORTS];
	uint32_t ports_num;
	uint32_t dst_macs_num;
	uint8_t dst_macs[MAX_NIC_NUMBER_OF_PORTS][ETH_ALEN];
};

struct lat_cfg {
	uint32_t ports[MAX_NIC_NUMBER_OF_PORTS];
	uint32_t ports_num;
	uint32_t dst_macs_num;
	uint8_t  dst_macs[MAX_NIC_NUMBER_OF_PORTS][ETH_ALEN];
	uint8_t  wq_on_sram;  /* no => on host-memory, yes => on SRAM */
	enum hltests_nic_data_loc data_loc; /* as per enum defined in gaudi_nic.h */
	uint32_t iterations;
	uint32_t max_sz;
};

struct qpc_requester {
	uint32_t destination_qp:24;
	uint32_t port:4;
	uint32_t prio:2;
	enum cc_type congestion_en:2;
	uint32_t remote_key:32;
	uint32_t destination_ip:32;
	uint32_t source_ip:32;
	uint32_t destination_mac_31_0:32;
	uint32_t destination_mac_47_32:16;
	uint32_t sequence_error_retry_count:8;
	uint32_t timeout_rertry_count:8;
	uint32_t next_to_send_psn:24;
	uint32_t sq_number: 8;
	uint32_t oldest_unacked_psn:24;
	uint32_t timer_granularity:7;
	uint32_t sob_en:1;
	uint32_t congestion_marked_ack:22;
	uint32_t congestion_non_marked_ack:22;
	uint32_t congestion_window:22;
	uint32_t rtt_timestamp:25;
	uint32_t rtt_marked_psn:22;
	enum ts_type transport_service:1;
	uint32_t burst_size:22;
	uint32_t last_index:22;
	uint32_t execution_index:22;
	uint32_t consumer_index:22;
	uint32_t producer_index:22;
	uint32_t wq_base_address:24;
	enum cc_state rtt_state: 2;
	uint32_t swq_granularity:1;
	enum trust_level trusted:2;
	uint32_t in_work:1;
	uint32_t error:1;
	uint32_t valid:1;
} __attribute__((packed));

struct qpc_responder {
	uint32_t destination_qp:24;
	uint32_t port:4;
	uint32_t prio:2;
	enum connection_state connection_state:2;
	uint32_t local_key:32;
	uint32_t destination_ip:32;
	uint32_t source_ip:32;
	uint32_t destination_mac_31_0:32;
	uint32_t destination_mac_47_32:16;
	uint32_t sq_number:8;
	uint32_t ecn_count:5;
	uint32_t nack_syndrom:2;
	enum ts_type transport_service:1;
	uint32_t expected_psn:24;
	uint32_t log_buffer_size_mask:5;
	uint32_t cyclic_index:30;
	uint32_t sob_en:1;
	enum trust_level trusted:2;
	uint32_t in_work:1;
	uint32_t valid:1;
} __attribute__((packed));

struct sq_wqe {
	uint32_t number_of_strides:16;
	uint32_t reduction_opcode:9;
	uint32_t reserved0:1;
	uint32_t stride_type:1;
	uint32_t ackreq:1;
	enum wqe_opcode opcode:4;
	uint32_t local_address_31_0:32;
	uint32_t local_address_49_32:18;
	uint32_t size:14;
	uint32_t remote_address_31_0:32;
	uint32_t remote_address_43_32:18;
	uint32_t stride_size:14;
	uint32_t remote_sync_object:26;
	uint32_t reserved1:5;
	uint32_t sync_object_valid:1;
	uint32_t remote_sync_object_data:32;
	uint32_t stride:32;
} __attribute__((packed));

struct rq_wqe {
	uint32_t local_sync_object_data:32;
	uint32_t local_sync_object_address:26;
	uint32_t reserved:4;
	uint32_t cq_valid:1;
	uint32_t valid:1;
} __attribute__((packed));

#endif /* GAUDI_NIC_H */
