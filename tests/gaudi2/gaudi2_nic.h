/* SPDX-License-Identifier: MIT
 *
 * Copyright 2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef GAUDI2_NIC_H
#define GAUDI2_NIC_H

#include "hlthunk_nic_tests.h"
#include "gaudi2/gaudi2.h"
#include "gaudi2/asic_reg/gaudi2_regs.h"
#include "gaudi2/gaudi2_packets.h"
#include "ini.h"
#include <stdint.h>

#define GAUDI2_NIC_PORTS_MASK	0xFFFFFF

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
#define NIC_MAX_CONN_ID		((1 << 13) - 1) /* 8K QPs */

#define NIC_NUMBER_OF_PORTS	NIC_NUMBER_OF_ENGINES
#define WQ_BUFFER_LOG_SIZE	16
#define WQ_BUFFER_SIZE		(1 << WQ_BUFFER_LOG_SIZE)
#define NUM_OF_WQES		(1 << WQ_BUFFER_LOG_SIZE)
#define DATA_BUFFER_SIZE	128
#define RAW_QPN			1
#define SCHEDQ			8
#define SCHEDQ_FREE_SIZE	256
#define TMR_GRANULARITY		32
#define TMR_FREE_SIZE		256
#define BURST_SIZE		128

#define BASE_SOB_ADDR		(CFG_BASE + \
				mmDCORE0_SYNC_MNGR_OBJS_SOB_OBJ_0)
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
#define LOCAL_BASE_ADDR		0x20000000
#define REMOTE_BASE_ADDR	0x30000000

#define NIC_MACRO_CFG_SIZE	(mmNIC1_QM0_GLBL_CFG0 - mmNIC0_QM0_GLBL_CFG0)
//#define ALIGN_UP(addr, size)	((addr + size) & ~(size - 1))

#define REDUCTION_INDICATION_MSK   0x01
#define REDUCTION_DATA_TYPE_MSK    0x0F
#define REDUCTION_OPERATION_MSK    0x03
#define REDUCTION_ROUNDING_MSK     0x03

#define REDUCTION_INDICATION_SHIFT  0
#define REDUCTION_DATA_TYPE_SHIFT   1
#define REDUCTION_OPERATION_SHIFT   5
#define REDUCTION_ROUNDING_SHIFT    7

enum gaudi2_red_datatype {
	GAUDI2_NIC_REDUCTION_INT8           = 0x0,
	GAUDI2_NIC_REDUCTION_INT16          = 0x1,
	GAUDI2_NIC_REDUCTION_INT32          = 0x2,
	GAUDI2_NIC_REDUCTION_UINT8          = 0x3,
	GAUDI2_NIC_REDUCTION_UINT16         = 0x4,
	GAUDI2_NIC_REDUCTION_UINT32         = 0x5,
	GAUDI2_NIC_REDUCTION_BF16           = 0x6,
	GAUDI2_NIC_REDUCTION_FP32           = 0x7,
	GAUDI2_NIC_REDUCTION_FP16           = 0x8,
	GAUDI2_NIC_REDUCTION_UPSCALING_FP16 = 0xC,
	GAUDI2_NIC_REDUCTION_UPSCALING_BF16 = 0xD,
	GAUDI2_NIC_REDUCTION_DT_INVALID     = 0xFF
};

enum gaudi2_red_op {
	GAUDI2_NIC_REDUCTION_OP_ADDITION     = 0x0,
	GAUDI2_NIC_REDUCTION_OP_SUBSTRACTION = 0x1,
	GAUDI2_NIC_REDUCTION_OP_MINIMUM      = 0x2,
	GAUDI2_NIC_REDUCTION_OP_MAXIMUM      = 0x3,
	GAUDI2_NIC_REDUCTION_OP_INVALID      = 0xFF
};

#define GAUDI2_DB_FIFO_ENTRY_SIZE	8
#define GAUDI2_NUM_MAX_BP_OFFS		2

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
	WQE_WR_RDV = 5,
	WQE_RD_RDV = 6,
	WQE_QOS_UPDATE = 7
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
	uint64_t opcode:5;
	uint64_t trace_event_data:1;
	uint64_t trace_event:1;
	uint64_t reserved7:1;
	uint64_t wqe_index:8;
	uint64_t reduction_opcode:13;
	uint64_t se:1;
	uint64_t in_line:1;
	uint64_t ackreq:1;
	uint64_t size:32;
	uint64_t local_address_31_0:32;
	uint64_t local_address_63_32:32;
	uint64_t remote_address_31_0:32;
	uint64_t remote_address_63_32:32;
	uint64_t tag:32;
	uint64_t remote_sync_object:27;
	uint64_t remote_sync_object_data:2;
	uint64_t sob_command:1;
	uint64_t completion_type:2;
} __attribute__((packed));

struct rq_wqe {
	uint64_t opcode:5;
	uint64_t reserved_5_7:3;
	uint64_t wqe_index:8;
	uint64_t reserved_16_30:15;
	uint64_t sob_command:1;
	uint64_t local_sync_object:27;
	uint64_t local_sync_object_data:3;
	uint64_t completion_type:2;
	uint64_t size:32;
	uint64_t tag:32;
} __attribute__((packed));

struct wtd_static {
	uint64_t rcv_opcode:5;
	uint64_t reserved_5_7:3;
	uint64_t rcv_wqe_index:8;
	uint64_t reserved_16_27:12;
	uint64_t pt:2;
	uint64_t reserved_30:1;
	uint64_t rcv_sob_command:1;
	uint64_t rcv_sync_object_addr:27;
	uint64_t rcv_sync_object_data:3;
	uint64_t rcv_completion_type:2;
	uint64_t rcv_tag:32;
	uint64_t send_opcode:5;
	uint64_t trace_event_data:1;
	uint64_t trace_event:1;
	uint64_t reserved_103:1;
	uint64_t send_wqe_index:8;
	uint64_t reduction_opcode:10;
	uint64_t reserved_122_124:3;
	uint64_t se:1;
	uint64_t in_line:1;
	uint64_t ackreq:1;
	uint64_t local_address_31_0:32;
	uint64_t local_address_63_32:32;
	uint64_t remote_address_31_0:32;
	uint64_t remote_address_63_32:32;
	uint64_t send_tag:32;
	uint64_t remote_completion_addr:27;
	uint64_t send_sync_object_data:2;
	uint64_t send_sob_command:1;
	uint64_t send_completion_type:2;
} __attribute__((packed));

struct wtd_dynamic {
	uint64_t rcv_size:32;
	uint64_t send_size:32;
	uint64_t local_offset_31_0:32;
	uint64_t local_offset_63_32:32;
	uint64_t remote_offset_31_0:32;
	uint64_t remote_offset_63_32:32;
	uint64_t qp_number:24;
	uint64_t reserved_216_255:40;
} __attribute__((packed));

#endif /* GAUDI2_NIC_H */
