/* SPDX-License-Identifier: MIT
 *
 * Copyright 2021 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef GAUDI3_NIC_H
#define GAUDI3_NIC_H

#include "hlthunk_nic_tests.h"
#include "gaudi3/gaudi3.h"
#include "gaudi3/asic_reg/gaudi3_regs.h"
#include "hw_ip/nic/nic_v1_1.h"
#include "ini.h"
#include "nic_patcher_cmds.h"
#include <stdint.h>

/* workaround checkpatch warnings over this pragma */
#ifndef __packed
#define ATTRIB(NAME)	__attribute__((__ ## NAME ## __))
#define __packed	ATTRIB(packed)
#endif

#define NIC_NUMBER_OF_PORTS	NIC_NUMBER_OF_ENGINES

#define NIC_MIN_CONN_ID		1
#define NIC_MAX_CONN_ID		((1 << 15) - 1) /* 32K QPs */

#define NUM_OF_SYNC_MNGR_OBJS	NUM_OF_HDCORES_PER_DIE	/* work with a single die for now */
#define NUM_OF_SOBJS_PER_SM	(((mmSOB_OBJS_SOB_OBJ_0_8191 - \
					mmSOB_OBJS_SOB_OBJ_0_0) + 1) * 2)
#define NUM_OF_SOBJS		(NUM_OF_SOBJS_PER_SM * NUM_OF_SYNC_MNGR_OBJS)

#define REDUCTION_ENABLE_MSK       0x01
#define REDUCTION_OPERATION_MSK    0x07
#define REDUCTION_ROUNDING_MSK     0x03
#define REDUCTION_DATA_TYPE_MSK    0x0F
#define REDUCTION_DOWN_CONV_MSK    0x03

#define REDUCTION_ENABLE_SHIFT      0
#define REDUCTION_OPERATION_SHIFT   1
#define REDUCTION_ROUNDING_SHIFT    4
#define REDUCTION_DATA_TYPE_SHIFT   6
#define REDUCTION_DOWN_CONV_SHIFT   10

/* Update Enable descriptor */
#define COLL_DESC_ENT_NICS_PER_ENTRY_M	0xFFFFFF

enum gaudi3_red_datatype {
	GAUDI3_NIC_REDUCTION_INT8           = 0x0,
	GAUDI3_NIC_REDUCTION_INT16          = 0x1,
	GAUDI3_NIC_REDUCTION_INT32          = 0x2,
	GAUDI3_NIC_REDUCTION_UINT8          = 0x3,
	GAUDI3_NIC_REDUCTION_UINT16         = 0x4,
	GAUDI3_NIC_REDUCTION_UINT32         = 0x5,
	GAUDI3_NIC_REDUCTION_BF16           = 0x6,
	GAUDI3_NIC_REDUCTION_FP32           = 0x7,
	GAUDI3_NIC_REDUCTION_FP16           = 0x8,
	GAUDI3_NIC_REDUCTION_UPSCALING_FP16 = 0xC,
	GAUDI3_NIC_REDUCTION_UPSCALING_BF16 = 0xD,
	GAUDI3_NIC_REDUCTION_DT_INVALID     = 0xFF
};

enum gaudi3_red_op {
	GAUDI3_NIC_REDUCTION_OP_ADDITION     = 0x0,
	GAUDI3_NIC_REDUCTION_OP_SUBTRACTION  = 0x1,
	GAUDI3_NIC_REDUCTION_OP_MINIMUM      = 0x2,
	GAUDI3_NIC_REDUCTION_OP_MAXIMUM      = 0x3,
	GAUDI3_NIC_REDUCTION_OP_INVALID      = 0xFF
};

enum gaudi3_downscale_dt {
	GAUDI3_NIC_REDUCTION_DS_NONE       = 0x0,
	GAUDI3_NIC_REDUCTION_DS_TO_FP16    = 0x2,
	GAUDI3_NIC_REDUCTION_DS_TO_BF16    = 0x3,
	GAUDI3_NIC_REDUCTION_DS_INVALID    = 0xFF
};

#define GAUDI3_DB_FIFO_ENTRY_SIZE	4
#define GAUDI3_NUM_MAX_BP_OFFS		16

enum wqe_opcode {
	WQE_NOP = 0,		/* TODO: verify NOP is supported */
	WQE_SEND = 1,
	WQE_LINEAR = 2,
	WQE_STRIDE = 3,
	WQE_MULTI_STRIDE = 4,
	WQE_RENDEZVOUS_WRITE = 5,
	WQE_RENDEZVOUS_READ = 6,
	WQE_ATOMIC_FETCH_ADD = 7,
	WQE_MULTI_STRIDE_DUAL = 8,
	WQE_ATOMIC_FETCH_AND_ADD_WRITE = 9,
	WQE_ATOMIC_FETCH_AND_ADD_READ = 0xa,
	WQE_FIFO_ALLOCATION = 0xb,
	WQE_FIFO_PUSH = 0xc,
};

struct sq_wqe {
	uint64_t opcode:5;
	uint64_t local_class:2;
	uint64_t sob_ctl:1;
	uint64_t local_mcid:7;
	uint64_t local_alloch:1;
	uint64_t reduction_opcode:12;
	uint64_t rc:1;
	uint64_t se_or_compress:1;
	uint64_t in_line:1;
	uint64_t ackreq:1;
	uint64_t size:32;
	uint64_t local_address_31_0:32;
	uint64_t local_address_63_32:32;
	uint64_t remote_address_31_0:32;
	uint64_t remote_address_63_32:32;
	uint64_t tag:32;
	uint64_t remote_sob_id:13;
	uint64_t remote_sub_sm:1;
	uint64_t remote_sm_id:3;
	uint64_t remote_mcid:7;
	uint64_t remote_alloch:1;
	uint64_t remote_class:2;
	uint64_t long_sync_object:1;
	uint64_t sob_command:2;
	uint64_t completion_type:2;
} __attribute__((packed));

struct sq_rdv_read_wqe {
	uint64_t opcode:5;
	uint64_t remote_pi_0_10:11;
	uint64_t reduction_opcode:12;
	uint64_t rc:1;
	uint64_t se_or_compress:1;
	uint64_t in_line:1;
	uint64_t ackreq:1;
	uint64_t size:32;
	uint64_t local_address_31_0:32;
	uint64_t local_address_63_32:32;
	uint64_t remote_address_31_0:32;
	uint64_t remote_address_63_32:32;
	uint64_t tag:32;
	uint64_t remote_sob_id:13;
	uint64_t remote_sub_sm:1;
	uint64_t remote_sm_id:3;
	uint64_t remote_pi_11_21:11;
	uint64_t sob_command:2;
	uint64_t completion_type:2;
} __attribute__((packed));

struct rq_wqe {
	uint64_t opcode:5;
	uint64_t reserved_5_7:3;
	uint64_t wqe_index:8;
	uint64_t reserved_16_31:16;
	uint64_t local_sob_id:13;
	uint64_t local_sub_sm:1;
	uint64_t local_sm_id:3;
	uint64_t reserved_17_24:8;
	uint32_t sob_fifo:2;
	uint64_t long_sync_object:1;
	uint64_t sob_command:2;
	uint64_t completion_type:2;
	uint64_t size:32;
	uint64_t tag:32;
} __attribute__((packed));

struct wtd_static {
	struct rq_wqe rwqe;
	struct sq_wqe swqe;
	uint32_t qpn;
} __attribute__((packed));

struct coll_desc {
	union {
		struct coll_desc_send_receive send_receive;
		struct coll_desc_ms_send_receive ms_send_receive;
		struct coll_desc_v_operation_send_receive v_operation;
		struct coll_desc_write write;
		struct direct_coll_desc_write direct_write;
		struct direct_coll_desc_send_receive direct_sr;
		struct direct_coll_desc_v_operation_send_receive direct_v_op;
		struct direct_coll_desc_ms_send_receive direct_ms_send_receive;
	};
} __packed;

#endif /* GAUDI3_NIC_H */
