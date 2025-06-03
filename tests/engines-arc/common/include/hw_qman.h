/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __HW_QMAN_H__
#define __HW_QMAN_H__

#include "arc_types.h"
#include "arc_common_packets.h"
#include "arc_eng_packets.h"

/**
 * \file    hw_qman.h
 * \brief   Data structure for HW QMAN commands
 */

/**
 * \enum    arc_cmd_opcode_t
 * \brief   Various ARC command opcodes
 * \details Command IDs for commands sent to Engine ARC from Scheduler ARC
 */
enum hw_qman_cmd_opcode_t {
	HW_QMAN_CMD_WREG32 = 0x1,
	HW_QMAN_CMD_WREG_BULK = 0x2,
	HW_QMAN_CMD_FENCE = 0x8,
	HW_QMAN_CMD_LIN_DMA = 0x9,
	HW_QMAN_CMD_NOP = 0xA,
	HW_QMAN_CMD_ARB_POINT = 0xC,
	HW_QMAN_CMD = 0x1F,
};

#define EDMA_QM_OFFSET(reg) (0xB000 + (reg & 0xFFF))

struct hw_qman_wreg32_t {
	u32 value;

	u32 pred:4;
	u32 reg:1;
	u32 reserved:3;
	u32 reg_offset:16;
	u32 opcode:5;
	u32 eb:1;
	u32 swtc:1;
	u32 mb:1;
} __attribute__ ((__packed__));

struct hw_qman_wreg_bulk_value_t {
	u32 value_lo;
	u32 value_hi;
} __attribute__ ((__packed__));

struct hw_qman_wreg_bulk_t {
	u32 size64:16;
	u32 reserved:16;

	u32 pred:4;
	u32 reserved1:4;
	u32 reg_offset:16;
	u32 opcode:5;
	u32 eb:1;
	u32 swtc:1;
	u32 mb:1;

	struct hw_qman_wreg_bulk_value_t values64[0];
} __attribute__ ((__packed__));

struct hw_qman_lin_dma_t {
	u32 tsize;
	u32 wrcomp:1;
	u32 endian_swap:2;
	u32 reserved:1;
	u32 memset:1;
	u32 reserved1:1;
	u32 reserved2:1;
	u32 reserved3:1;
	u32 inc_ctxt_id:1;
	u32 reserved4:15;
	u32 opcode:5;
	u32 eb:1;
	u32 swtc:1;
	u32 mb:1;

	u64 src_addr;
	u64 dst_addr;
} __attribute__ ((__packed__));

struct hw_qman_nop_t {
	u32 reserved0;
	u32 reserved1:24;
	u32 opcode:5;
	u32 eng_barrier:1;
	u32 swtc:1;
	u32 msg_barrier:1;
}  __attribute__ ((__packed__));

struct hw_qman_arb_point_t {
	u32 priority :24;
	u32 reserved:7;
	u32 rls :1;
	u32 pred:5;
	u32 reserved1:19;
	u32 opcode:5;
	u32 eng_barrier:1;
	u32 reserved2:1;
	u32 msg_barrier:1;
} __attribute__ ((__packed__));

struct hw_qman_fence_t {
	union {
		struct {
			u32 dec_val:4;
			u32 :12;
			u32 target_val:8;
			u32 :6;
			u32 id:2;
		} __attribute__ ((__packed__));
		u32 raw;
	} cfg;
	struct {
		u32 pred:5;
		u32 :19;
		u32 opcode:5;
		u32 eng_barrier:1;
		u32 swtc:1;
		u32 msg_barrier:1;
	} ctl __attribute__ ((__packed__));
} __attribute__ ((__packed__));

#endif /* __HW_QMAN_H__ */
