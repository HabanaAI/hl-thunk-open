/* SPDX-License-Identifier: MIT
 *
 * Copyright 2017-2018 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef GOYA_PACKETS_H
#define GOYA_PACKETS_H

#include <linux/types.h>

#define PACKET_HEADER_PACKET_ID_SHIFT		56
#define PACKET_HEADER_PACKET_ID_MASK		0x1F00000000000000ull

enum packet_id {
	PACKET_WREG_32 = 0x1,
	PACKET_WREG_BULK = 0x2,
	PACKET_MSG_LONG = 0x3,
	PACKET_MSG_SHORT = 0x4,
	PACKET_CP_DMA = 0x5,
	PACKET_MSG_PROT = 0x7,
	PACKET_FENCE = 0x8,
	PACKET_LIN_DMA = 0x9,
	PACKET_NOP = 0xA,
	PACKET_STOP = 0xB,
	MAX_PACKET_ID = (PACKET_HEADER_PACKET_ID_MASK >>
				PACKET_HEADER_PACKET_ID_SHIFT) + 1
};

enum goya_dma_direction {
	DMA_HOST_TO_DRAM,
	DMA_HOST_TO_SRAM,
	DMA_DRAM_TO_SRAM,
	DMA_SRAM_TO_DRAM,
	DMA_SRAM_TO_HOST,
	DMA_DRAM_TO_HOST,
	DMA_DRAM_TO_DRAM,
	DMA_SRAM_TO_SRAM,
	DMA_ENUM_MAX
};

struct packet_nop {
	__u32 reserved;
	union {
		struct {
			__u32:24;
			__u32 opcode :5;
			__u32 eng_barrier :1;
			__u32 reg_barrier :1;
			__u32 msg_barrier :1;
		};
		__u32 ctl;
	};
};

struct packet_stop {
	__u32 reserved;
	union {
		struct {
			__u32:24;
			__u32 opcode :5;
			__u32 eng_barrier :1;
			__u32 reg_barrier :1; /* must be 0 */
			__u32 msg_barrier :1; /* must be 0 */
		};
		__u32 ctl;
	};
};

struct packet_wreg32 {
	__u32 value;
	union {
		struct {
			__u32 reg_offset :16;
			__u32:7;
			__u32 local :1; /* 0: write to TCL regs,
					 * 1: write to CMDQ regs
					 */
			__u32 opcode :5;
			__u32 eng_barrier :1;
			__u32 reg_barrier :1; /* must be 1 */
			__u32 msg_barrier :1;
		};
		__u32 ctl;
	};
};

struct packet_wreg_bulk {
	__u32 size64 :16;
	__u32:16;
	__u32 reg_offset :16;
	__u32:8;
	__u32 opcode :5;
	__u32 eng_barrier :1;
	__u32 reg_barrier :1; /* must be 1 */
	__u32 msg_barrier :1;
	__u64 values[0]; /* data starts here */
};

struct packet_msg_long {
	__u32 value;
	union {
		struct {
			__u32:16;
			__u32 weakly_ordered :1;
			__u32 no_snoop :1;
			__u32:2;
			__u32 op :2; /* 0: write <value>. 1: write timestamp. */
			__u32:2;
			__u32 opcode :5;
			__u32 eng_barrier :1;
			__u32 reg_barrier :1;
			__u32 msg_barrier :1;
		};
		__u32 ctl;
	};
	__u64 addr;
};

struct packet_msg_short {
	union {
		struct {
			__u32 sync_id :10;
			__u32:5;
			__u32 mode : 1;
			__u32 sync_value :16;
		} mon_arm_register;
		struct {
			__u32 sync_value :16;
			__u32:15;
			__u32 mode :1;
		} so_upd;
		__u32 value;
	};
	union {
		struct {
			__u32 msg_addr_offset :16;
			__u32 weakly_ordered :1;
			__u32 no_snoop :1;
			__u32:2;
			__u32 op :2;
			__u32 base :2;
			__u32 opcode :5;
			__u32 eng_barrier :1;
			__u32 reg_barrier :1;
			__u32 msg_barrier :1;
		};
		__u32 ctl;
	};
};

struct packet_msg_prot {
	__u32 value;
	union {
		struct {
			__u32:16;
			__u32 weakly_ordered :1;
			__u32 no_snoop :1;
			__u32:2;
			__u32 op :2; /* 0: write <value>. 1: write timestamp. */
			__u32:2;
			__u32 opcode :5;
			__u32 eng_barrier :1;
			__u32 reg_barrier :1;
			__u32 msg_barrier :1;
		};
		__u32 ctl;
	};
	__u64 addr;
};

struct packet_fence {
	__u32 dec_val :4;
	__u32:12;
	__u32 gate_val :8;
	__u32:6;
	__u32 id :2;
	__u32:24;
	__u32 opcode :5;
	__u32 eng_barrier :1;
	__u32 reg_barrier :1;
	__u32 msg_barrier :1;
};

struct packet_lin_dma {
	__u32 tsize;
	union {
		struct {
			__u32 weakly_ordered :1; /* H/W bug, must be 1 */
			__u32 rdcomp :1;
			__u32 wrcomp :1;
			__u32 no_snoop :1;
			__u32 src_disable :1;
			__u32 dst_disable :1;
			__u32 memset_mode :1;
			__u32 tensor_dma :1; /* N/A, must be 0 */
			__u32 cntrl :12;
			__u32 dma_dir :3; /* S/W only, no effect on HW */
			__u32:1;
			__u32 opcode :5;
			__u32 eng_barrier :1;
			__u32 reg_barrier :1; /* must be 1 */
			__u32 msg_barrier :1;
		};
		__u32 ctl;
	};
	__u64 src_addr;
	__u64 dst_addr;
};

struct packet_cp_dma {
	__u32 tsize;
	union {
		struct {
			__u32 weakly_ordered :1;
			__u32 no_snoop :1;
			__u32:22;
			__u32 opcode :5;
			__u32 eng_barrier :1;
			__u32 reg_barrier :1; /* must be 1 */
			__u32 msg_barrier :1;
		};
		__u32 ctl;
	};
	__u64 src_addr;
};

#endif /* GOYA_PACKETS_H */
