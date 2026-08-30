/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#ifndef __GAUDI2_ARC_ENG_PACKETS_H__
#define __GAUDI2_ARC_ENG_PACKETS_H__

#include <stdint.h>

/**
 * \enum    eng_arc_cmd_t
 * \brief   Various engine commands
 * \details Command type enum specifies the commands that are processed by
 *	    compute engines ARCs.
 */
enum eng_arc_cmd_t {
	ECB_CMD_LIST_SIZE = 0,
	ECB_CMD_NOP = 1,
	ECB_CMD_STATIC_DESC = 2,
	ECB_CMD_WD_FENCE_AND_EXE = 3,
	ECB_CMD_SCHED_DMA = 4,
	ECB_CMD_ARM_MON = 5,
	ECB_CMD_COUNT = 6
};

/**
 * Total count of Work distribution context supported
 */
#define WD_CTXT_COUNT	8

#define MAX_DIMENSIONS	5

#define TENSOR_DIM0	0
#define TENSOR_DIM1	1
#define TENSOR_DIM2	2
#define TENSOR_DIM3	3
#define TENSOR_DIM4	4

/**
 * DCCM buffer size for doing the DMA transfers
 * All the ECB commands should be within these boundaries
 */
#define STATIC_COMPUTE_ECB_LIST_BUFF_SIZE			256
#define DYNAMIC_COMPUTE_ECB_LIST_BUFF_SIZE			256

/**
 * \struct  virtual_sob_t
 * \brief   virtual sob identifier
 * \details data structure to store sob offset and threshold
 *	    information per engine type
 */
struct virtual_sob_t {
	uint16_t sob_offset;
	/**<
	 * sob offset to use in culculating the sob id
	 * sob offset is with respect to so set base
	 */
	uint16_t threshold;
	/**<
	 * threshold to be used in arming monitor
	 */
} __attribute__ ((aligned(4), __packed__));

/**<
 * Virtual SOB index count
 */
#define VIRTUAL_SOB_INDEX_COUNT			7

/**<
 * Virtual SOB index used in virtual SOB array
 */
#define VIRTUAL_SOB_INDEX_TPC			0
#define VIRTUAL_SOB_INDEX_MME			1
#define VIRTUAL_SOB_INDEX_EDMA			2
#define VIRTUAL_SOB_INDEX_ROT			3
#define VIRTUAL_SOB_INDEX_DEBUG			4
#define VIRTUAL_SOB_INDEX_CTRL_EDGES		5
#define VIRTUAL_SOB_INDEX_TPC_OVERLAP		6

/**
 * \struct  rot_wd_ctxt_t
 * \brief   Rotator specific work distribution context
 * \details Rotator work distribution context for GC
 */
struct rot_wd_ctxt_t {
	uint32_t rot_commit_reg;
	/**<
	 * rotator commit register parameters
	 */
	uint8_t sob_offset:6;
	/**<
	 * SOB offset to be used for signaling the completion
	 * valid only when we move to new sync scheme
	 */
	uint8_t switch_bit:1;
	/**<
	 * value of the switch bit to be configured when pushing the
	 * descriptor into ARC CQ
	 */
	uint32_t reserved:25;
	/**<
	 * reserved
	 */
} __attribute__ ((aligned(4), __packed__));

/**
 * \struct  rot_wd_ctxts_t
 * \brief   Rotator engine and sync scheme context
 * \details Rotator engine context and sync scheme context used for GC
 */
struct rot_wd_ctxts_t {
	struct rot_wd_ctxt_t rot_ctxt[WD_CTXT_COUNT];
	/**<
	 * array of contexts for Rotator
	 */

	/*
	 * TODO: Add global parameters here
	 * Global means used in all the contexts
	 */
} __attribute__ ((aligned(4), __packed__));

/**
 * \struct  mme_wd_ctxt_t
 * \brief   MME specific work distribution context
 * \details MME work distribution context for GC
 */
struct mme_wd_ctxt_t {
	uint32_t mme_commit_reg;
	/**<
	 * mme commit register parameters
	 */
	uint32_t sob_offset:6;
	/**<
	 * SOB offset to be used for signaling the completion
	 * valid only when we move to new sync scheme
	 */
	uint32_t switch_bit:1;
	/**<
	 * value of the switch bit to be configured when pushing the
	 * descriptor into ARC CQ
	 */
	uint32_t reserved:17;
	/**<
	 * reserved
	 */
	uint32_t virtual_sob_bitmap:8;
	/**<
	 * Virtual SOB bitmap indicating index which are valid
	 * in the virtual_sob array
	 */
	struct virtual_sob_t virtual_sob[VIRTUAL_SOB_INDEX_COUNT];
	/**<
	 * Virtual SOB array
	 */
} __attribute__ ((aligned(4), __packed__));

/**
 * \struct  mme_wd_ctxts_t
 * \brief   MME engine and sync scheme context
 * \details MME engine context and sync scheme context used for GC
 */
struct mme_wd_ctxts_t {
	struct mme_wd_ctxt_t mme_ctxt[WD_CTXT_COUNT];
	/**<
	 * array of contexts for MME
	 */

	/*
	 * TODO: Add global parameters here
	 * Global means used in all the contexts
	 */
} __attribute__ ((aligned(4), __packed__));

/**
 * \enum    edma_op_type_t
 * \brief   Various EDMA operations
 * \details EDMA enums supported by Firmware
 */
enum edma_op_type_t {
	EDMA_OP_MEMSET = 0,
	EDMA_OP_MEMCPY_LINEAR = 1,
	EDMA_OP_MEMCPY_TENSOR = 2,
	EDMA_OP_TRANSPOSE = 3
};

/**
 * \struct  edma_tensor_t
 * \brief   EDMA tensor data structure
 * \details Data structure to store EDMA tensor related parameters
 */
struct edma_tensor_t {
	uint32_t base_cord[MAX_DIMENSIONS];
	/**<
	 * Base cordinates of the tensor
	 * DIM0 is in Bytes, rest all in elements
	 */
	uint32_t curr_cord[MAX_DIMENSIONS];
	/**<
	 * current cordinates of the tensor
	 * DIM0 is in Bytes, rest all in elements
	 */
	uint32_t grid_size[MAX_DIMENSIONS];
	/**<
	 * Size of the complete tensor
	 * DIM0 is in Bytes, rest all in elements
	 */
	uint32_t box_size[MAX_DIMENSIONS];
	/**<
	 * Chunk size of the tensor
	 * DIM0 is in Bytes, rest all in elements
	 * Note: Using box size field, firmware programs the tsize registers
	 * of source and destination tensors
	 */
	uint32_t grid_stride[MAX_DIMENSIONS];
	/**<
	 * Stride of the Tensor dimentions
	 * DIM0 - Not used by FW, set it to 0
	 * rest of the DIMs are in elements
	 * Note: Stride registers are not programmed by Firmware. Its expected
	 * to be programmed by GC using static ecb desc command.
	 */
	uint64_t addr_offset;
	/**<
	 * address offset of the main tensor,
	 * for the individual boxes the offsets would
	 * calculated by FW using this field
	 * Note: Firmware programs SRC and DST offset registers by using this
	 * field along with other parameters specified in this structure
	 */
} __attribute__ ((aligned(4), __packed__));

/**
 * \struct  edma_wd_ctxt_t
 * \brief   EDMA specific work distribution context
 * \details EDMA work distribution context for GC
 */
struct edma_wd_ctxt_t {
	uint32_t dma_commit_reg;
	/**<
	 * dma commit register value to be written
	 */
	uint32_t dma_op:2;
	/**<
	 * DMA operation to be performed from edma_op_type_t
	 */
	uint32_t sob_offset:6;
	/**<
	 * TODO: Remove this field, and start using virtual_sob array
	 * For now kept to avoid compilation issues
	 */
	uint32_t switch_bit:1;
	/**<
	 * value of the switch bit to be configured when pushing the
	 * descriptor into ARC CQ
	 */
	uint32_t shuffle_index:3;
	/**<
	 * Index of the 1st engine to start with, 3 bits
	 * Linear number starting from 0 to (num_engines - 1)
	 */
	uint32_t reserved:12;
	/**<
	 * reserved
	 */
	uint32_t virtual_sob_bitmap:8;
	/**<
	 * Virtual SOB bitmap indicating index which are valid
	 * in the virtual_sob array
	 */
	struct virtual_sob_t virtual_sob[VIRTUAL_SOB_INDEX_COUNT];
	/**<
	 * Virtual SOB array
	 */
	struct edma_tensor_t dst_tensor;
	/**<
	 * Destination tensor configuration
	 */
	struct edma_tensor_t src_tensor;
	/**<
	 * Source tensor configuration
	 */
} __attribute__ ((aligned(4), __packed__));

/**
 * \struct  edma_wd_ctxts_t
 * \brief   EDMA engine and sync scheme context
 * \details EDMA engine context and sync scheme context used for GC
 */
struct edma_wd_ctxts_t {
	struct edma_wd_ctxt_t edma_ctxt[WD_CTXT_COUNT];
	/**<
	 * array of contexts for EDMA
	 */

	/*
	 * TODO: Add global parameters here
	 * Global means used in all the contexts
	 */
} __attribute__ ((aligned(4), __packed__));

/**
 * \struct  index_space_tensor_t
 * \brief   Data structure which defines index space tensor
 * \details Index space tensor parameters stored within GC Context
 */
struct index_space_tensor_t {
	uint32_t base_cord[MAX_DIMENSIONS];
	/**<
	 * Base coordinate of the grid
	 */
	uint32_t grid_size[MAX_DIMENSIONS];
	/**<
	 * Actual or Total Size of the index space tensor
	 */
	uint32_t box_size[MAX_DIMENSIONS];
	/**<
	 * Index space tensor is divided into small boxes
	 * Each box is processed by a particular TPC.
	 * Box size is nothing bug amount of work
	 * that is processed by a TPC.
	 */
	uint32_t curr_cord[MAX_DIMENSIONS];
	/**<
	 * Current cord within Index space tensor
	 */
} __attribute__ ((aligned(4), __packed__));

/**
 * \struct  tpc_wd_ctxt_t
 * \brief   TPC specific work distribution context
 * \details TPC specific work distribution context for GC
 */
struct tpc_wd_ctxt_t {
	struct index_space_tensor_t ist;
	/**<
	 * Index space tensor parameters
	 */
	uint8_t dim_order[MAX_DIMENSIONS];
	/**<
	 * Traversal order of the dimensions
	 * value of MAX_DIMENSIONS or more means invalid dimension and
	 * stop processing
	 */
	uint8_t shuffle_index;
	/**<
	 * Index of the 1st engine to start with, 5 bits
	 * Linear number starting from 0 to (num_engines - 1)
	 */
	uint8_t sob_offset:6;
	/**<
	 * TODO: Mark this reserved, only kept to have a clean
	 * build. Once spec changes are merged, make it reserved
	 */
	uint8_t switch_bit:1;
	/**<
	 * value of the switch bit to be configured when pushing the
	 * descriptor into ARC CQ
	 */
	uint8_t use_gc_nop_kernel:1;
	/**<
	 * use NOP kernel address provided by ECB list command
	 */
	uint8_t virtual_sob_bitmap;
	/**<
	 * Virtual SOB bitmap indicating index which are valid
	 * in the virtual_sob array
	 */
	struct virtual_sob_t virtual_sob[VIRTUAL_SOB_INDEX_COUNT];
	/**<
	 * Virtual SOB array
	 */
	uint32_t gc_tpc_nop_kernel_addr_lo;
	/**<
	 * TPC NOP kernel high
	 * TODO: Do we need this as per context ?
	 */
	uint32_t gc_tpc_nop_kernel_addr_hi;
	/**<
	 * TPC NOP kernel low
	 * TODO: Do we need this as per context ?
	 */
	uint32_t tpc_kernel_addr_lo;
	/**<
	 * Actual TPC kernel address high
	 */
	uint32_t tpc_kernel_addr_hi;
	/**<
	 * Actual TPC kernel address low
	 */
} __attribute__ ((aligned(4), __packed__));

/**
 * \struct  tpc_wd_ctxts_t
 * \brief   TPC engine and sync scheme context
 * \details TPC engine context and sync scheme context used for GC
 */
struct tpc_wd_ctxts_t {
	struct tpc_wd_ctxt_t tpc_ctxt[WD_CTXT_COUNT];
	/**<
	 * Array of contexts for TPC
	 */

	/*
	 * TODO: Add global parameters here
	 * Global means used in all the contexts
	 */
} __attribute__ ((aligned(4), __packed__));

/**
 * \struct  eng_arc_cmd_generic_t
 * \brief   generic command structure
 * \details Generic command structure
 */
struct eng_arc_cmd_generic_t {
	uint32_t cmd_type:4;
	/**<
	 * set to eng_arc_cmd_t
	 */
	uint32_t yield:1;
	/**<
	 * Yield ARC control to the other list (s/d) after execution
	 */
	uint32_t dma_completion:3;
	/**<
	 * Number of DMAs should complete before the execution can start
	 */
	uint32_t reserved:24;
} __attribute__ ((__packed__));


/**
 * \struct  eng_arc_cmd_nop_t
 * \brief   NOP command structure
 * \details NOP command to align other commands on the buffer boundary
 */
struct eng_arc_cmd_nop_t {
	uint32_t cmd_type:4;
	/**<
	 * set to ECB_CMD_NOP
	 */
	uint32_t yield:1;
	/**<
	 * Yield ARC control to the other list (s/d) after execution
	 */
	uint32_t dma_completion:3;
	/**<
	 * Number of DMAs should complete before the execution can start
	 */
	uint32_t switch_cq:1;
	/**<
	 * Switch CQ
	 * Engine FW pushes a NOP QMAN command into Static CQ or ARC CQ
	 * depending on the ECB list where this command is encountered
	 * and causes switch between Static CQ and ARC CQ
	 */
	uint32_t padding:23;
	/**<
	 * Number of DWORDS(4 Bytes) padded after this command.
	 * When padding = 0 means the size of DWORD command is 1 DWORD
	 */
} __attribute__ ((__packed__));

/**
 * \struct  eng_arc_cmd_static_desc_t
 * \brief   Static CP DMA transfer
 * \details Push a descriptor into static CQ. The content of the descriptor
 *	    is not known to Firmware. The descriptor buffer can contain
 *	    any valid QMAN commands
 */
struct eng_arc_cmd_static_desc_t {
	uint32_t cmd_type:4;
	/**<
	 * set to ECB_CMD_STATIC_DESC
	 */
	uint32_t yield:1;
	/**<
	 * Yield ARC control to the other list (s/d) after execution
	 */
	uint32_t reserved:3;
	/**<
	 * Reserved, unused
	 */
	uint32_t cpu_id:8;
	/**<
	 * ARC CPU ID as defined in the common header
	 * CPU_ID_xxx_QMAN_ARCx
	 * cpu_id = CPU_ID_ALL command is processed by all engine ARCs
	 * cpu_id = CPU_ID_INVALID command is ignored by all engine ARCs
	 */
	uint32_t size:13;
	/**<
	 * transfer size in bytes
	 * TODO: can be coverted to DWORD if 21bits are not enough
	 */
	uint32_t addr_index:3;
	/**<
	 * Recipe base address register index to be used to generate target
	 * address of 64 bits
	 */
	uint32_t addr_offset;
	/**<
	 * 32bit address offset
	 */
} __attribute__ ((__packed__));

/**
 * \struct  eng_arc_cmd_wd_fence_and_exec_t
 * \brief   Work distribution, fence and execute
 * \details TODO;
 */
struct eng_arc_cmd_wd_fence_and_exec_t {
	uint32_t cmd_type:4;
	/**<
	 * set to ECB_CMD_WD_FENCE_AND_EXE
	 */
	uint32_t yield:1;
	/**<
	 * Yield ARC control to the other list (s/d) after execution
	 */
	uint32_t dma_completion:3;
	/**<
	 * Number of DMAs should complete before the execution can start
	 */
	uint32_t reserved:19;
	uint32_t wd_ctxt_id:3;
	/**<
	 * a context number from 0 to max number of contexts that fw supports
	 */
} __attribute__ ((__packed__));

/**
 * \struct  eng_arc_cmd_sched_dma_t
 * \brief   Schedule DMA to update GC context
 * \details Initiate a DMA transfer to update GC context. Any command which
 *	    depends on this transfer to be completed can use the dma_completion
 *	    field of that command to wait until GC context is updated.
 */
struct eng_arc_cmd_sched_dma_t {
	uint32_t cmd_type:4;
	/**<
	 * set to ECB_CMD_SCHED_DMA
	 */
	uint32_t yield:1;
	/**<
	 * Yield ARC control to the other list (s/d) after execution
	 */
	uint32_t addr_index:3;
	/**<
	 * Recipe base address register index to be used to generate target
	 * address of 64 bits
	 */
	uint32_t size:10;
	/**<
	 * size of the buffer in bytes
	 */
	uint32_t gc_ctxt_offset:14;
	/*
	 * destination address where the DMA needs to be done
	 * offset of the location within GC managed struct in the DCCM
	 */
	uint32_t addr_offset;
	/**<
	 * 32bit address offset into recipe base address
	 */
} __attribute__ ((__packed__));

/**
 * \struct  eng_arc_cmd_list_size_t
 * \brief   Schedule DMA to update GC context
 * \details This is the first command in the chunk to indicate size of the list
 *	    Its present in static and dynamic list both.
 */
struct eng_arc_cmd_list_size_t {
	uint32_t cmd_type:4;
	/**<
	 * set to ECB_CMD_LIST_SIZE
	 */
	uint32_t yield:1;
	/**<
	 * Yield ARC control to the other list (s/d) after execution
	 */
	uint32_t topology_start:1;
	/**<
	 * start of new topology, fw can reset
	 * prev_sob_id etc. when this flag is set to 1
	 */
	uint32_t reserved:2;
	/**<
	 * reserved
	 */
	uint32_t list_size:24;
	/**<
	 * Total size of list in bytes; for FW management of double buffer
	 * The size includes the size of this command as well.
	 */
} __attribute__ ((__packed__));

/**
 * \struct  eng_arc_cmd_arm_mon_t
 * \brief   ARM monitor
 * \details Arm monitor by converting the virtual SOB ID into physical SOB
 *	    ID, based on the producer engine type.
 *	    When the monitor fires, it increments a particular local fence
 *	    register.
 */
struct eng_arc_cmd_arm_mon_t {
	uint32_t cmd_type:4;
	/**<
	 * set to ECB_CMD_ARM_MON
	 */
	uint32_t yield:1;
	/**<
	 * Yield ARC control to the other list (s/d) after execution
	 */
	uint32_t dma_completion:3;
	/**<
	 * Number of DMAs should complete before the execution can start
	 */
	union {
		struct {
			uint16_t sob_offset:6;
			/**<
			 * SOB offset into 64 SOBs allocated in a given SO set
			 * TODO: I have removed cycle bit, I am not sure how it
			 * adds value, or how it should be used
			 */
			uint16_t threshold:10;
			/**<
			 * Monitor ttarget hreshold to be programmed
			 * target threshold = threshold * 32;
			 * Target threshold is always in multiple of 32
			 */
		} tpc;
		struct {
			uint16_t sob_offset:3;
			uint16_t threshold:13;
		} mme;
		struct {
			uint16_t sob_offset:5;
			uint16_t threshold:11;
		} edma;
		uint16_t raw;
	} virtual_sob_id;
	/**<
	 * virtual SOB ID of the producer engine
	 * TODO: EDMA encoding is not yet finalized, so kept only placeholder
	 */
	uint32_t mon_op:1;
	/*
	 * operation to be configured in monitor
	 * 0 - Greater Equal to
	 * 1 - Equal to
	 */
	uint32_t engine_type:3;
	/**<
	 * Produce engine type
	 */
	uint32_t reserved:4;
} __attribute__ ((__packed__));

/*
 * Single Offset CML entry
 */
struct nic_socml_entry_t {
	uint32_t local_chunk_index;
	uint32_t qpn;
} __attribute__ ((__packed__));

/*
 * Dual Offset CML entry
 */
struct nic_docml_entry_t {
	uint32_t local_chunk_index;
	uint32_t remote_chunk_index;
	uint32_t qpn;
} __attribute__ ((__packed__));

/*
 * Single Offset CML
 */
struct nic_socml_t {
	uint32_t num_entries;
	struct nic_socml_entry_t entries[];
} __attribute__ ((__packed__));

/*
 * Dual Offset CML
 */
struct nic_docml_t {
	uint32_t num_entries;
	struct nic_docml_entry_t entries[];
} __attribute__ ((__packed__));

/*
 * NIC input descriptor data structure
 * Address of this descriptor is sent by scheduler ARC to NIC DCCM queue
 * via a command
 * Note:
 * 36 Bytes of static descriptor as defined in NIC spec
 * and 8 Bytes of Bulk Reg Write command, so 44 bytes
 */
#define NIC_STATIC_DESC_SIZE		(44)
#define NIC_STATIC_DESC_SIZE_DWORD	(NIC_STATIC_DESC_SIZE / 4)

struct eng_arc_nic_input_desc_t {
	uint32_t static_desc[NIC_STATIC_DESC_SIZE_DWORD];
	/*
	 * static descriptor including qman command header
	 */
	uint32_t cmt_offset:16;
	/*
	 * communication table offset
	 */
	uint32_t reserved:15;
	uint32_t docml:1;
	/*
	 * if this is set then cmt entry pointed by the cmt_offset is dual
	 * offset cml or not i.e. arc_cmd_docml_ts
	 */
	uint32_t chunk_size;
	uint32_t total_size;
} __attribute__ ((__packed__));

#endif /* __GAUDI2_ARC_ENG_PACKETS_H__ */
