/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __ARC_MSGS_H__
#define __ARC_MSGS_H__

#include "arc_types.h"

/**
 * \file    arc_cmds.h
 * \brief   ARC Command definitions for both the ARCs.
 *          This defines data structures to be used by both the ARCs i.e.
 *          scheduler ARC and Engine ARC to communicate
 */

/*!<
 * Size of Engine ARC DCCM queue in Bytes
 */
#define MAX_DCCM_QUEUE_COUNT		8
#define PDMA_DCCM_QUEUE_COUNT		5
#define EDMA_DCCM_QUEUE_COUNT		2
#define NIC_DCCM_QUEUE_COUNT		2

/*!<
 * compute engine supports only 1 queue/priority
 */
#define COMPUTE_DCCM_QUEUE_COUNT	1
#define MME_DCCM_QUEUE_COUNT		COMPUTE_DCCM_QUEUE_COUNT
#define TPC_DCCM_QUEUE_COUNT		COMPUTE_DCCM_QUEUE_COUNT
#define ROT_DCCM_QUEUE_COUNT		COMPUTE_DCCM_QUEUE_COUNT

/*!<
 * Size of Engine ARC DCCM queue in Bytes
 */
#define ENGINE_ARC_DCCM_QUEUE_SIZE_BYTES	2048
#define ENGINE_ARC_DCCM_QUEUE_SIZE_DWORD	(ENGINE_ARC_DCCM_QUEUE_SIZE_BYTES / 4)

/*!<
 * Every time all the engine ARC consumes this much chunk scheduler ARC
 * will receive a notification in the engine ARC queue
 */
#define ENGINE_ARC_QUEUE_THRESHOLD_SIZE_BYTES		(ENGINE_ARC_DCCM_QUEUE_SIZE_BYTES / 2)
#define ENGINE_ARC_QUEUE_THRESHOLD_SIZE_DWORD		(ENGINE_ARC_QUEUE_THRESHOLD_SIZE_BYTES / 4)

#define FIRMWARE_CONFIG_SIZE	1024

/**
 * \enum    arc_cmd_opcode_t
 * \brief   Various ARC command opcodes
 * \details Command IDs for commands sent to Engine ARC from Scheduler ARC
 */
enum arc_cmd_opcode_t {
	ARC_CMD_BARRIER_OPCODE = 0x0,
	ARC_CMD_DISPATCH_STATIC_ECB_OPCODE = 0x1,

	ARC_CMD_UPDATE_RECIPE_BASE_OPCODE = 0x2,
	ARC_CMD_DISPATCH_COMPUTE_ECB_LIST_OPCODE = 0x3,
	ARC_CMD_DOWNLOAD_CMT_OPCODE = 0x4,
	ARC_CMD_PROCESS_CMT_OPCODE = 0x5,
	ARC_CMD_SO_SET_ALLOC = 0x6,
	ARC_CMD_LAST_OPCODE = 0x1F,
};

enum arc_cmd_pdma_opcode_t {
	/* Leave common opcodes */
	ARC_CMD_PDMA_USER_DATA_OPCODE = 0x2,
	ARC_CMD_PDMA_COMMANDS_OPCODE = 0x3,
	ARC_CMD_PDMA_LAST_OPCODE = 0x1F,
};

struct arc_cmd_generic_t {
	u32 opcode:5;
	u32 reserved:27;
} __attribute__ ((__packed__));

/**
 * \struct  arc_cmd_send_ecb_to_lcp_t
 * \brief   Dispatch to engine ARC command
 * \details Command structure to send the dispatch a command to engine ARC
 */
struct arc_cmd_dispatch_static_ecb_t {
	/*!< opcode of the command = ARC_CMD_DISPATCH_STATIC_ECB_OPCODE */
	u32 opcode:5;
	/*!< reserved */
	u32 reserved:16;
	/*!< Message barrier */
	u32 engine_cpu_id:11;
	/*!< size of the static ECB */
	u32 ecb_size;
	/*!< 64 bit address in the memory */
	u64 address;
} __attribute__ ((__packed__));

typedef u32 arc_cmd_dispatch_static_ecb_t_assert[(sizeof(struct arc_cmd_dispatch_static_ecb_t) == 16) * 2 - 1];

#define ARC_CMD_DISPATCH_STATIC_ECB_SIZE (sizeof(struct arc_cmd_dispatch_static_ecb_t))
#define ARC_CMD_DISPATCH_STATIC_ECB_SIZE_DWORD (ARC_CMD_DISPATCH_STATIC_ECB_SIZE / 4)

struct arc_cmd_barrier_t {
	/*!< opcode of the command = ARC_CMD_BARRIER */
	u32 opcode:5;
	/*!< Sync Object ID */
	u32 sob_id:13;
	u32 dcore_id:2;
	/*!< Unused/reserved */
	u32 reserved2:12;
} __attribute__ ((__packed__));

typedef u32 arc_cmd_barrier_t_assert[(sizeof(struct arc_cmd_barrier_t) == 4) * 2 - 1];

#define ARC_CMD_BARRIER_SIZE (sizeof(struct arc_cmd_barrier_t))
#define ARC_CMD_BARRIER_SIZE_DWORD (ARC_CMD_BARRIER_SIZE/4)

struct arc_cmd_dispatch_compute_ecb_list_t {
	/*!< opcode of the command = ARC_CMD_DISPATCH_COMPUTE_ECB_LIST_OPCODE */
	u32 opcode:5;
	/*!< Size in DWORDs(32bit) of Engine Command Buffer in system memory */
	u32 single_static_chunk:1;
	u32 single_dynamic_chunk:1;
	u32 static_ecb_list_offset:25;
	/*!< 32 bit address in the memory for dynamic ecb list */
	u32 dynamic_ecb_list_addr;
	/*!< 32 bit address in the memory for dynamic ecb list */
} __attribute__ ((__packed__));

typedef u32 arc_cmd_dispatch_compute_ecb_list_t_assert[(sizeof(struct arc_cmd_dispatch_compute_ecb_list_t) == 8) * 2 - 1];

#define ARC_CMD_DISPATCH_COMPUTE_ECB_LIST_SIZE (sizeof(struct arc_cmd_dispatch_compute_ecb_list_t))
#define ARC_CMD_DISPATCH_COMPUTE_ECB_LIST_SIZE_DWORD (ARC_CMD_DISPATCH_COMPUTE_ECB_LIST_SIZE/4)

struct arc_cmd_so_set_alloc_t {
	/*!< opcode of the command = ARC_CMD_SO_SET_ALLOC */
	u32 opcode:5;
	u32 reserved:12;
	/*!< SOB start ID */
	u32 sob_start_id:15;
} __attribute__ ((__packed__));

typedef u32 arc_cmd_arc_cmd_so_set_alloc_t_assert[(sizeof(struct arc_cmd_so_set_alloc_t) == 4) * 2 - 1];

#define ARC_CMD_SO_SET_ALLOC_SIZE (sizeof(struct arc_cmd_so_set_alloc_t))
#define ARC_CMD_SO_SET_ALLOC_SIZE_DWORD (ARC_CMD_SO_SET_ALLOC_SIZE / 4)

/**
 * \struct  arc_cmd_update_recipe_base_t
 * \brief   Update the recipe base address
 * \details Update the recipe base address pointed by index
 */
struct arc_cmd_update_recipe_base_t {
	/*!< opcode of the command = ARC_CMD_UPDATE_RECIPE_BASE_OPCODE */
	u32 opcode:5;
	/*!< size of the static ECB */
	u32 recipe_base_index:3;
	/*!< Message barrier */
	u32 reserved:24;
	/*!< 64 bit address in the memory */
	u64 recipe_base_addr;
} __attribute__ ((__packed__));

typedef u32 arc_cmd_update_recipe_base_t_assert[(sizeof(struct arc_cmd_update_recipe_base_t) == 12) * 2 - 1];

#define ARC_CMD_UPDATE_RECIPE_BASE_SIZE (sizeof(struct arc_cmd_update_recipe_base_t))
#define ARC_CMD_UPDATE_RECIPE_BASE_SIZE_DWORD (ARC_CMD_UPDATE_RECIPE_BASE_SIZE / 4)

#define TENSOR_DIMS	5
struct arc_tensor_cfg_t {
	u32 offset[TENSOR_DIMS];
	u32 size[TENSOR_DIMS];
};

// Compute Dynamic Recipe input parameters (sent from Lower CP)
struct arc_cmd_compute_dyn_recipe_t {
	/*!< opcode of the command = ARC_CMD_COMPUTE_DYN_RECIPE */
	u32 opcode:5;
	/*!< Unused/reserved */
	u32 reserved1:3;
	/*!< First engine that should execute */
	u32 first_engine_index:8;
	/*!< Number of executing engines */
	u32 engines_num:8;
	/*!< Unused/reserved */
	u32 reserved2:7;
	/*!< Message barrier */
	u32 mb:1;
	struct arc_tensor_cfg_t grid_size;
	struct arc_tensor_cfg_t grid_start_pos;
	struct arc_tensor_cfg_t box_size;
} __attribute__ ((__packed__));

struct arc_cmd_download_cmt_t {
	/*!< opcode of the command = ARC_CMD_DOWNLOAD_CML_OPCODE */
	u32 opcode:5;
	/*!< Primary Queue ID required to be sent in response */
	u32 pq_id:8;
	/*!< Size in bytes of Communication List in system memory */
	u32 cmt_size:19;
	/*!< 64 bit address in the memory */
	u32 cmt_addr;
} __attribute__ ((__packed__));

typedef u32 arc_cmd_download_cmt_t_assert[(sizeof(struct arc_cmd_download_cmt_t) == 8) * 2 - 1];

#define ARC_CMD_DOWNLOAD_CMT_SIZE (sizeof(struct arc_cmd_download_cmt_t))
#define ARC_CMD_DOWNLOAD_CMT_SIZE_DWORD (ARC_CMD_DOWNLOAD_CMT_SIZE/4)

struct arc_cmd_process_cmt_t {
	/*!< opcode of the command = ARC_CMD_PROCESS_CML_OPCODE */
	u32 opcode:5;
	/*!< Primary Queue ID required to be sent in response */
	u32 pq_id:8;
	/*!< Size in bytes of Communication List in system memory */
	u32 nic_desc_size:19;
	/*!< 32 bit address in the memory */
	u32 nic_desc_addr;
} __attribute__ ((__packed__));

typedef u32 arc_cmd_process_cmt_t_assert[(sizeof(struct arc_cmd_process_cmt_t) == 8) * 2 - 1];

#define ARC_CMD_PROCESS_CMT_SIZE (sizeof(struct arc_cmd_process_cmt_t))
#define ARC_CMD_PROCESS_CMT_SIZE_DWORD (ARC_CMD_PROCESS_CMT_SIZE/4)

struct arc_cmd_pdma_user_data_t {
	/*!< opcode of the command = ARC_CMD_PDMA_USER_DATA_OPCODE */
	u32 opcode:5;
	/*!< Used for sending completion back to DCCM queue */
	u32 sched_id:3;
	/*!< Used for sending completion back to DCCM queue */
	u32 reserved1:5;
	/*!< Used for sending completion back to DCCM queue */
	u32 has_payload:1;
	/*!< reserved */
	u32 reserved:18;
	/*!< 64 bit address in the memory */
	u64 src_addr;
	/*!< 64 bit address in the memory */
	u64 dst_addr;
	/*!< 64 bit address in the memory */
	u32 transfer_size;
	u32 pay_data;
	u32 pay_addr;
} __attribute__ ((__packed__));

typedef u32 arc_cmd_pdma_user_data_t_assert[(sizeof(struct arc_cmd_pdma_user_data_t) == 32) * 2 - 1];

#define ARC_CMD_PDMA_USER_DATA_SIZE (sizeof(struct arc_cmd_pdma_user_data_t))
#define ARC_CMD_PDMA_USER_DATA_SIZE_DWORD (ARC_CMD_PDMA_USER_DATA_SIZE / 4)

struct arc_cmd_pdma_commands_t {
	/*!< opcode of the command = ARC_CMD_PDMA_COMMANDS_OPCODE */
	u32 opcode:5;
	/*!< Used for sending completion back to DCCM queue */
	u32 sched_id:3;
	/*!< Used for sending completion back to DCCM queue */
	u32 reserved1:5;
	/*!< Used for sending completion back to DCCM queue */
	u32 has_payload:1;
	/*!< reserved */
	u32 reserved:18;
	/*!< 64 bit address in the memory */
	u64 src_addr;
	/*!< 64 bit address in the memory */
	u64 dst_addr;
	/*!< 64 bit address in the memory */
	u32 transfer_size;
	u32 pay_data;
	u32 pay_addr;
} __attribute__ ((__packed__));

typedef u32 arc_cmd_pdma_commands_t_assert[(sizeof(struct arc_cmd_pdma_commands_t) == 32) * 2 - 1];

#define ARC_CMD_PDMA_COMMANDS_SIZE (sizeof(struct arc_cmd_pdma_commands_t))
#define ARC_CMD_PDMA_COMMANDS_SIZE_DWORD (ARC_CMD_PDMA_COMMANDS_SIZE / 4)

struct mon_resp_update_q_credit_t {
	u32 opcode:2;
	u32 engine_group_type:4;
	u32 sob_index:1;
	u32 reserved:25;
} __attribute__ ((__packed__));

#endif /* __ARC_MSGS_H__ */
