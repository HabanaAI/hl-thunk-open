/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#ifndef __GAUDI2_ARC_SCHED_PACKETS_H__
#define __GAUDI2_ARC_SCHED_PACKETS_H__

#include <stdint.h>

/**
 * \file    qman_cmds.h
 * \brief   QMAN Command definitions for Host.
 *          This defines data structures to be used by Host to submit commands
 */

/**
 * \enum    qman_cmd_opcode_t
 * \brief   QMAN commands opcodes
 * \details Opcodes processed by the Scheduler ARC
 */
enum sched_arc_cmd_opcode_t {
	SCHED_ARC_CMD_DISPATCH_STATIC_ECB = 0,
	SCHED_ARC_CMD_NOP = 1,
	SCHED_ARC_CMD_COUNT = 2,
	SCHED_ARC_CMD_SIZE = 0x1F
};

/**
 * \struct  sched_arc_cmd_dispatch_static_ecb_t
 * \brief   Dispatch to engine ARC command
 * \details Command structure to dispatch a command buffer to engine ARC
 */
struct sched_arc_cmd_dispatch_static_ecb_t {
	uint32_t opcode:5;
	/**< opcode of the command = SCHED_ARC_CMD_DISPATCH_STATIC_ECB */
	uint32_t predicate:5;
	/**<
	 * Predicate register to be used
	 * 0 means dont use predicate
	 */
	uint32_t engine_group_type:4;
	/**<
	 * Various engine types supported by hardware
	 */
	uint32_t reserved:18;
	/**<
	 * unused/reserved
	 */
	uint32_t size;
	/**< size of static ECB buffer */
	uint32_t engine_cpu_id;
	/**<
	 *  CPU ID of engine ARC cpu which should process
	 *  this command. All the engine ARC receives the message
	 *  but only the engine ARC which has matching cpu_id processes
	 *  this message.
	 */
	uint64_t addr;
	/**<
	 * 64 bit address of the static ECB in system memory
	 * ARC is not accessing this memory. It only pushes this
	 * address and size in the CQ Fetcher
	 */
} __attribute__ ((__packed__));

/**
 * \struct  qman_cmd_nop_t
 * \brief   Stop Message
 * \details Command structure for Stop message
 */
struct sched_arc_cmd_nop_t {
	uint32_t opcode:5;
	/**< opcode of the command = SCHED_ARC_CMD_NOP */
	uint32_t padding_count:27;
	/**<
	 * number of padded DWORDs(32bits) at the end of the
	 * command for alignment purpose
	 */
	uint32_t padding[0];
	/**<
	 * Padding to align with 256 Bytes command buffer
	 */
} __attribute__ ((__packed__));

/**
 * \enum    sched_mon_exp_opcode_t
 * \brief   Opcodes for monitor expiration messages
 * \details Opcodes used by firmware for monitor expiration messages
 */
enum sched_mon_exp_opcode_t {
	MON_EXP_COMP_FENCE_UPDATE = 0,
	/**<
	 * used internally by firmware
	 */
	MON_EXP_UPDATE_Q_CREDIT = 1
	/**<
	 * used internally by firmware
	 */
};

/**
 * \struct  sched_mon_exp_generic_t
 * \brief   Generic message structure
 * \details Structure describes common fields for all the types of messages
 */
struct sched_mon_exp_generic_t {
	uint32_t opcode:2;
	/**<
	 * opcode
	 */
	uint32_t reserved:30;
	/**<
	 * reserved
	 */
} __attribute__ ((__packed__));

/**
 * \struct  sched_mon_exp_comp_fence_t
 * \brief   Monitor expiration structure to update fence counters in completion
 *	    groups
 * \details structure used for updating global fence counters which are part of
 *	    completion groups
 */
struct sched_mon_exp_comp_fence_t {
	uint32_t opcode:2;
	/**<
	 * opcode : MON_EXP_COMP_FENCE_UPDATE
	 */
	uint32_t comp_group_index:4;
	/**<
	 * Index of the completion group
	 */
	uint32_t mon_id:11;
	/**<
	 * Monitor ID
	 */
	uint32_t mon_dcore_id:2;
	/**<
	 * Monitor Dcore ID
	 */
	uint32_t reserved:13;
	/**<
	 * reserved
	 */
} __attribute__ ((__packed__));

/**
 * \union  sched_mon_exp_msg_t
 * \brief   Various monitor expiration messages
 * \details Various monitor expiration messages shared used by Firmware and
 *	    software stack.
 */
union sched_mon_exp_msg_t {
	struct sched_mon_exp_generic_t generic;
	/**<
	 * monitor expiration message used for global fence counters
	 */
	struct sched_mon_exp_comp_fence_t comp_fence;
	/**<
	 * monitor expiration message used for fence counters of completion
	 * groups
	 */
	uint32_t raw;
	/**<
	 * raw bitfield
	 */
} __attribute__ ((__packed__));

#endif /* __GAUDI2_ARC_SCHED_PACKETS_H__ */
