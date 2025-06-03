/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#ifndef __ARC_HOST_PACKETS_H__
#define __ARC_HOST_PACKETS_H__

#include "arc_common_packets.h"
#include <stdint.h>

/**
 * \file    host_if.h
 * \brief   Interface file for Host.
 *          This defines data structures to be shared by the Host (LKD)
 *          and QMAN Scheduler ARC.
 */

/**
 * \struct  arc_asic_models
 * \brief   Supported ASIC models
 * \details Enumerator specifying the asic models supported by FW
 */
enum arc_asic_models {
	ARC_ASIC_MODEL_GAUDI2 = 0x100,
	ARC_ASIC_MODEL_GAUDI3 = 0x200,
};

/**
 * Firmware configuration blob version
 */
#define ARC_FW_INIT_CONFIG_VER		0x2

#define MON_COUNT_PER_MON_SET	8
#define DCCM_QUEUE_COUNT	5

struct common_config_t {
	uint32_t version;
	uint32_t log_arc_va;
	uint32_t log_size;
	uint32_t log_enabled;
};

struct engine_config_t {
	struct common_config_t common_cfg;
	uint32_t qm_base;
};

struct sched_engine_arc_config_t {
	uint8_t enabled;
	uint32_t engine_group_type;
	uint32_t arc_aux_base;
};

/**
 * \struct  scheduler_config_t
 * \brief   Scheduler configuration
 * \details Configuration parameters related to a scheduler instance
 */
struct scheduler_config_t {
	struct common_config_t common_cfg;
	struct sched_engine_arc_config_t eng_arc_cfg[MAX_ARC_CPUS];
};

#define SCHED_MAX_CHECKPOINT_COUNT	256

#define MAX_SCHED_QUEUE_COUNT 1

#define MAX_SCHED_QUEUE_SIZE 0x1000

struct sched_soft_queue_t {
	uint8_t q[MAX_SCHED_QUEUE_SIZE];
};

/**
 * \struct  common_arc_reg_t
 * \brief   Common Registers
 * \details Registers of both sched and engine ARC
 *          Registers start at the base address of DCCM
 */
struct common_arc_reg_t {
	uint32_t canary;
	/**<
	 * SCAL writes SCAL_INIT_COMPLETED into this register to inform
	 * firmware that it has completed the initialization and firmware can
	 * now perform Post Init.
	 * not written by firmware at all during runtime.
	 */
	uint32_t asic_model;
	/**<
	 * 32bit free running counter, which is incremented
	 * by engine ARC periodically
	 */
	uint32_t checkpoint_index;
	uint32_t log_buf_ci;
};

/**
 * \struct  sched_registers_t
 * \brief   Scheduler Registers
 * \details Various registers exposed by Scheduler ARC
 *          Registers start at the base address of DCCM
 */
struct sched_registers_t {
	struct common_arc_reg_t common_regs;
	uint32_t checkpoint[SCHED_MAX_CHECKPOINT_COUNT];
	struct sched_soft_queue_t qs[MAX_SCHED_QUEUE_COUNT];
};

#define ENG_MAX_CHECKPOINT_COUNT	256

/**
 * \struct  engine_arc_reg_t
 * \brief   Engine Registers
 * \details Registers of engine ARC
 *          Registers start at the base address of DCCM
 */
struct engine_arc_reg_t {
	struct common_arc_reg_t common_regs;
	uint32_t checkpoint[ENG_MAX_CHECKPOINT_COUNT];
};

#endif /* __ARC_HOST_PACKETS_H__ */
