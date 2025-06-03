/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#ifndef __GAUDI2_ARC_HOST_PACKETS_H__
#define __GAUDI2_ARC_HOST_PACKETS_H__

#include <stdint.h>
#include "gaudi2/asic_reg/gaudi2_regs.h"

/**
 * Firmware interface registers between Scheduler Firmware and Host
 */
#define SCHED_SOB_LBU_ADDR	mmARC_FARM_ARC0_AUX_SCRATCHPAD_0
/**<
 * SCAL writes LBU address of the Fence register which it would
 * like Firmware to update
 */
#define SCHED_FW_CONFIG_ADDR	mmARC_FARM_ARC0_AUX_SCRATCHPAD_1
/**<
 * SCAL writes ARC address of the Configuration which should be used
 * by firmware for initialization
 */
#define SCHED_FW_CONFIG_SIZE	mmARC_FARM_ARC0_AUX_SCRATCHPAD_2
/**<
 * SCAL writes size in bytes of the Configuration which should be used
 * by firmware for initialization
 */
#define SCHED_SOB_LBU_VALUE	mmARC_FARM_ARC0_AUX_SCRATCHPAD_3
/**<
 * SCAL writes LBU value which it would like Firmware to write to
 * SCHED_SOB_LBU_ADDR
 */

/**
 * Firmware interface registers between Engine Firmware and Host
 */
#define ENG_SOB_LBU_ADDR	mmDCORE0_MME_QM_ARC_AUX_SCRATCHPAD_0
#define ENG_FW_CONFIG_ADDR	mmDCORE0_MME_QM_ARC_AUX_SCRATCHPAD_1
#define ENG_FW_CONFIG_SIZE	mmDCORE0_MME_QM_ARC_AUX_SCRATCHPAD_2
#define ENG_SOB_LBU_VALUE	mmDCORE0_MME_QM_ARC_AUX_SCRATCHPAD_3

#endif /* __GAUDI2_ARC_HOST_PACKETS_H__ */
