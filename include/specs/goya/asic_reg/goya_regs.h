/* SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2019 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */
 
#ifndef ASIC_REG_GOYA_REGS_H_
#define ASIC_REG_GOYA_REGS_H_

#include "goya_blocks.h"
#include "psoc_global_conf_regs.h"
#include "cpu_ca53_cfg_regs.h"
#include "tpc_pll_regs.h"
#include "dma_qm_0_regs.h"
#include "dma_qm_1_regs.h"
#include "dma_qm_2_regs.h"
#include "dma_qm_3_regs.h"
#include "dma_qm_4_regs.h"
#include "mme_qm_regs.h"
#include "mme_cmdq_regs.h"
#include "tpc0_qm_regs.h"
#include "tpc1_qm_regs.h"
#include "tpc2_qm_regs.h"
#include "tpc3_qm_regs.h"
#include "tpc4_qm_regs.h"
#include "tpc5_qm_regs.h"
#include "tpc6_qm_regs.h"
#include "tpc7_qm_regs.h"
#include "tpc0_cmdq_regs.h"
#include "tpc1_cmdq_regs.h"
#include "tpc2_cmdq_regs.h"
#include "tpc3_cmdq_regs.h"
#include "tpc4_cmdq_regs.h"
#include "tpc5_cmdq_regs.h"
#include "tpc6_cmdq_regs.h"
#include "tpc7_cmdq_regs.h"

#define mmSYNC_MNGR_MON_PAY_ADDRL_0                                  0x113000
#define mmSYNC_MNGR_MON_PAY_ADDRH_0                                  0x113400
#define mmSYNC_MNGR_MON_PAY_DATA_0                                   0x113800
#define mmSYNC_MNGR_MON_ARM_0                                        0x113C00

#define mmGIC_DISTRIBUTOR__5_GICD_SETSPI_NSR                         0x800040

#endif /* ASIC_REG_GOYA_REGS_H_ */
