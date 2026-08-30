/* SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2021 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

#ifndef ASIC_REG_GAUDI3_REGS_H_
#define ASIC_REG_GAUDI3_REGS_H_

#include "gaudi3_blocks.h"

#include "pdma_ch_b_regs.h"
#include "pdma_ch_a_ctx_regs.h"
#include "pdma_ch_a_pqm_ch_regs.h"
#include "pdma_cmn_b_pqm_cmn_b_regs.h"
#include "sob_objs_regs.h"
#include "sob_glbl_regs.h"
#include "sob_glbl_usr_hbw_user_regs.h"
#include "sob_glbl_sec_hbw_user_regs.h"
#include "sob_glbl_priv_hbw_user_regs.h"
#include "qman_arc_aux_regs.h"
#include "qman_regs.h"
#include "cbc_user_regs.h"
#include "pcie_wrap_dbi_access_regs.h"
#include "nic_qpc_regs.h"
#include "prt_mac_core_regs.h"
#include "mme_ctrl_lo_arch_dma_n_ten_st_regs.h"
#include "mme_ctrl_lo_arch_dma_ten_a_regs.h"
#include "mme_ctrl_lo_arch_dma_ten_cout_regs.h"
#include "mme_ctrl_lo_arch_dma_base_addr_regs.h"
#include "mme_ctrl_lo_arch_dma_n_ten_regs.h"
#include "mme_ctrl_lo_regs.h"
#include "mme_ctrl_lo_arch_dma_agu_in0_slave_regs.h"
#include "mme_ctrl_lo_arch_dma_agu_cout0_slave_regs.h"
#include "tpc_regs.h"

#include "pdma_ch_a_pqm_ch_masks.h"
#include "sob_objs_masks.h"
#include "cbc_user_masks.h"
#include "pcie_wrap_dbi_access_masks.h"
#include "prt_mac_core_masks.h"

#define DIE_OFFSET (mmD1_NIC0_UMR_0_BASE - mmD0_NIC0_UMR_0_BASE)

#define PDMA_CH_OFFSET (mmD0_SPDMA0_CH1_A_BASE - mmD0_SPDMA0_CH0_A_BASE)

#define PDMA_CH_B_OFFSET (mmD0_SPDMA0_CH0_B_BASE - mmD0_SPDMA0_CH0_A_BASE)

#define PDMA_CTX_OFFSET (mmD0_SPDMA0_CH0_A_CTX_BASE - mmD0_SPDMA0_CH0_A_BASE)

#define PDMA_CMN_B_OFFSET (mmD0_SPDMA0_CMN_B_BASE - mmD0_SPDMA0_CH0_A_BASE)

#define PDMA_CH_B_CH_LBW_OFFSET (PDMA_CH_B_OFFSET + mmPDMA_CH_B_CH_LBW)

#define PDMA_CMN_B_PQM_CP_MSG_BASE_ADDR_0_OFFSET \
	(PDMA_CMN_B_OFFSET + mmPDMA_CMN_B_PQM_CMN_B_CP_MSG_BASE_ADDR_0)

#define CTX_SRC_BASE_LO_OFFSET (PDMA_CTX_OFFSET + mmPDMA_CH_A_CTX_SRC_BASE_LO)
#define CTX_SRC_BASE_HI_OFFSET (PDMA_CTX_OFFSET + mmPDMA_CH_A_CTX_SRC_BASE_HI)
#define CTX_DST_BASE_LO_OFFSET (PDMA_CTX_OFFSET + mmPDMA_CH_A_CTX_DST_BASE_LO)
#define CTX_DST_BASE_HI_OFFSET (PDMA_CTX_OFFSET + mmPDMA_CH_A_CTX_DST_BASE_HI)

#define HDCORE_OFFSET (mmHD1_ARC_FARM_ARC0_DUP_ENG_BASE - mmHD0_ARC_FARM_ARC0_DUP_ENG_BASE)

#endif /* ASIC_REG_GAUDI3_REGS_H_ */
