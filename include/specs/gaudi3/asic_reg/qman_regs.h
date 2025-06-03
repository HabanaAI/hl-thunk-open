/* SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2021 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

/************************************
 ** This is an auto-generated file **
 **       DO NOT EDIT BELOW        **
 ************************************/

#ifndef ASIC_REG_QMAN_REGS_H_
#define ASIC_REG_QMAN_REGS_H_

/*
 *****************************************
 *   QMAN
 *   (Prototype: QMAN)
 *****************************************
 */

#define mmQMAN_GLBL_CFG0 0x0

#define mmQMAN_GLBL_CFG1 0x4

#define mmQMAN_GLBL_CFG2 0x8

#define mmQMAN_GLBL_ERR_CFG 0xC

#define mmQMAN_GLBL_ERR_CFG1 0x10

#define mmQMAN_GLBL_ERR_ARC_HALT_EN 0x14

#define mmQMAN_GLBL_HBW_AXCACHE 0x18

#define mmQMAN_GLBL_STS0 0x1C

#define mmQMAN_GLBL_STS1 0x20

#define mmQMAN_GLBL_ERR_STS 0x24

#define mmQMAN_GLBL_ERR_MSG_EN 0x28

#define mmQMAN_GLBL_PROT 0x2C

#define mmQMAN_CQ_CFG0 0x30

#define mmQMAN_CQ_STS0 0x34

#define mmQMAN_CQ_CFG1 0x38

#define mmQMAN_CQ_STS1 0x3C

#define mmQMAN_CQ_PTR_LO 0x40

#define mmQMAN_CQ_PTR_HI 0x44

#define mmQMAN_CQ_TSIZE 0x48

#define mmQMAN_CQ_CTL 0x4C

#define mmQMAN_CQ_TSIZE_STS 0x50

#define mmQMAN_CQ_PTR_LO_STS 0x54

#define mmQMAN_CQ_PTR_HI_STS 0x58

#define mmQMAN_CQ_IFIFO_STS 0x5C

#define mmQMAN_CP_MSG_BASE_ADDR_0 0x60

#define mmQMAN_CP_MSG_BASE_ADDR_1 0x64

#define mmQMAN_CP_MSG_BASE_ADDR_2 0x68

#define mmQMAN_CP_MSG_BASE_ADDR_3 0x6C

#define mmQMAN_CP_MSG_BASE_ADDR_4 0x70

#define mmQMAN_CP_MSG_BASE_ADDR_5 0x74

#define mmQMAN_CP_MSG_BASE_ADDR_6 0x78

#define mmQMAN_CP_MSG_BASE_ADDR_7 0x7C

#define mmQMAN_CP_MSG_BASE_ADDR_8 0x80

#define mmQMAN_CP_MSG_BASE_ADDR_9 0x84

#define mmQMAN_CP_MSG_BASE_ADDR_10 0x88

#define mmQMAN_CP_MSG_BASE_ADDR_11 0x8C

#define mmQMAN_CP_MSG_BASE_ADDR_12 0x90

#define mmQMAN_CP_MSG_BASE_ADDR_13 0x94

#define mmQMAN_CP_MSG_BASE_ADDR_14 0x98

#define mmQMAN_CP_MSG_BASE_ADDR_15 0x9C

#define mmQMAN_CP_FENCE0_RDATA 0xA0

#define mmQMAN_CP_FENCE1_RDATA 0xA4

#define mmQMAN_CP_FENCE2_RDATA 0xA8

#define mmQMAN_CP_FENCE3_RDATA 0xAC

#define mmQMAN_CP_FENCE0_CNT 0xB0

#define mmQMAN_CP_FENCE1_CNT 0xB4

#define mmQMAN_CP_FENCE2_CNT 0xB8

#define mmQMAN_CP_FENCE3_CNT 0xBC

#define mmQMAN_CP_BARRIER_CFG 0xC0

#define mmQMAN_CP_LDMA_BASE_ADDR 0xC4

#define mmQMAN_CP_STS 0xC8

#define mmQMAN_CP_CURRENT_INST_LO 0xCC

#define mmQMAN_CP_CURRENT_INST_HI 0xD0

#define mmQMAN_CP_PRED 0xD4

#define mmQMAN_CP_PRED_UPEN 0xD8

#define mmQMAN_CP_DBG_0 0xDC

#define mmQMAN_CP_IN_DATA_LO 0xE0

#define mmQMAN_CP_IN_DATA_HI 0xE4

#define mmQMAN_ARC_CQ_CFG0 0xE8

#define mmQMAN_ARC_CQ_CFG1 0xEC

#define mmQMAN_ARC_CQ_PTR_LO 0xF0

#define mmQMAN_ARC_CQ_PTR_HI 0xF4

#define mmQMAN_ARC_CQ_TSIZE 0xF8

#define mmQMAN_ARC_CQ_STS0 0xFC

#define mmQMAN_ARC_CQ_CTL 0x100

#define mmQMAN_ARC_CQ_IFIFO_STS 0x104

#define mmQMAN_ARC_CQ_STS1 0x108

#define mmQMAN_ARC_CQ_TSIZE_STS 0x10C

#define mmQMAN_ARC_CQ_PTR_LO_STS 0x110

#define mmQMAN_ARC_CQ_PTR_HI_STS 0x114

#define mmQMAN_ARC_CQ_IFIFO_MSG_BASE_HI 0x120

#define mmQMAN_ARC_CQ_IFIFO_MSG_BASE_LO 0x124

#define mmQMAN_ARC_CQ_CTL_MSG_BASE_HI 0x128

#define mmQMAN_ARC_CQ_CTL_MSG_BASE_LO 0x12C

#define mmQMAN_CQ_IFIFO_MSG_BASE_HI 0x130

#define mmQMAN_CQ_IFIFO_MSG_BASE_LO 0x134

#define mmQMAN_CQ_CTL_MSG_BASE_HI 0x138

#define mmQMAN_CQ_CTL_MSG_BASE_LO 0x13C

#define mmQMAN_CQ_IFIFO_CI 0x140

#define mmQMAN_ARC_CQ_IFIFO_CI 0x144

#define mmQMAN_CQ_CTL_CI 0x148

#define mmQMAN_ARC_CQ_CTL_CI 0x14C

#define mmQMAN_CP_CFG 0x150

#define mmQMAN_CP_EXT_SWITCH 0x154

#define mmQMAN_ARC_LB_ADDR_BASE_LO 0x158

#define mmQMAN_ARC_LB_ADDR_BASE_HI 0x15C

#define mmQMAN_ENGINE_BASE_ADDR_HI 0x160

#define mmQMAN_ENGINE_BASE_ADDR_LO 0x164

#define mmQMAN_ENGINE_ADDR_RANGE_SIZE 0x168

#define mmQMAN_QM_BASE_ADDR_HI 0x16C

#define mmQMAN_QM_BASE_ADDR_LO 0x170

#define mmQMAN_GLBL_ERR_ADDR_LO 0x174

#define mmQMAN_GLBL_ERR_ADDR_HI 0x178

#define mmQMAN_GLBL_ERR_WDATA 0x17C

#define mmQMAN_L2H_MASK_LO 0x180

#define mmQMAN_L2H_MASK_HI 0x184

#define mmQMAN_L2H_CMPR_LO 0x188

#define mmQMAN_L2H_CMPR_HI 0x18C

#define mmQMAN_LOCAL_RANGE_BASE 0x190

#define mmQMAN_LOCAL_RANGE_SIZE 0x194

#define mmQMAN_HBW_RD_RATE_LIM_CFG_1 0x198

#define mmQMAN_LBW_WR_RATE_LIM_CFG_0 0x19C

#define mmQMAN_LBW_WR_RATE_LIM_CFG_1 0x1A0

#define mmQMAN_HBW_RD_RATE_LIM_CFG_0 0x1A4

#define mmQMAN_IND_GW_APB_CFG 0x1A8

#define mmQMAN_IND_GW_APB_WDATA 0x1AC

#define mmQMAN_IND_GW_APB_RDATA 0x1B0

#define mmQMAN_IND_GW_APB_STATUS 0x1B4

#define mmQMAN_PERF_CNT_FREE_LO 0x1B8

#define mmQMAN_PERF_CNT_FREE_HI 0x1BC

#define mmQMAN_PERF_CNT_IDLE_LO 0x1C0

#define mmQMAN_PERF_CNT_IDLE_HI 0x1C4

#define mmQMAN_PERF_CNT_CFG 0x1C8

#define mmQMAN_CP_CUR_CH_PRGM_REG 0x1CC

#define mmQMAN_ARC_CTL 0x1D0

#define mmQMAN_SEI_STATUS 0x1D4

#define mmQMAN_SEI_MASK 0x1D8

#define mmQMAN_ARC_AXI_OVRD 0x1DC

#define mmQMAN_GLBL_LBW_AXCACHE 0x1E0

#endif /* ASIC_REG_QMAN_REGS_H_ */
