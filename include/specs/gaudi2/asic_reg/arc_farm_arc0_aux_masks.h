/* SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2020 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

/************************************
 ** This is an auto-generated file **
 **       DO NOT EDIT BELOW        **
 ************************************/

#ifndef ASIC_REG_ARC_FARM_ARC0_AUX_MASKS_H_
#define ASIC_REG_ARC_FARM_ARC0_AUX_MASKS_H_

/*
 *****************************************
 *   ARC_FARM_ARC0_AUX
 *   (Prototype: QMAN_ARC_AUX)
 *****************************************
 */

/* ARC_FARM_ARC0_AUX_RUN_HALT_REQ */
#define ARC_FARM_ARC0_AUX_RUN_HALT_REQ_RUN_REQ_SHIFT 0
#define ARC_FARM_ARC0_AUX_RUN_HALT_REQ_RUN_REQ_MASK 0x1
#define ARC_FARM_ARC0_AUX_RUN_HALT_REQ_HALT_REQ_SHIFT 1
#define ARC_FARM_ARC0_AUX_RUN_HALT_REQ_HALT_REQ_MASK 0x2

/* ARC_FARM_ARC0_AUX_RUN_HALT_ACK */
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_RUN_ACK_SHIFT 0
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_RUN_ACK_MASK 0x1
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_HALT_ACK_SHIFT 4
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_HALT_ACK_MASK 0x10
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_SYS_HALT_R_SHIFT 8
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_SYS_HALT_R_MASK 0x100
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_SYS_TF_HALT_R_SHIFT 12
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_SYS_TF_HALT_R_MASK 0x1000
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_SYS_SLEEP_R_SHIFT 16
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_SYS_SLEEP_R_MASK 0x10000
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_SYS_SLEEP_MODE_R_SHIFT 17
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_SYS_SLEEP_MODE_R_MASK 0xE0000
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_WATCHDOG_RESET_SHIFT 20
#define ARC_FARM_ARC0_AUX_RUN_HALT_ACK_WATCHDOG_RESET_MASK 0x100000

/* ARC_FARM_ARC0_AUX_RST_VEC_ADDR */
#define ARC_FARM_ARC0_AUX_RST_VEC_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_RST_VEC_ADDR_VAL_MASK 0x3FFFFF

/* ARC_FARM_ARC0_AUX_DBG_MODE */
#define ARC_FARM_ARC0_AUX_DBG_MODE_DBG_PROT_SEL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DBG_MODE_DBG_PROT_SEL_MASK 0x1
#define ARC_FARM_ARC0_AUX_DBG_MODE_DBGEN_SHIFT 4
#define ARC_FARM_ARC0_AUX_DBG_MODE_DBGEN_MASK 0x10
#define ARC_FARM_ARC0_AUX_DBG_MODE_NIDEN_SHIFT 8
#define ARC_FARM_ARC0_AUX_DBG_MODE_NIDEN_MASK 0x100
#define ARC_FARM_ARC0_AUX_DBG_MODE_CASHE_RST_DISABLE_SHIFT 12
#define ARC_FARM_ARC0_AUX_DBG_MODE_CASHE_RST_DISABLE_MASK 0x1000
#define ARC_FARM_ARC0_AUX_DBG_MODE_DDCM_DMI_PRIORITY_SHIFT 16
#define ARC_FARM_ARC0_AUX_DBG_MODE_DDCM_DMI_PRIORITY_MASK 0x10000

/* ARC_FARM_ARC0_AUX_CLUSTER_NUM */
#define ARC_FARM_ARC0_AUX_CLUSTER_NUM_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CLUSTER_NUM_VAL_MASK 0xFF

/* ARC_FARM_ARC0_AUX_ARC_NUM */
#define ARC_FARM_ARC0_AUX_ARC_NUM_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_NUM_VAL_MASK 0xFF

/* ARC_FARM_ARC0_AUX_WAKE_UP_EVENT */
#define ARC_FARM_ARC0_AUX_WAKE_UP_EVENT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_WAKE_UP_EVENT_VAL_MASK 0x1

/* ARC_FARM_ARC0_AUX_DCCM_SYS_ADDR_BASE */
#define ARC_FARM_ARC0_AUX_DCCM_SYS_ADDR_BASE_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_SYS_ADDR_BASE_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CTI_AP_STS */
#define ARC_FARM_ARC0_AUX_CTI_AP_STS_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CTI_AP_STS_VAL_MASK 0xFF

/* ARC_FARM_ARC0_AUX_CTI_CFG_MUX_SEL */
#define ARC_FARM_ARC0_AUX_CTI_CFG_MUX_SEL_RUN_HALT_SHIFT 0
#define ARC_FARM_ARC0_AUX_CTI_CFG_MUX_SEL_RUN_HALT_MASK 0x1

/* ARC_FARM_ARC0_AUX_ARC_RST */
#define ARC_FARM_ARC0_AUX_ARC_RST_CORE_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_RST_CORE_MASK 0x1
#define ARC_FARM_ARC0_AUX_ARC_RST_PRESETDBGN_SHIFT 4
#define ARC_FARM_ARC0_AUX_ARC_RST_PRESETDBGN_MASK 0x10

/* ARC_FARM_ARC0_AUX_ARC_RST_REQ */
#define ARC_FARM_ARC0_AUX_ARC_RST_REQ_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_RST_REQ_VAL_MASK 0x1

/* ARC_FARM_ARC0_AUX_SRAM_LSB_ADDR */
#define ARC_FARM_ARC0_AUX_SRAM_LSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_SRAM_LSB_ADDR_VAL_MASK 0x3F

/* ARC_FARM_ARC0_AUX_SRAM_MSB_ADDR */
#define ARC_FARM_ARC0_AUX_SRAM_MSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_SRAM_MSB_ADDR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_PCIE_LSB_ADDR */
#define ARC_FARM_ARC0_AUX_PCIE_LSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_PCIE_LSB_ADDR_VAL_MASK 0xF

/* ARC_FARM_ARC0_AUX_PCIE_MSB_ADDR */
#define ARC_FARM_ARC0_AUX_PCIE_MSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_PCIE_MSB_ADDR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CFG_LSB_ADDR */
#define ARC_FARM_ARC0_AUX_CFG_LSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CFG_LSB_ADDR_VAL_MASK 0xF

/* ARC_FARM_ARC0_AUX_CFG_MSB_ADDR */
#define ARC_FARM_ARC0_AUX_CFG_MSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CFG_MSB_ADDR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_HBM0_LSB_ADDR */
#define ARC_FARM_ARC0_AUX_HBM0_LSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_HBM0_LSB_ADDR_VAL_MASK 0xF

/* ARC_FARM_ARC0_AUX_HBM0_MSB_ADDR */
#define ARC_FARM_ARC0_AUX_HBM0_MSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_HBM0_MSB_ADDR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_HBM1_LSB_ADDR */
#define ARC_FARM_ARC0_AUX_HBM1_LSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_HBM1_LSB_ADDR_VAL_MASK 0xF

/* ARC_FARM_ARC0_AUX_HBM1_MSB_ADDR */
#define ARC_FARM_ARC0_AUX_HBM1_MSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_HBM1_MSB_ADDR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_HBM2_LSB_ADDR */
#define ARC_FARM_ARC0_AUX_HBM2_LSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_HBM2_LSB_ADDR_VAL_MASK 0xF

/* ARC_FARM_ARC0_AUX_HBM2_MSB_ADDR */
#define ARC_FARM_ARC0_AUX_HBM2_MSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_HBM2_MSB_ADDR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_HBM3_LSB_ADDR */
#define ARC_FARM_ARC0_AUX_HBM3_LSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_HBM3_LSB_ADDR_VAL_MASK 0xF

/* ARC_FARM_ARC0_AUX_HBM3_MSB_ADDR */
#define ARC_FARM_ARC0_AUX_HBM3_MSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_HBM3_MSB_ADDR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_HBM0_OFFSET */
#define ARC_FARM_ARC0_AUX_HBM0_OFFSET_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_HBM0_OFFSET_VAL_MASK 0xFFFFFFF

/* ARC_FARM_ARC0_AUX_HBM1_OFFSET */
#define ARC_FARM_ARC0_AUX_HBM1_OFFSET_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_HBM1_OFFSET_VAL_MASK 0xFFFFFFF

/* ARC_FARM_ARC0_AUX_HBM2_OFFSET */
#define ARC_FARM_ARC0_AUX_HBM2_OFFSET_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_HBM2_OFFSET_VAL_MASK 0xFFFFFFF

/* ARC_FARM_ARC0_AUX_HBM3_OFFSET */
#define ARC_FARM_ARC0_AUX_HBM3_OFFSET_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_HBM3_OFFSET_VAL_MASK 0xFFFFFFF

/* ARC_FARM_ARC0_AUX_GENERAL_PURPOSE_LSB_ADDR */
#define ARC_FARM_ARC0_AUX_GENERAL_PURPOSE_LSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_GENERAL_PURPOSE_LSB_ADDR_VAL_MASK 0xF

/* ARC_FARM_ARC0_AUX_GENERAL_PURPOSE_MSB_ADDR */
#define ARC_FARM_ARC0_AUX_GENERAL_PURPOSE_MSB_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_GENERAL_PURPOSE_MSB_ADDR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_ARC_CBU_AWCACHE_OVR */
#define ARC_FARM_ARC0_AUX_ARC_CBU_AWCACHE_OVR_AXI_WRITE_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_CBU_AWCACHE_OVR_AXI_WRITE_MASK 0xF
#define ARC_FARM_ARC0_AUX_ARC_CBU_AWCACHE_OVR_AXI_WRITE_EN_SHIFT 4
#define ARC_FARM_ARC0_AUX_ARC_CBU_AWCACHE_OVR_AXI_WRITE_EN_MASK 0xF0

/* ARC_FARM_ARC0_AUX_ARC_LBU_AWCACHE_OVR */
#define ARC_FARM_ARC0_AUX_ARC_LBU_AWCACHE_OVR_AXI_WRITE_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_LBU_AWCACHE_OVR_AXI_WRITE_MASK 0xF
#define ARC_FARM_ARC0_AUX_ARC_LBU_AWCACHE_OVR_AXI_WRITE_EN_SHIFT 4
#define ARC_FARM_ARC0_AUX_ARC_LBU_AWCACHE_OVR_AXI_WRITE_EN_MASK 0xF0

/* ARC_FARM_ARC0_AUX_CONTEXT_ID */
#define ARC_FARM_ARC0_AUX_CONTEXT_ID_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CONTEXT_ID_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CID_OFFSET */
#define ARC_FARM_ARC0_AUX_CID_OFFSET_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CID_OFFSET_VAL_MASK 0xFF

/* ARC_FARM_ARC0_AUX_SW_INTR */
#define ARC_FARM_ARC0_AUX_SW_INTR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_SW_INTR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_IRQ_INTR_MASK */
#define ARC_FARM_ARC0_AUX_IRQ_INTR_MASK_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_IRQ_INTR_MASK_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_ARC_SEI_INTR_STS */
#define ARC_FARM_ARC0_AUX_ARC_SEI_INTR_STS_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_SEI_INTR_STS_VAL_MASK 0x3FFF

/* ARC_FARM_ARC0_AUX_ARC_SEI_INTR_CLR */
#define ARC_FARM_ARC0_AUX_ARC_SEI_INTR_CLR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_SEI_INTR_CLR_VAL_MASK 0x3FFF

/* ARC_FARM_ARC0_AUX_ARC_SEI_INTR_MASK */
#define ARC_FARM_ARC0_AUX_ARC_SEI_INTR_MASK_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_SEI_INTR_MASK_VAL_MASK 0x3FFF

/* ARC_FARM_ARC0_AUX_ARC_EXCPTN_CAUSE */
#define ARC_FARM_ARC0_AUX_ARC_EXCPTN_CAUSE_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_EXCPTN_CAUSE_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_SEI_INTR_HALT_EN */
#define ARC_FARM_ARC0_AUX_SEI_INTR_HALT_EN_INTR_EN_SHIFT 0
#define ARC_FARM_ARC0_AUX_SEI_INTR_HALT_EN_INTR_EN_MASK 0x1
#define ARC_FARM_ARC0_AUX_SEI_INTR_HALT_EN_HALT_EN_SHIFT 1
#define ARC_FARM_ARC0_AUX_SEI_INTR_HALT_EN_HALT_EN_MASK 0x2

/* ARC_FARM_ARC0_AUX_ARC_SEI_INTR_HALT_MASK */
#define ARC_FARM_ARC0_AUX_ARC_SEI_INTR_HALT_MASK_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_SEI_INTR_HALT_MASK_VAL_MASK 0x3FFF

/* ARC_FARM_ARC0_AUX_QMAN_SEI_INTR_HALT_MASK */
#define ARC_FARM_ARC0_AUX_QMAN_SEI_INTR_HALT_MASK_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_QMAN_SEI_INTR_HALT_MASK_VAL_MASK 0x3FFF

/* ARC_FARM_ARC0_AUX_ARC_REI_INTR_STS */
#define ARC_FARM_ARC0_AUX_ARC_REI_INTR_STS_SERR_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REI_INTR_STS_SERR_MASK 0x1
#define ARC_FARM_ARC0_AUX_ARC_REI_INTR_STS_DERR_SHIFT 1
#define ARC_FARM_ARC0_AUX_ARC_REI_INTR_STS_DERR_MASK 0x2

/* ARC_FARM_ARC0_AUX_ARC_REI_INTR_CLR */
#define ARC_FARM_ARC0_AUX_ARC_REI_INTR_CLR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REI_INTR_CLR_VAL_MASK 0x3

/* ARC_FARM_ARC0_AUX_ARC_REI_INTR_MASK */
#define ARC_FARM_ARC0_AUX_ARC_REI_INTR_MASK_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REI_INTR_MASK_VAL_MASK 0x3

/* ARC_FARM_ARC0_AUX_DCCM_ECC_ERR_ADDR */
#define ARC_FARM_ARC0_AUX_DCCM_ECC_ERR_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_ECC_ERR_ADDR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_DCCM_ECC_SYNDROME */
#define ARC_FARM_ARC0_AUX_DCCM_ECC_SYNDROME_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_ECC_SYNDROME_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_I_CACHE_ECC_ERR_ADDR */
#define ARC_FARM_ARC0_AUX_I_CACHE_ECC_ERR_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_I_CACHE_ECC_ERR_ADDR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_I_CACHE_ECC_SYNDROME */
#define ARC_FARM_ARC0_AUX_I_CACHE_ECC_SYNDROME_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_I_CACHE_ECC_SYNDROME_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_D_CACHE_ECC_ERR_ADDR */
#define ARC_FARM_ARC0_AUX_D_CACHE_ECC_ERR_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_D_CACHE_ECC_ERR_ADDR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_D_CACHE_ECC_SYNDROME */
#define ARC_FARM_ARC0_AUX_D_CACHE_ECC_SYNDROME_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_D_CACHE_ECC_SYNDROME_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_LBW_TRMINATE_AWADDR_ERR */
#define ARC_FARM_ARC0_AUX_LBW_TRMINATE_AWADDR_ERR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBW_TRMINATE_AWADDR_ERR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_LBW_TRMINATE_ARADDR_ERR */
#define ARC_FARM_ARC0_AUX_LBW_TRMINATE_ARADDR_ERR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBW_TRMINATE_ARADDR_ERR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CFG_LBW_TERMINATE_BRESP */
#define ARC_FARM_ARC0_AUX_CFG_LBW_TERMINATE_BRESP_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CFG_LBW_TERMINATE_BRESP_VAL_MASK 0x3

/* ARC_FARM_ARC0_AUX_CFG_LBW_TERMINATE_RRESP */
#define ARC_FARM_ARC0_AUX_CFG_LBW_TERMINATE_RRESP_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CFG_LBW_TERMINATE_RRESP_VAL_MASK 0x3

/* ARC_FARM_ARC0_AUX_CFG_LBW_TERMINATE_AXLEN */
#define ARC_FARM_ARC0_AUX_CFG_LBW_TERMINATE_AXLEN_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CFG_LBW_TERMINATE_AXLEN_VAL_MASK 0xFF

/* ARC_FARM_ARC0_AUX_CFG_LBW_TERMINATE_AXSIZE */
#define ARC_FARM_ARC0_AUX_CFG_LBW_TERMINATE_AXSIZE_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CFG_LBW_TERMINATE_AXSIZE_VAL_MASK 0x7

/* ARC_FARM_ARC0_AUX_SCRATCHPAD */
#define ARC_FARM_ARC0_AUX_SCRATCHPAD_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_SCRATCHPAD_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_TOTAL_CBU_WR_CNT */
#define ARC_FARM_ARC0_AUX_TOTAL_CBU_WR_CNT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_TOTAL_CBU_WR_CNT_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_INFLIGHT_CBU_WR_CNT */
#define ARC_FARM_ARC0_AUX_INFLIGHT_CBU_WR_CNT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_INFLIGHT_CBU_WR_CNT_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_TOTAL_CBU_RD_CNT */
#define ARC_FARM_ARC0_AUX_TOTAL_CBU_RD_CNT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_TOTAL_CBU_RD_CNT_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_INFLIGHT_CBU_RD_CNT */
#define ARC_FARM_ARC0_AUX_INFLIGHT_CBU_RD_CNT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_INFLIGHT_CBU_RD_CNT_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_TOTAL_LBU_WR_CNT */
#define ARC_FARM_ARC0_AUX_TOTAL_LBU_WR_CNT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_TOTAL_LBU_WR_CNT_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_INFLIGHT_LBU_WR_CNT */
#define ARC_FARM_ARC0_AUX_INFLIGHT_LBU_WR_CNT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_INFLIGHT_LBU_WR_CNT_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_TOTAL_LBU_RD_CNT */
#define ARC_FARM_ARC0_AUX_TOTAL_LBU_RD_CNT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_TOTAL_LBU_RD_CNT_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_INFLIGHT_LBU_RD_CNT */
#define ARC_FARM_ARC0_AUX_INFLIGHT_LBU_RD_CNT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_INFLIGHT_LBU_RD_CNT_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_ARUSER_OVR */
#define ARC_FARM_ARC0_AUX_CBU_ARUSER_OVR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_ARUSER_OVR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_ARUSER_OVR_EN */
#define ARC_FARM_ARC0_AUX_CBU_ARUSER_OVR_EN_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_ARUSER_OVR_EN_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_AWUSER_OVR */
#define ARC_FARM_ARC0_AUX_CBU_AWUSER_OVR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_AWUSER_OVR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_AWUSER_OVR_EN */
#define ARC_FARM_ARC0_AUX_CBU_AWUSER_OVR_EN_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_AWUSER_OVR_EN_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_ARUSER_MSB_OVR */
#define ARC_FARM_ARC0_AUX_CBU_ARUSER_MSB_OVR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_ARUSER_MSB_OVR_VAL_MASK 0x3FF

/* ARC_FARM_ARC0_AUX_CBU_ARUSER_MSB_OVR_EN */
#define ARC_FARM_ARC0_AUX_CBU_ARUSER_MSB_OVR_EN_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_ARUSER_MSB_OVR_EN_VAL_MASK 0x3FF

/* ARC_FARM_ARC0_AUX_CBU_AWUSER_MSB_OVR */
#define ARC_FARM_ARC0_AUX_CBU_AWUSER_MSB_OVR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_AWUSER_MSB_OVR_VAL_MASK 0x3FF

/* ARC_FARM_ARC0_AUX_CBU_AWUSER_MSB_OVR_EN */
#define ARC_FARM_ARC0_AUX_CBU_AWUSER_MSB_OVR_EN_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_AWUSER_MSB_OVR_EN_VAL_MASK 0x3FF

/* ARC_FARM_ARC0_AUX_CBU_AXCACHE_OVR */
#define ARC_FARM_ARC0_AUX_CBU_AXCACHE_OVR_CBU_READ_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_AXCACHE_OVR_CBU_READ_MASK 0xF
#define ARC_FARM_ARC0_AUX_CBU_AXCACHE_OVR_CBU_WRITE_SHIFT 4
#define ARC_FARM_ARC0_AUX_CBU_AXCACHE_OVR_CBU_WRITE_MASK 0xF0
#define ARC_FARM_ARC0_AUX_CBU_AXCACHE_OVR_CBU_RD_EN_SHIFT 8
#define ARC_FARM_ARC0_AUX_CBU_AXCACHE_OVR_CBU_RD_EN_MASK 0xF00
#define ARC_FARM_ARC0_AUX_CBU_AXCACHE_OVR_CBU_WR_EN_SHIFT 12
#define ARC_FARM_ARC0_AUX_CBU_AXCACHE_OVR_CBU_WR_EN_MASK 0xF000

/* ARC_FARM_ARC0_AUX_CBU_LOCK_OVR */
#define ARC_FARM_ARC0_AUX_CBU_LOCK_OVR_CBU_READ_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_LOCK_OVR_CBU_READ_MASK 0x3
#define ARC_FARM_ARC0_AUX_CBU_LOCK_OVR_CBU_WRITE_SHIFT 4
#define ARC_FARM_ARC0_AUX_CBU_LOCK_OVR_CBU_WRITE_MASK 0x30
#define ARC_FARM_ARC0_AUX_CBU_LOCK_OVR_CBU_RD_EN_SHIFT 8
#define ARC_FARM_ARC0_AUX_CBU_LOCK_OVR_CBU_RD_EN_MASK 0x300
#define ARC_FARM_ARC0_AUX_CBU_LOCK_OVR_CBU_WR_EN_SHIFT 12
#define ARC_FARM_ARC0_AUX_CBU_LOCK_OVR_CBU_WR_EN_MASK 0x3000

/* ARC_FARM_ARC0_AUX_CBU_PROT_OVR */
#define ARC_FARM_ARC0_AUX_CBU_PROT_OVR_CBU_READ_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_PROT_OVR_CBU_READ_MASK 0x7
#define ARC_FARM_ARC0_AUX_CBU_PROT_OVR_CBU_WRITE_SHIFT 4
#define ARC_FARM_ARC0_AUX_CBU_PROT_OVR_CBU_WRITE_MASK 0x70
#define ARC_FARM_ARC0_AUX_CBU_PROT_OVR_CBU_RD_EN_SHIFT 8
#define ARC_FARM_ARC0_AUX_CBU_PROT_OVR_CBU_RD_EN_MASK 0x700
#define ARC_FARM_ARC0_AUX_CBU_PROT_OVR_CBU_WR_EN_SHIFT 12
#define ARC_FARM_ARC0_AUX_CBU_PROT_OVR_CBU_WR_EN_MASK 0x7000

/* ARC_FARM_ARC0_AUX_CBU_MAX_OUTSTANDING */
#define ARC_FARM_ARC0_AUX_CBU_MAX_OUTSTANDING_CBU_READ_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_MAX_OUTSTANDING_CBU_READ_MASK 0xFF
#define ARC_FARM_ARC0_AUX_CBU_MAX_OUTSTANDING_CBU_WRITE_SHIFT 8
#define ARC_FARM_ARC0_AUX_CBU_MAX_OUTSTANDING_CBU_WRITE_MASK 0xFF00

/* ARC_FARM_ARC0_AUX_CBU_EARLY_BRESP_EN */
#define ARC_FARM_ARC0_AUX_CBU_EARLY_BRESP_EN_CBU_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_EARLY_BRESP_EN_CBU_VAL_MASK 0x1

/* ARC_FARM_ARC0_AUX_CBU_FORCE_RSP_OK */
#define ARC_FARM_ARC0_AUX_CBU_FORCE_RSP_OK_CBU_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORCE_RSP_OK_CBU_VAL_MASK 0x1

/* ARC_FARM_ARC0_AUX_CBU_NO_WR_INFLIGHT */
#define ARC_FARM_ARC0_AUX_CBU_NO_WR_INFLIGHT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_NO_WR_INFLIGHT_VAL_MASK 0x1

/* ARC_FARM_ARC0_AUX_CBU_SEI_INTR_ID */
#define ARC_FARM_ARC0_AUX_CBU_SEI_INTR_ID_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_SEI_INTR_ID_VAL_MASK 0x7F

/* ARC_FARM_ARC0_AUX_LBU_ARUSER_OVR */
#define ARC_FARM_ARC0_AUX_LBU_ARUSER_OVR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBU_ARUSER_OVR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_LBU_ARUSER_OVR_EN */
#define ARC_FARM_ARC0_AUX_LBU_ARUSER_OVR_EN_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBU_ARUSER_OVR_EN_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_LBU_AWUSER_OVR */
#define ARC_FARM_ARC0_AUX_LBU_AWUSER_OVR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBU_AWUSER_OVR_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_LBU_AWUSER_OVR_EN */
#define ARC_FARM_ARC0_AUX_LBU_AWUSER_OVR_EN_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBU_AWUSER_OVR_EN_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_LBU_AXCACHE_OVR */
#define ARC_FARM_ARC0_AUX_LBU_AXCACHE_OVR_LBU_READ_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBU_AXCACHE_OVR_LBU_READ_MASK 0xF
#define ARC_FARM_ARC0_AUX_LBU_AXCACHE_OVR_LBU_WRITE_SHIFT 4
#define ARC_FARM_ARC0_AUX_LBU_AXCACHE_OVR_LBU_WRITE_MASK 0xF0
#define ARC_FARM_ARC0_AUX_LBU_AXCACHE_OVR_LBU_RD_EN_SHIFT 8
#define ARC_FARM_ARC0_AUX_LBU_AXCACHE_OVR_LBU_RD_EN_MASK 0xF00
#define ARC_FARM_ARC0_AUX_LBU_AXCACHE_OVR_LBU_WR_EN_SHIFT 12
#define ARC_FARM_ARC0_AUX_LBU_AXCACHE_OVR_LBU_WR_EN_MASK 0xF000

/* ARC_FARM_ARC0_AUX_LBU_LOCK_OVR */
#define ARC_FARM_ARC0_AUX_LBU_LOCK_OVR_LBU_READ_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBU_LOCK_OVR_LBU_READ_MASK 0x3
#define ARC_FARM_ARC0_AUX_LBU_LOCK_OVR_LBU_WRITE_SHIFT 4
#define ARC_FARM_ARC0_AUX_LBU_LOCK_OVR_LBU_WRITE_MASK 0x30
#define ARC_FARM_ARC0_AUX_LBU_LOCK_OVR_LBU_RD_EN_SHIFT 8
#define ARC_FARM_ARC0_AUX_LBU_LOCK_OVR_LBU_RD_EN_MASK 0x300
#define ARC_FARM_ARC0_AUX_LBU_LOCK_OVR_LBU_WR_EN_SHIFT 12
#define ARC_FARM_ARC0_AUX_LBU_LOCK_OVR_LBU_WR_EN_MASK 0x3000

/* ARC_FARM_ARC0_AUX_LBU_PROT_OVR */
#define ARC_FARM_ARC0_AUX_LBU_PROT_OVR_LBU_READ_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBU_PROT_OVR_LBU_READ_MASK 0x7
#define ARC_FARM_ARC0_AUX_LBU_PROT_OVR_LBU_WRITE_SHIFT 4
#define ARC_FARM_ARC0_AUX_LBU_PROT_OVR_LBU_WRITE_MASK 0x70
#define ARC_FARM_ARC0_AUX_LBU_PROT_OVR_LBU_RD_EN_SHIFT 8
#define ARC_FARM_ARC0_AUX_LBU_PROT_OVR_LBU_RD_EN_MASK 0x700
#define ARC_FARM_ARC0_AUX_LBU_PROT_OVR_LBU_WR_EN_SHIFT 12
#define ARC_FARM_ARC0_AUX_LBU_PROT_OVR_LBU_WR_EN_MASK 0x7000

/* ARC_FARM_ARC0_AUX_LBU_MAX_OUTSTANDING */
#define ARC_FARM_ARC0_AUX_LBU_MAX_OUTSTANDING_LBU_READ_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBU_MAX_OUTSTANDING_LBU_READ_MASK 0xFF
#define ARC_FARM_ARC0_AUX_LBU_MAX_OUTSTANDING_LBU_WRITE_SHIFT 8
#define ARC_FARM_ARC0_AUX_LBU_MAX_OUTSTANDING_LBU_WRITE_MASK 0xFF00

/* ARC_FARM_ARC0_AUX_LBU_EARLY_BRESP_EN */
#define ARC_FARM_ARC0_AUX_LBU_EARLY_BRESP_EN_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBU_EARLY_BRESP_EN_VAL_MASK 0x1

/* ARC_FARM_ARC0_AUX_LBU_FORCE_RSP_OK */
#define ARC_FARM_ARC0_AUX_LBU_FORCE_RSP_OK_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBU_FORCE_RSP_OK_VAL_MASK 0x1

/* ARC_FARM_ARC0_AUX_LBU_NO_WR_INFLIGHT */
#define ARC_FARM_ARC0_AUX_LBU_NO_WR_INFLIGHT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBU_NO_WR_INFLIGHT_VAL_MASK 0x1

/* ARC_FARM_ARC0_AUX_LBU_SEI_INTR_ID */
#define ARC_FARM_ARC0_AUX_LBU_SEI_INTR_ID_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBU_SEI_INTR_ID_VAL_MASK 0x3FF

/* ARC_FARM_ARC0_AUX_DCCM_QUEUE_BASE_ADDR */
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_BASE_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_BASE_ADDR_VAL_MASK 0xFFFFFF

/* ARC_FARM_ARC0_AUX_DCCM_QUEUE_SIZE */
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_SIZE_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_SIZE_VAL_MASK 0xFFFFFF

/* ARC_FARM_ARC0_AUX_DCCM_QUEUE_PI */
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_PI_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_PI_VAL_MASK 0xFFFFFF

/* ARC_FARM_ARC0_AUX_DCCM_QUEUE_CI */
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_CI_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_CI_VAL_MASK 0xFFFFFF

/* ARC_FARM_ARC0_AUX_DCCM_QUEUE_PUSH_REG */
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_PUSH_REG_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_PUSH_REG_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_DCCM_QUEUE_MAX_OCCUPANCY */
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_MAX_OCCUPANCY_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_MAX_OCCUPANCY_VAL_MASK 0xFFFFFF

/* ARC_FARM_ARC0_AUX_DCCM_QUEUE_VALID_ENTRIES */
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_VALID_ENTRIES_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_VALID_ENTRIES_VAL_MASK 0xFFFFFF

/* ARC_FARM_ARC0_AUX_GENERAL_Q_VLD_ENTRY_MASK */
#define ARC_FARM_ARC0_AUX_GENERAL_Q_VLD_ENTRY_MASK_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_GENERAL_Q_VLD_ENTRY_MASK_VAL_MASK 0xFF

/* ARC_FARM_ARC0_AUX_NIC_Q_VLD_ENTRY_MASK */
#define ARC_FARM_ARC0_AUX_NIC_Q_VLD_ENTRY_MASK_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_NIC_Q_VLD_ENTRY_MASK_VAL_MASK 0xFF

/* ARC_FARM_ARC0_AUX_DCCM_QUEUE_DROP_EN */
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_DROP_EN_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_DROP_EN_VAL_MASK 0x1

/* ARC_FARM_ARC0_AUX_DCCM_QUEUE_WARN_MSG */
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_WARN_MSG_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_WARN_MSG_VAL_MASK 0xFFFF

/* ARC_FARM_ARC0_AUX_DCCM_QUEUE_ALERT_MSG */
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_ALERT_MSG_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_QUEUE_ALERT_MSG_VAL_MASK 0xFFFF

/* ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWPROT */
#define ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWPROT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWPROT_VAL_MASK 0x7

/* ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWUSER */
#define ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWUSER_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWUSER_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWBURST */
#define ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWBURST_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWBURST_VAL_MASK 0x3

/* ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWLOCK */
#define ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWLOCK_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWLOCK_VAL_MASK 0x1

/* ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWCACHE */
#define ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWCACHE_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_GEN_AXI_AWCACHE_VAL_MASK 0xF

/* ARC_FARM_ARC0_AUX_DCCM_WRR_ARB_WEIGHT */
#define ARC_FARM_ARC0_AUX_DCCM_WRR_ARB_WEIGHT_LBW_SLV_AXI_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_WRR_ARB_WEIGHT_LBW_SLV_AXI_MASK 0xF
#define ARC_FARM_ARC0_AUX_DCCM_WRR_ARB_WEIGHT_GEN_AXI_SHIFT 4
#define ARC_FARM_ARC0_AUX_DCCM_WRR_ARB_WEIGHT_GEN_AXI_MASK 0xF0

/* ARC_FARM_ARC0_AUX_DCCM_Q_PUSH_FIFO_FULL_CFG */
#define ARC_FARM_ARC0_AUX_DCCM_Q_PUSH_FIFO_FULL_CFG_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_Q_PUSH_FIFO_FULL_CFG_VAL_MASK 0x1F

/* ARC_FARM_ARC0_AUX_DCCM_Q_PUSH_FIFO_CNT */
#define ARC_FARM_ARC0_AUX_DCCM_Q_PUSH_FIFO_CNT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_Q_PUSH_FIFO_CNT_VAL_MASK 0x1F

/* ARC_FARM_ARC0_AUX_QMAN_CQ_IFIFO_SHADOW_CI */
#define ARC_FARM_ARC0_AUX_QMAN_CQ_IFIFO_SHADOW_CI_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_QMAN_CQ_IFIFO_SHADOW_CI_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_QMAN_ARC_CQ_IFIFO_SHADOW_CI */
#define ARC_FARM_ARC0_AUX_QMAN_ARC_CQ_IFIFO_SHADOW_CI_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_QMAN_ARC_CQ_IFIFO_SHADOW_CI_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_QMAN_CQ_SHADOW_CI */
#define ARC_FARM_ARC0_AUX_QMAN_CQ_SHADOW_CI_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_QMAN_CQ_SHADOW_CI_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_QMAN_ARC_CQ_SHADOW_CI */
#define ARC_FARM_ARC0_AUX_QMAN_ARC_CQ_SHADOW_CI_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_QMAN_ARC_CQ_SHADOW_CI_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_AUX2APB_PROT */
#define ARC_FARM_ARC0_AUX_AUX2APB_PROT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_AUX2APB_PROT_VAL_MASK 0x7

/* ARC_FARM_ARC0_AUX_LBW_FORK_WIN_EN */
#define ARC_FARM_ARC0_AUX_LBW_FORK_WIN_EN_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBW_FORK_WIN_EN_VAL_MASK 0x3

/* ARC_FARM_ARC0_AUX_QMAN_LBW_FORK_BASE_ADDR0 */
#define ARC_FARM_ARC0_AUX_QMAN_LBW_FORK_BASE_ADDR0_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_QMAN_LBW_FORK_BASE_ADDR0_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_QMAN_LBW_FORK_ADDR_MASK0 */
#define ARC_FARM_ARC0_AUX_QMAN_LBW_FORK_ADDR_MASK0_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_QMAN_LBW_FORK_ADDR_MASK0_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_QMAN_LBW_FORK_BASE_ADDR1 */
#define ARC_FARM_ARC0_AUX_QMAN_LBW_FORK_BASE_ADDR1_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_QMAN_LBW_FORK_BASE_ADDR1_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_QMAN_LBW_FORK_ADDR_MASK1 */
#define ARC_FARM_ARC0_AUX_QMAN_LBW_FORK_ADDR_MASK1_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_QMAN_LBW_FORK_ADDR_MASK1_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_FARM_LBW_FORK_BASE_ADDR0 */
#define ARC_FARM_ARC0_AUX_FARM_LBW_FORK_BASE_ADDR0_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_FARM_LBW_FORK_BASE_ADDR0_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_FARM_LBW_FORK_ADDR_MASK0 */
#define ARC_FARM_ARC0_AUX_FARM_LBW_FORK_ADDR_MASK0_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_FARM_LBW_FORK_ADDR_MASK0_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_FARM_LBW_FORK_BASE_ADDR1 */
#define ARC_FARM_ARC0_AUX_FARM_LBW_FORK_BASE_ADDR1_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_FARM_LBW_FORK_BASE_ADDR1_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_FARM_LBW_FORK_ADDR_MASK1 */
#define ARC_FARM_ARC0_AUX_FARM_LBW_FORK_ADDR_MASK1_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_FARM_LBW_FORK_ADDR_MASK1_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_LBW_APB_FORK_MAX_ADDR0 */
#define ARC_FARM_ARC0_AUX_LBW_APB_FORK_MAX_ADDR0_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBW_APB_FORK_MAX_ADDR0_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_LBW_APB_FORK_MAX_ADDR1 */
#define ARC_FARM_ARC0_AUX_LBW_APB_FORK_MAX_ADDR1_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_LBW_APB_FORK_MAX_ADDR1_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_ARC_ACC_ENGS_LBW_FORK_MASK */
#define ARC_FARM_ARC0_AUX_ARC_ACC_ENGS_LBW_FORK_MASK_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_ACC_ENGS_LBW_FORK_MASK_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_ARC_DUP_ENG_LBW_FORK_ADDR */
#define ARC_FARM_ARC0_AUX_ARC_DUP_ENG_LBW_FORK_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_DUP_ENG_LBW_FORK_ADDR_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_ARC_ACP_ENG_LBW_FORK_ADDR */
#define ARC_FARM_ARC0_AUX_ARC_ACP_ENG_LBW_FORK_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_ACP_ENG_LBW_FORK_ADDR_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_ARC_ACC_ENGS_VIRTUAL_ADDR */
#define ARC_FARM_ARC0_AUX_ARC_ACC_ENGS_VIRTUAL_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_ACC_ENGS_VIRTUAL_ADDR_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_WIN_EN */
#define ARC_FARM_ARC0_AUX_CBU_FORK_WIN_EN_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_WIN_EN_VAL_MASK 0xF

/* ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR0_LSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR0_LSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR0_LSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR0_MSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR0_MSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR0_MSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK0_LSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK0_LSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK0_LSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK0_MSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK0_MSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK0_MSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR1_LSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR1_LSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR1_LSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR1_MSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR1_MSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR1_MSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK1_LSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK1_LSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK1_LSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK1_MSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK1_MSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK1_MSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR2_LSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR2_LSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR2_LSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR2_MSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR2_MSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR2_MSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK2_LSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK2_LSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK2_LSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK2_MSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK2_MSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK2_MSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR3_LSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR3_LSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR3_LSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR3_MSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR3_MSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_BASE_ADDR3_MSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK3_LSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK3_LSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK3_LSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK3_MSB */
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK3_MSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_FORK_ADDR_MASK3_MSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_TRMINATE_ARADDR_LSB */
#define ARC_FARM_ARC0_AUX_CBU_TRMINATE_ARADDR_LSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_TRMINATE_ARADDR_LSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CBU_TRMINATE_ARADDR_MSB */
#define ARC_FARM_ARC0_AUX_CBU_TRMINATE_ARADDR_MSB_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CBU_TRMINATE_ARADDR_MSB_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_CFG_CBU_TERMINATE_BRESP */
#define ARC_FARM_ARC0_AUX_CFG_CBU_TERMINATE_BRESP_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CFG_CBU_TERMINATE_BRESP_VAL_MASK 0x3

/* ARC_FARM_ARC0_AUX_CFG_CBU_TERMINATE_RRESP */
#define ARC_FARM_ARC0_AUX_CFG_CBU_TERMINATE_RRESP_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CFG_CBU_TERMINATE_RRESP_VAL_MASK 0x3

/* ARC_FARM_ARC0_AUX_ARC_REGION_CFG */
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_0_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_0_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_1_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_1_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_2_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_2_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_3_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_3_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_4_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_4_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_5_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_5_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_6_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_6_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_7_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_7_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_8_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_8_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_9_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_9_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_10_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_10_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_11_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_11_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_12_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_12_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_13_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_13_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_14_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_14_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_15_ASID_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_15_ASID_MASK 0x3FF
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_MMU_BP_SHIFT 12
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_MMU_BP_MASK 0x1000
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_PROT_VAL_SHIFT 16
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_PROT_VAL_MASK 0x70000
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_PROT_VAL_EN_SHIFT 20
#define ARC_FARM_ARC0_AUX_ARC_REGION_CFG_PROT_VAL_EN_MASK 0x700000

/* ARC_FARM_ARC0_AUX_DCCM_TRMINATE_AWADDR_ERR */
#define ARC_FARM_ARC0_AUX_DCCM_TRMINATE_AWADDR_ERR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_TRMINATE_AWADDR_ERR_VAL_MASK 0xFFFFFF

/* ARC_FARM_ARC0_AUX_DCCM_TRMINATE_ARADDR_ERR */
#define ARC_FARM_ARC0_AUX_DCCM_TRMINATE_ARADDR_ERR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_DCCM_TRMINATE_ARADDR_ERR_VAL_MASK 0xFFFFFF

/* ARC_FARM_ARC0_AUX_CFG_DCCM_TERMINATE_BRESP */
#define ARC_FARM_ARC0_AUX_CFG_DCCM_TERMINATE_BRESP_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CFG_DCCM_TERMINATE_BRESP_VAL_MASK 0x3

/* ARC_FARM_ARC0_AUX_CFG_DCCM_TERMINATE_RRESP */
#define ARC_FARM_ARC0_AUX_CFG_DCCM_TERMINATE_RRESP_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CFG_DCCM_TERMINATE_RRESP_VAL_MASK 0x3

/* ARC_FARM_ARC0_AUX_CFG_DCCM_TERMINATE_EN */
#define ARC_FARM_ARC0_AUX_CFG_DCCM_TERMINATE_EN_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CFG_DCCM_TERMINATE_EN_VAL_MASK 0x1

/* ARC_FARM_ARC0_AUX_CFG_DCCM_SECURE_REGION */
#define ARC_FARM_ARC0_AUX_CFG_DCCM_SECURE_REGION_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_CFG_DCCM_SECURE_REGION_VAL_MASK 0xFFFFFF

/* ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_WR_IF_CNT */
#define ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_WR_IF_CNT_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_WR_IF_CNT_VAL_MASK 0xFFFFFFFF

/* ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_CTL */
#define ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_CTL_ENABLE_BP_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_CTL_ENABLE_BP_MASK 0x1
#define ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_CTL_RD_DELAY_CC_SHIFT 1
#define ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_CTL_RD_DELAY_CC_MASK 0x3E

/* ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_ADDR_MSK */
#define ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_ADDR_MSK_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_ADDR_MSK_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_ADDR */
#define ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_ADDR_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_AXI_ORDERING_ADDR_VAL_MASK 0x7FFFFFF

/* ARC_FARM_ARC0_AUX_ARC_ACC_ENGS_BUSER */
#define ARC_FARM_ARC0_AUX_ARC_ACC_ENGS_BUSER_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_ARC_ACC_ENGS_BUSER_VAL_MASK 0x3

/* ARC_FARM_ARC0_AUX_MME_ARC_UPPER_DCCM_EN */
#define ARC_FARM_ARC0_AUX_MME_ARC_UPPER_DCCM_EN_VAL_SHIFT 0
#define ARC_FARM_ARC0_AUX_MME_ARC_UPPER_DCCM_EN_VAL_MASK 0x1

#endif /* ASIC_REG_ARC_FARM_ARC0_AUX_MASKS_H_ */
