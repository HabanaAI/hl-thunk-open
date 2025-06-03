/* SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2018 HabanaLabs, Ltd.
 * All Rights Reserved.
 *
 */

/************************************
 ** This is an auto-generated file **
 **       DO NOT EDIT BELOW        **
 ************************************/

#ifndef ASIC_REG_NIC0_RXE0_REGS_H_
#define ASIC_REG_NIC0_RXE0_REGS_H_

/*
 *****************************************
 *   NIC0_RXE0 (Prototype: NIC_RXE)
 *****************************************
 */

#define mmNIC0_RXE0_CONTROL                                          0xCE9000

#define mmNIC0_RXE0_LBW_BASE_LO                                      0xCE9004

#define mmNIC0_RXE0_LBW_BASE_HI                                      0xCE9008

#define mmNIC0_RXE0_PKT_DROP                                         0xCE900C

#define mmNIC0_RXE0_RAW_QPN_P0_0                                     0xCE9010

#define mmNIC0_RXE0_RAW_QPN_P0_1                                     0xCE9014

#define mmNIC0_RXE0_RAW_BASE_LO_P0_0                                 0xCE9020

#define mmNIC0_RXE0_RAW_BASE_LO_P0_1                                 0xCE9024

#define mmNIC0_RXE0_RAW_BASE_HI_P0_0                                 0xCE9030

#define mmNIC0_RXE0_RAW_BASE_HI_P0_1                                 0xCE9034

#define mmNIC0_RXE0_RAW_QPN_P1_0                                     0xCE9040

#define mmNIC0_RXE0_RAW_QPN_P1_1                                     0xCE9044

#define mmNIC0_RXE0_RAW_BASE_LO_P1_0                                 0xCE9050

#define mmNIC0_RXE0_RAW_BASE_LO_P1_1                                 0xCE9054

#define mmNIC0_RXE0_RAW_BASE_HI_P1_0                                 0xCE9060

#define mmNIC0_RXE0_RAW_BASE_HI_P1_1                                 0xCE9064

#define mmNIC0_RXE0_RAW_QPN_P2_0                                     0xCE9070

#define mmNIC0_RXE0_RAW_QPN_P2_1                                     0xCE9074

#define mmNIC0_RXE0_RAW_BASE_LO_P2_0                                 0xCE9080

#define mmNIC0_RXE0_RAW_BASE_LO_P2_1                                 0xCE9084

#define mmNIC0_RXE0_RAW_BASE_HI_P2_0                                 0xCE9090

#define mmNIC0_RXE0_RAW_BASE_HI_P2_1                                 0xCE9094

#define mmNIC0_RXE0_RAW_QPN_P3_0                                     0xCE90A0

#define mmNIC0_RXE0_RAW_QPN_P3_1                                     0xCE90A4

#define mmNIC0_RXE0_RAW_BASE_LO_P3_0                                 0xCE90B0

#define mmNIC0_RXE0_RAW_BASE_LO_P3_1                                 0xCE90B4

#define mmNIC0_RXE0_RAW_BASE_HI_P3_0                                 0xCE90C0

#define mmNIC0_RXE0_RAW_BASE_HI_P3_1                                 0xCE90C4

#define mmNIC0_RXE0_DBG_INV_OP_0                                     0xCE90D0

#define mmNIC0_RXE0_DBG_INV_OP_1                                     0xCE90D4

#define mmNIC0_RXE0_DBG_AXI_ERR                                      0xCE90D8

#define mmNIC0_RXE0_ARUSER_HBW_10_0                                  0xCE90E0

#define mmNIC0_RXE0_ARUSER_HBW_31_11                                 0xCE90E4

#define mmNIC0_RXE0_AWUSER_LBW_10_0                                  0xCE90E8

#define mmNIC0_RXE0_AWUSER_LBW_31_11                                 0xCE90EC

#define mmNIC0_RXE0_ARPROT_HBW                                       0xCE90F0

#define mmNIC0_RXE0_AWPROT_LBW                                       0xCE90F4

#define mmNIC0_RXE0_WIN0_WQ_BASE_LO                                  0xCE9100

#define mmNIC0_RXE0_WIN0_WQ_BASE_HI                                  0xCE9104

#define mmNIC0_RXE0_WIN1_WQ_BASE_LO                                  0xCE9108

#define mmNIC0_RXE0_WIN1_WQ_BASE_HI                                  0xCE910C

#define mmNIC0_RXE0_WIN2_WQ_BASE_LO                                  0xCE9110

#define mmNIC0_RXE0_WIN2_WQ_BASE_HI                                  0xCE9114

#define mmNIC0_RXE0_WIN3_WQ_BASE_LO                                  0xCE9118

#define mmNIC0_RXE0_WIN3_WQ_BASE_HI                                  0xCE911C

#define mmNIC0_RXE0_WQ_BASE_WINDOW_SEL                               0xCE9120

#define mmNIC0_RXE0_SEI_CAUSE                                        0xCE9140

#define mmNIC0_RXE0_SEI_MASK                                         0xCE9144

#define mmNIC0_RXE0_SPI_CAUSE                                        0xCE9150

#define mmNIC0_RXE0_SPI_MASK                                         0xCE9154

#define mmNIC0_RXE0_CQ_CFG0                                          0xCE9158

#define mmNIC0_RXE0_CQ_CFG1                                          0xCE915C

#define mmNIC0_RXE0_CQ_BASE_ADDR_31_7                                0xCE9160

#define mmNIC0_RXE0_CA_BASE_ADDR_49_32                               0xCE9180

#define mmNIC0_RXE0_CQ_WRITE_INDEX                                   0xCE91A0

#define mmNIC0_RXE0_CQ_PRODUCER_INDEX                                0xCE91C0

#define mmNIC0_RXE0_CQ_CONSUMER_INDEX                                0xCE91E0

#define mmNIC0_RXE0_CQ_MASK                                          0xCE9200

#define mmNIC0_RXE0_CQ_INTER_MODERATION_EN                           0xCE9220

#define mmNIC0_RXE0_CQ_INTER_MODERATION_CNT                          0xCE9240

#define mmNIC0_RXE0_CQ_MSI_CAUSE_CLR                                 0xCE9260

#define mmNIC0_RXE0_CQ_MSI_ADDR_0                                    0xCE9270

#define mmNIC0_RXE0_CQ_MSI_ADDR_1                                    0xCE9274

#define mmNIC0_RXE0_CQ_MSI_DATA_0                                    0xCE92B0

#define mmNIC0_RXE0_CQ_MSI_DATA_1                                    0xCE92B4

#define mmNIC0_RXE0_CQ_MSI_TRUSTED                                   0xCE92F0

#define mmNIC0_RXE0_MSI_CAUSE                                        0xCE92F4

#define mmNIC0_RXE0_MSI_CASUE_MASK                                   0xCE92F8

#endif /* ASIC_REG_NIC0_RXE0_REGS_H_ */
