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

#ifndef ASIC_REG_NIC0_RXE1_REGS_H_
#define ASIC_REG_NIC0_RXE1_REGS_H_

/*
 *****************************************
 *   NIC0_RXE1 (Prototype: NIC_RXE)
 *****************************************
 */

#define mmNIC0_RXE1_CONTROL                                          0xCEA000

#define mmNIC0_RXE1_LBW_BASE_LO                                      0xCEA004

#define mmNIC0_RXE1_LBW_BASE_HI                                      0xCEA008

#define mmNIC0_RXE1_PKT_DROP                                         0xCEA00C

#define mmNIC0_RXE1_RAW_QPN_P0_0                                     0xCEA010

#define mmNIC0_RXE1_RAW_QPN_P0_1                                     0xCEA014

#define mmNIC0_RXE1_RAW_BASE_LO_P0_0                                 0xCEA020

#define mmNIC0_RXE1_RAW_BASE_LO_P0_1                                 0xCEA024

#define mmNIC0_RXE1_RAW_BASE_HI_P0_0                                 0xCEA030

#define mmNIC0_RXE1_RAW_BASE_HI_P0_1                                 0xCEA034

#define mmNIC0_RXE1_RAW_QPN_P1_0                                     0xCEA040

#define mmNIC0_RXE1_RAW_QPN_P1_1                                     0xCEA044

#define mmNIC0_RXE1_RAW_BASE_LO_P1_0                                 0xCEA050

#define mmNIC0_RXE1_RAW_BASE_LO_P1_1                                 0xCEA054

#define mmNIC0_RXE1_RAW_BASE_HI_P1_0                                 0xCEA060

#define mmNIC0_RXE1_RAW_BASE_HI_P1_1                                 0xCEA064

#define mmNIC0_RXE1_RAW_QPN_P2_0                                     0xCEA070

#define mmNIC0_RXE1_RAW_QPN_P2_1                                     0xCEA074

#define mmNIC0_RXE1_RAW_BASE_LO_P2_0                                 0xCEA080

#define mmNIC0_RXE1_RAW_BASE_LO_P2_1                                 0xCEA084

#define mmNIC0_RXE1_RAW_BASE_HI_P2_0                                 0xCEA090

#define mmNIC0_RXE1_RAW_BASE_HI_P2_1                                 0xCEA094

#define mmNIC0_RXE1_RAW_QPN_P3_0                                     0xCEA0A0

#define mmNIC0_RXE1_RAW_QPN_P3_1                                     0xCEA0A4

#define mmNIC0_RXE1_RAW_BASE_LO_P3_0                                 0xCEA0B0

#define mmNIC0_RXE1_RAW_BASE_LO_P3_1                                 0xCEA0B4

#define mmNIC0_RXE1_RAW_BASE_HI_P3_0                                 0xCEA0C0

#define mmNIC0_RXE1_RAW_BASE_HI_P3_1                                 0xCEA0C4

#define mmNIC0_RXE1_DBG_INV_OP_0                                     0xCEA0D0

#define mmNIC0_RXE1_DBG_INV_OP_1                                     0xCEA0D4

#define mmNIC0_RXE1_DBG_AXI_ERR                                      0xCEA0D8

#define mmNIC0_RXE1_ARUSER_HBW_10_0                                  0xCEA0E0

#define mmNIC0_RXE1_ARUSER_HBW_31_11                                 0xCEA0E4

#define mmNIC0_RXE1_AWUSER_LBW_10_0                                  0xCEA0E8

#define mmNIC0_RXE1_AWUSER_LBW_31_11                                 0xCEA0EC

#define mmNIC0_RXE1_ARPROT_HBW                                       0xCEA0F0

#define mmNIC0_RXE1_AWPROT_LBW                                       0xCEA0F4

#define mmNIC0_RXE1_WIN0_WQ_BASE_LO                                  0xCEA100

#define mmNIC0_RXE1_WIN0_WQ_BASE_HI                                  0xCEA104

#define mmNIC0_RXE1_WIN1_WQ_BASE_LO                                  0xCEA108

#define mmNIC0_RXE1_WIN1_WQ_BASE_HI                                  0xCEA10C

#define mmNIC0_RXE1_WIN2_WQ_BASE_LO                                  0xCEA110

#define mmNIC0_RXE1_WIN2_WQ_BASE_HI                                  0xCEA114

#define mmNIC0_RXE1_WIN3_WQ_BASE_LO                                  0xCEA118

#define mmNIC0_RXE1_WIN3_WQ_BASE_HI                                  0xCEA11C

#define mmNIC0_RXE1_WQ_BASE_WINDOW_SEL                               0xCEA120

#define mmNIC0_RXE1_SEI_CAUSE                                        0xCEA140

#define mmNIC0_RXE1_SEI_MASK                                         0xCEA144

#define mmNIC0_RXE1_SPI_CAUSE                                        0xCEA150

#define mmNIC0_RXE1_SPI_MASK                                         0xCEA154

#define mmNIC0_RXE1_CQ_CFG0                                          0xCEA158

#define mmNIC0_RXE1_CQ_CFG1                                          0xCEA15C

#define mmNIC0_RXE1_CQ_BASE_ADDR_31_7                                0xCEA160

#define mmNIC0_RXE1_CA_BASE_ADDR_49_32                               0xCEA180

#define mmNIC0_RXE1_CQ_WRITE_INDEX                                   0xCEA1A0

#define mmNIC0_RXE1_CQ_PRODUCER_INDEX                                0xCEA1C0

#define mmNIC0_RXE1_CQ_CONSUMER_INDEX                                0xCEA1E0

#define mmNIC0_RXE1_CQ_MASK                                          0xCEA200

#define mmNIC0_RXE1_CQ_INTER_MODERATION_EN                           0xCEA220

#define mmNIC0_RXE1_CQ_INTER_MODERATION_CNT                          0xCEA240

#define mmNIC0_RXE1_CQ_MSI_CAUSE_CLR                                 0xCEA260

#define mmNIC0_RXE1_CQ_MSI_ADDR_0                                    0xCEA270

#define mmNIC0_RXE1_CQ_MSI_ADDR_1                                    0xCEA274

#define mmNIC0_RXE1_CQ_MSI_DATA_0                                    0xCEA2B0

#define mmNIC0_RXE1_CQ_MSI_DATA_1                                    0xCEA2B4

#define mmNIC0_RXE1_CQ_MSI_TRUSTED                                   0xCEA2F0

#define mmNIC0_RXE1_MSI_CAUSE                                        0xCEA2F4

#define mmNIC0_RXE1_MSI_CASUE_MASK                                   0xCEA2F8

#endif /* ASIC_REG_NIC0_RXE1_REGS_H_ */
