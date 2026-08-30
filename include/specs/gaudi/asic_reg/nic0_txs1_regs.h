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

#ifndef ASIC_REG_NIC0_TXS1_REGS_H_
#define ASIC_REG_NIC0_TXS1_REGS_H_

/*
 *****************************************
 *   NIC0_TXS1 (Prototype: NIC_TXS)
 *****************************************
 */

#define mmNIC0_TXS1_TMR_SCAN_EN                                      0xCF1000

#define mmNIC0_TXS1_TICK_WRAP                                        0xCF1004

#define mmNIC0_TXS1_SCAN_TIME_COMPARE_0                              0xCF1008

#define mmNIC0_TXS1_SCAN_TIME_COMPARE_1                              0xCF100C

#define mmNIC0_TXS1_SLICE_CREDIT                                     0xCF1010

#define mmNIC0_TXS1_SLICE_FORCE_FULL                                 0xCF1014

#define mmNIC0_TXS1_FIRST_SCHEDQ_ID                                  0xCF1018

#define mmNIC0_TXS1_LAST_SCHEDQ_ID                                   0xCF101C

#define mmNIC0_TXS1_PUSH_MASK                                        0xCF1020

#define mmNIC0_TXS1_POP_MASK                                         0xCF1024

#define mmNIC0_TXS1_PUSH_RELEASE_INVALIDATE                          0xCF1028

#define mmNIC0_TXS1_POP_RELEASE_INVALIDATE                           0xCF102C

#define mmNIC0_TXS1_LIST_MEM_READ_MASK                               0xCF1030

#define mmNIC0_TXS1_FIFO_MEM_READ_MASK                               0xCF1034

#define mmNIC0_TXS1_LIST_MEM_WRITE_MASK                              0xCF1038

#define mmNIC0_TXS1_FIFO_MEM_WRITE_MASK                              0xCF103C

#define mmNIC0_TXS1_BASE_ADDRESS_49_18                               0xCF1040

#define mmNIC0_TXS1_BASE_ADDRESS_17_7                                0xCF1044

#define mmNIC0_TXS1_AXI_USER                                         0xCF1048

#define mmNIC0_TXS1_AXI_PROT                                         0xCF104C

#define mmNIC0_TXS1_RATE_LIMIT                                       0xCF1050

#define mmNIC0_TXS1_CACHE_CFG                                        0xCF1054

#define mmNIC0_TXS1_SCHEDQ_UPDATE_EN                                 0xCF105C

#define mmNIC0_TXS1_SCHEDQ_UPDATE_FIFO                               0xCF1060

#define mmNIC0_TXS1_SCHEDQ_UPDATE_DESC_31_0                          0xCF1064

#define mmNIC0_TXS1_SCHEDQ_UPDATE_DESC_63_32                         0xCF1068

#define mmNIC0_TXS1_SCHEDQ_UPDATE_DESC_95_64                         0xCF106C

#define mmNIC0_TXS1_SCHEDQ_UPDATE_DESC_127_96                        0xCF1070

#define mmNIC0_TXS1_SCHEDQ_UPDATE_DESC_159_128                       0xCF1074

#define mmNIC0_TXS1_SCHEDQ_UPDATE_DESC_191_160                       0xCF1078

#define mmNIC0_TXS1_SCHEDQ_UPDATE_DESC_217_192                       0xCF107C

#define mmNIC0_TXS1_FORCE_HIT_EN                                     0xCF1080

#define mmNIC0_TXS1_INVALIDATE_LIST                                  0xCF1084

#define mmNIC0_TXS1_INVALIDATE_LIST_STATUS                           0xCF1088

#define mmNIC0_TXS1_INVALIDATE_FREE_LIST                             0xCF108C

#define mmNIC0_TXS1_INVALIDATE_FREE_LIST_STAT                        0xCF1090

#define mmNIC0_TXS1_PUSH_PREFETCH_EN                                 0xCF1094

#define mmNIC0_TXS1_PUSH_RELEASE_EN                                  0xCF1098

#define mmNIC0_TXS1_PUSH_LOCK_EN                                     0xCF109C

#define mmNIC0_TXS1_PUSH_PREFETCH_NEXT_EN                            0xCF10A0

#define mmNIC0_TXS1_POP_PREFETCH_EN                                  0xCF10A4

#define mmNIC0_TXS1_POP_RELEASE_EN                                   0xCF10A8

#define mmNIC0_TXS1_POP_LOCK_EN                                      0xCF10AC

#define mmNIC0_TXS1_POP_PREFETCH_NEXT_EN                             0xCF10B0

#define mmNIC0_TXS1_LIST_MASK                                        0xCF10B4

#define mmNIC0_TXS1_RELEASE_INCALIDATE                               0xCF10B8

#define mmNIC0_TXS1_BASE_ADDRESS_FREE_LIST_49_32                     0xCF10BC

#define mmNIC0_TXS1_BASE_ADDRESS_FREE_LIST_31_0                      0xCF10C0

#define mmNIC0_TXS1_FREE_LIST_EN                                     0xCF10C4

#define mmNIC0_TXS1_PUSH_FORCE_HIT_EN                                0xCF10C8

#define mmNIC0_TXS1_PRODUCER_UPDATE_EN                               0xCF10CC

#define mmNIC0_TXS1_PRODUCER_UPDATE                                  0xCF10D0

#define mmNIC0_TXS1_PRIOQ_CREDIT_FORCE                               0xCF10D4

#define mmNIC0_TXS1_PRIOQ_CREDIT_0                                   0xCF10D8

#define mmNIC0_TXS1_PRIOQ_CREDIT_1                                   0xCF10DC

#define mmNIC0_TXS1_PRIOQ_CREDIT_2                                   0xCF10E0

#define mmNIC0_TXS1_PRIOQ_CREDIT_3                                   0xCF10E4

#define mmNIC0_TXS1_PRIOQ_CREDIT_4                                   0xCF10E8

#define mmNIC0_TXS1_PRIOQ_CREDIT_5                                   0xCF10EC

#define mmNIC0_TXS1_PRIOQ_CREDIT_6                                   0xCF10F0

#define mmNIC0_TXS1_PRIOQ_CREDIT_7                                   0xCF10F4

#define mmNIC0_TXS1_DBG_COUNT_SELECT_0                               0xCF10F8

#define mmNIC0_TXS1_DBG_COUNT_SELECT_1                               0xCF10FC

#define mmNIC0_TXS1_DBG_COUNT_SELECT_2                               0xCF1100

#define mmNIC0_TXS1_DBG_COUNT_SELECT_3                               0xCF1104

#define mmNIC0_TXS1_DBG_COUNT_SELECT_4                               0xCF1108

#define mmNIC0_TXS1_DBG_COUNT_SELECT_5                               0xCF110C

#define mmNIC0_TXS1_DBG_COUNT_SELECT_6                               0xCF1110

#define mmNIC0_TXS1_DBG_COUNT_SELECT_7                               0xCF1114

#define mmNIC0_TXS1_DBG_COUNT_SELECT_8                               0xCF1118

#define mmNIC0_TXS1_DBG_COUNT_SELECT_9                               0xCF111C

#define mmNIC0_TXS1_DBG_COUNT_SELECT_10                              0xCF1120

#define mmNIC0_TXS1_DBG_COUNT_SELECT_11                              0xCF1124

#define mmNIC0_TXS1_IGNORE_BURST_EN                                  0xCF1140

#define mmNIC0_TXS1_IGNORE_BURST_THRESHOLD_0                         0xCF1144

#define mmNIC0_TXS1_IGNORE_BURST_THRESHOLD_1                         0xCF1148

#define mmNIC0_TXS1_IGNORE_BURST_THRESHOLD_2                         0xCF114C

#define mmNIC0_TXS1_IGNORE_BURST_THRESHOLD_3                         0xCF1150

#define mmNIC0_TXS1_IGNORE_BURST_THRESHOLD_4                         0xCF1154

#define mmNIC0_TXS1_IGNORE_BURST_THRESHOLD_5                         0xCF1158

#define mmNIC0_TXS1_IGNORE_BURST_THRESHOLD_6                         0xCF115C

#define mmNIC0_TXS1_IGNORE_BURST_THRESHOLD_7                         0xCF1160

#define mmNIC0_TXS1_RANDOM_PSUH_CFG                                  0xCF1164

#define mmNIC0_TXS1_DBG_HW_EVENT_TRIGER                              0xCF1168

#define mmNIC0_TXS1_INTERRUPT_CAUSE                                  0xCF116C

#define mmNIC0_TXS1_INTERRUPT_MASK                                   0xCF1170

#define mmNIC0_TXS1_INTERRUPT_CLR                                    0xCF1174

#define mmNIC0_TXS1_LOAD_SLICE_HIT_EN                                0xCF1178

#define mmNIC0_TXS1_SLICE_ACTIVE_47_32                               0xCF117C

#define mmNIC0_TXS1_SLICE_ACTIVE_31_0                                0xCF1180

#define mmNIC0_TXS1_AXI_CACHE                                        0xCF1184

#define mmNIC0_TXS1_SLICE_GW_ADDR                                    0xCF1188

#define mmNIC0_TXS1_SLICE_GW_DATA                                    0xCF118C

#define mmNIC0_TXS1_SCANNER_CREDIT_EN                                0xCF1190

#define mmNIC0_TXS1_FREE_LIST_PUSH_MASK_EN                           0xCF1194

#define mmNIC0_TXS1_FREE_AEMPTY_THRESHOLD                            0xCF1198

#endif /* ASIC_REG_NIC0_TXS1_REGS_H_ */
