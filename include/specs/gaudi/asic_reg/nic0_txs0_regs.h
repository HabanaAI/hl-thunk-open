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

#ifndef ASIC_REG_NIC0_TXS0_REGS_H_
#define ASIC_REG_NIC0_TXS0_REGS_H_

/*
 *****************************************
 *   NIC0_TXS0 (Prototype: NIC_TXS)
 *****************************************
 */

#define mmNIC0_TXS0_TMR_SCAN_EN                                      0xCF0000

#define mmNIC0_TXS0_TICK_WRAP                                        0xCF0004

#define mmNIC0_TXS0_SCAN_TIME_COMPARE_0                              0xCF0008

#define mmNIC0_TXS0_SCAN_TIME_COMPARE_1                              0xCF000C

#define mmNIC0_TXS0_SLICE_CREDIT                                     0xCF0010

#define mmNIC0_TXS0_SLICE_FORCE_FULL                                 0xCF0014

#define mmNIC0_TXS0_FIRST_SCHEDQ_ID                                  0xCF0018

#define mmNIC0_TXS0_LAST_SCHEDQ_ID                                   0xCF001C

#define mmNIC0_TXS0_PUSH_MASK                                        0xCF0020

#define mmNIC0_TXS0_POP_MASK                                         0xCF0024

#define mmNIC0_TXS0_PUSH_RELEASE_INVALIDATE                          0xCF0028

#define mmNIC0_TXS0_POP_RELEASE_INVALIDATE                           0xCF002C

#define mmNIC0_TXS0_LIST_MEM_READ_MASK                               0xCF0030

#define mmNIC0_TXS0_FIFO_MEM_READ_MASK                               0xCF0034

#define mmNIC0_TXS0_LIST_MEM_WRITE_MASK                              0xCF0038

#define mmNIC0_TXS0_FIFO_MEM_WRITE_MASK                              0xCF003C

#define mmNIC0_TXS0_BASE_ADDRESS_49_18                               0xCF0040

#define mmNIC0_TXS0_BASE_ADDRESS_17_7                                0xCF0044

#define mmNIC0_TXS0_AXI_USER                                         0xCF0048

#define mmNIC0_TXS0_AXI_PROT                                         0xCF004C

#define mmNIC0_TXS0_RATE_LIMIT                                       0xCF0050

#define mmNIC0_TXS0_CACHE_CFG                                        0xCF0054

#define mmNIC0_TXS0_SCHEDQ_UPDATE_EN                                 0xCF005C

#define mmNIC0_TXS0_SCHEDQ_UPDATE_FIFO                               0xCF0060

#define mmNIC0_TXS0_SCHEDQ_UPDATE_DESC_31_0                          0xCF0064

#define mmNIC0_TXS0_SCHEDQ_UPDATE_DESC_63_32                         0xCF0068

#define mmNIC0_TXS0_SCHEDQ_UPDATE_DESC_95_64                         0xCF006C

#define mmNIC0_TXS0_SCHEDQ_UPDATE_DESC_127_96                        0xCF0070

#define mmNIC0_TXS0_SCHEDQ_UPDATE_DESC_159_128                       0xCF0074

#define mmNIC0_TXS0_SCHEDQ_UPDATE_DESC_191_160                       0xCF0078

#define mmNIC0_TXS0_SCHEDQ_UPDATE_DESC_217_192                       0xCF007C

#define mmNIC0_TXS0_FORCE_HIT_EN                                     0xCF0080

#define mmNIC0_TXS0_INVALIDATE_LIST                                  0xCF0084

#define mmNIC0_TXS0_INVALIDATE_LIST_STATUS                           0xCF0088

#define mmNIC0_TXS0_INVALIDATE_FREE_LIST                             0xCF008C

#define mmNIC0_TXS0_INVALIDATE_FREE_LIST_STAT                        0xCF0090

#define mmNIC0_TXS0_PUSH_PREFETCH_EN                                 0xCF0094

#define mmNIC0_TXS0_PUSH_RELEASE_EN                                  0xCF0098

#define mmNIC0_TXS0_PUSH_LOCK_EN                                     0xCF009C

#define mmNIC0_TXS0_PUSH_PREFETCH_NEXT_EN                            0xCF00A0

#define mmNIC0_TXS0_POP_PREFETCH_EN                                  0xCF00A4

#define mmNIC0_TXS0_POP_RELEASE_EN                                   0xCF00A8

#define mmNIC0_TXS0_POP_LOCK_EN                                      0xCF00AC

#define mmNIC0_TXS0_POP_PREFETCH_NEXT_EN                             0xCF00B0

#define mmNIC0_TXS0_LIST_MASK                                        0xCF00B4

#define mmNIC0_TXS0_RELEASE_INCALIDATE                               0xCF00B8

#define mmNIC0_TXS0_BASE_ADDRESS_FREE_LIST_49_32                     0xCF00BC

#define mmNIC0_TXS0_BASE_ADDRESS_FREE_LIST_31_0                      0xCF00C0

#define mmNIC0_TXS0_FREE_LIST_EN                                     0xCF00C4

#define mmNIC0_TXS0_PUSH_FORCE_HIT_EN                                0xCF00C8

#define mmNIC0_TXS0_PRODUCER_UPDATE_EN                               0xCF00CC

#define mmNIC0_TXS0_PRODUCER_UPDATE                                  0xCF00D0

#define mmNIC0_TXS0_PRIOQ_CREDIT_FORCE                               0xCF00D4

#define mmNIC0_TXS0_PRIOQ_CREDIT_0                                   0xCF00D8

#define mmNIC0_TXS0_PRIOQ_CREDIT_1                                   0xCF00DC

#define mmNIC0_TXS0_PRIOQ_CREDIT_2                                   0xCF00E0

#define mmNIC0_TXS0_PRIOQ_CREDIT_3                                   0xCF00E4

#define mmNIC0_TXS0_PRIOQ_CREDIT_4                                   0xCF00E8

#define mmNIC0_TXS0_PRIOQ_CREDIT_5                                   0xCF00EC

#define mmNIC0_TXS0_PRIOQ_CREDIT_6                                   0xCF00F0

#define mmNIC0_TXS0_PRIOQ_CREDIT_7                                   0xCF00F4

#define mmNIC0_TXS0_DBG_COUNT_SELECT_0                               0xCF00F8

#define mmNIC0_TXS0_DBG_COUNT_SELECT_1                               0xCF00FC

#define mmNIC0_TXS0_DBG_COUNT_SELECT_2                               0xCF0100

#define mmNIC0_TXS0_DBG_COUNT_SELECT_3                               0xCF0104

#define mmNIC0_TXS0_DBG_COUNT_SELECT_4                               0xCF0108

#define mmNIC0_TXS0_DBG_COUNT_SELECT_5                               0xCF010C

#define mmNIC0_TXS0_DBG_COUNT_SELECT_6                               0xCF0110

#define mmNIC0_TXS0_DBG_COUNT_SELECT_7                               0xCF0114

#define mmNIC0_TXS0_DBG_COUNT_SELECT_8                               0xCF0118

#define mmNIC0_TXS0_DBG_COUNT_SELECT_9                               0xCF011C

#define mmNIC0_TXS0_DBG_COUNT_SELECT_10                              0xCF0120

#define mmNIC0_TXS0_DBG_COUNT_SELECT_11                              0xCF0124

#define mmNIC0_TXS0_IGNORE_BURST_EN                                  0xCF0140

#define mmNIC0_TXS0_IGNORE_BURST_THRESHOLD_0                         0xCF0144

#define mmNIC0_TXS0_IGNORE_BURST_THRESHOLD_1                         0xCF0148

#define mmNIC0_TXS0_IGNORE_BURST_THRESHOLD_2                         0xCF014C

#define mmNIC0_TXS0_IGNORE_BURST_THRESHOLD_3                         0xCF0150

#define mmNIC0_TXS0_IGNORE_BURST_THRESHOLD_4                         0xCF0154

#define mmNIC0_TXS0_IGNORE_BURST_THRESHOLD_5                         0xCF0158

#define mmNIC0_TXS0_IGNORE_BURST_THRESHOLD_6                         0xCF015C

#define mmNIC0_TXS0_IGNORE_BURST_THRESHOLD_7                         0xCF0160

#define mmNIC0_TXS0_RANDOM_PSUH_CFG                                  0xCF0164

#define mmNIC0_TXS0_DBG_HW_EVENT_TRIGER                              0xCF0168

#define mmNIC0_TXS0_INTERRUPT_CAUSE                                  0xCF016C

#define mmNIC0_TXS0_INTERRUPT_MASK                                   0xCF0170

#define mmNIC0_TXS0_INTERRUPT_CLR                                    0xCF0174

#define mmNIC0_TXS0_LOAD_SLICE_HIT_EN                                0xCF0178

#define mmNIC0_TXS0_SLICE_ACTIVE_47_32                               0xCF017C

#define mmNIC0_TXS0_SLICE_ACTIVE_31_0                                0xCF0180

#define mmNIC0_TXS0_AXI_CACHE                                        0xCF0184

#define mmNIC0_TXS0_SLICE_GW_ADDR                                    0xCF0188

#define mmNIC0_TXS0_SLICE_GW_DATA                                    0xCF018C

#define mmNIC0_TXS0_SCANNER_CREDIT_EN                                0xCF0190

#define mmNIC0_TXS0_FREE_LIST_PUSH_MASK_EN                           0xCF0194

#define mmNIC0_TXS0_FREE_AEMPTY_THRESHOLD                            0xCF0198

#endif /* ASIC_REG_NIC0_TXS0_REGS_H_ */
