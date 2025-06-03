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

#ifndef ASIC_REG_NIC0_TMR_REGS_H_
#define ASIC_REG_NIC0_TMR_REGS_H_

/*
 *****************************************
 *   NIC0_TMR (Prototype: NIC_TMR)
 *****************************************
 */

#define mmNIC0_TMR_TMR_PUSH_MASK                                     0xCF5000

#define mmNIC0_TMR_TMR_POP_MASK                                      0xCF5004

#define mmNIC0_TMR_TMR_PUSH_RELEASE_INVALIDATE                       0xCF5008

#define mmNIC0_TMR_TMR_POP_RELEASE_INVALIDATE                        0xCF500C

#define mmNIC0_TMR_TMR_LIST_MEM_READ_MASK                            0xCF5010

#define mmNIC0_TMR_TMR_FIFO_MEM_READ_MASK                            0xCF5014

#define mmNIC0_TMR_TMR_LIST_MEM_WRITE_MASK                           0xCF5018

#define mmNIC0_TMR_TMR_FIFO_MEM_WRITE_MASK                           0xCF501C

#define mmNIC0_TMR_TMR_BASE_ADDRESS_49_18                            0xCF5020

#define mmNIC0_TMR_TMR_BASE_ADDRESS_17_7                             0xCF5024

#define mmNIC0_TMR_TMR_LIST_AXI_USER                                 0xCF5028

#define mmNIC0_TMR_TMR_LIST_AXI_PROT                                 0xCF502C

#define mmNIC0_TMR_TMR_STATE_AXI_USER                                0xCF5030

#define mmNIC0_TMR_TMR_STATE_AXI_PROT                                0xCF5034

#define mmNIC0_TMR_TMR_SCHEDQ_UPDATE_EN                              0xCF503C

#define mmNIC0_TMR_TMR_SCHEDQ_UPDATE_FIFO                            0xCF5040

#define mmNIC0_TMR_TMR_SCHEDQ_UPDATE_DESC_31_0                       0xCF5044

#define mmNIC0_TMR_TMR_SCHEDQ_UPDATE_DESC_63_32                      0xCF5048

#define mmNIC0_TMR_TMR_SCHEDQ_UPDATE_DESC_95_64                      0xCF504C

#define mmNIC0_TMR_TMR_SCHEDQ_UPDATE_DESC_127_96                     0xCF5050

#define mmNIC0_TMR_TMR_SCHEDQ_UPDATE_DESC_159_128                    0xCF5054

#define mmNIC0_TMR_TMR_SCHEDQ_UPDATE_DESC_191_160                    0xCF5058

#define mmNIC0_TMR_TMR_SCHEDQ_UPDATE_DESC_216_192                    0xCF505C

#define mmNIC0_TMR_TMR_FORCE_HIT_EN                                  0xCF5060

#define mmNIC0_TMR_TMR_INVALIDATE_LIST                               0xCF5064

#define mmNIC0_TMR_TMR_INVALIDATE_LIST_STAT                          0xCF5068

#define mmNIC0_TMR_TMR_INVALIDATE_FREE                               0xCF506C

#define mmNIC0_TMR_TMR_INVALIDATE_FREE_STAT                          0xCF5070

#define mmNIC0_TMR_TMR_PUSH_PREFETCH_EN                              0xCF5074

#define mmNIC0_TMR_TMR_PUSH_RELEASE_EN                               0xCF5078

#define mmNIC0_TMR_TMR_PUSH_LOCK_EN                                  0xCF507C

#define mmNIC0_TMR_TMR_PUSH_PREFETCH_NEXT_EN                         0xCF5080

#define mmNIC0_TMR_TMR_POP_PREFETCH_EN                               0xCF5084

#define mmNIC0_TMR_TMR_POP_RELEASE_EN                                0xCF5088

#define mmNIC0_TMR_TMR_POP_LOCK_EN                                   0xCF508C

#define mmNIC0_TMR_TMR_POP_PREFETCH_NEXT_EN                          0xCF5090

#define mmNIC0_TMR_TMR_LIST_MASK                                     0xCF5094

#define mmNIC0_TMR_TMR_RELEASE_INCALIDATE                            0xCF5098

#define mmNIC0_TMR_TMR_BASE_ADDRESS_FREE_LIST_49_32                  0xCF509C

#define mmNIC0_TMR_TMR_BASE_ADDRESS_FREE_LIST_31_0                   0xCF50A0

#define mmNIC0_TMR_TMR_FREE_LIST_EN                                  0xCF50A4

#define mmNIC0_TMR_TMR_PUSH_FORCE_HIT_EN                             0xCF50A8

#define mmNIC0_TMR_TMR_PRODUCER_UPDATE_EN                            0xCF50AC

#define mmNIC0_TMR_TMR_PRODUCER_UPDATE                               0xCF50B0

#define mmNIC0_TMR_TMR_CAHE_INVALIDATE                               0xCF50B4

#define mmNIC0_TMR_TMR_CAHE_INVALIDATE_STAT                          0xCF50B8

#define mmNIC0_TMR_TMR_CACHE_CLEAR_LINK_LIST                         0xCF50BC

#define mmNIC0_TMR_TMR_CACHE_CFG                                     0xCF50C0

#define mmNIC0_TMR_TMR_CACHE_BASE_ADDR_49_32                         0xCF50C4

#define mmNIC0_TMR_TMR_CACHE_BASE_ADDR_31_7                          0xCF50C8

#define mmNIC0_TMR_TMR_TIMER_EN                                      0xCF50CC

#define mmNIC0_TMR_TMR_TICK_WRAP                                     0xCF50D0

#define mmNIC0_TMR_TMR_SCAN_TIMER_COMP_47_32                         0xCF50D4

#define mmNIC0_TMR_TMR_SCAN_TIMER_COMP_31_0                          0xCF50D8

#define mmNIC0_TMR_TMR_SCHEDQS_0                                     0xCF50DC

#define mmNIC0_TMR_TMR_SCHEDQS_1                                     0xCF50E0

#define mmNIC0_TMR_TMR_SCHEDQS_2                                     0xCF50E4

#define mmNIC0_TMR_TMR_SCHEDQS_3                                     0xCF50E8

#define mmNIC0_TMR_TMR_CACHES_CFG                                    0xCF50EC

#define mmNIC0_TMR_TMR_DBG_COUNT_SELECT_0                            0xCF50F0

#define mmNIC0_TMR_TMR_DBG_COUNT_SELECT_1                            0xCF50F4

#define mmNIC0_TMR_TMR_DBG_COUNT_SELECT_2                            0xCF50F8

#define mmNIC0_TMR_TMR_DBG_COUNT_SELECT_3                            0xCF50FC

#define mmNIC0_TMR_TMR_DBG_COUNT_SELECT_4                            0xCF5100

#define mmNIC0_TMR_TMR_DBG_COUNT_SELECT_5                            0xCF5104

#define mmNIC0_TMR_TMR_DBG_COUNT_SELECT_6                            0xCF5108

#define mmNIC0_TMR_TMR_DBG_COUNT_SELECT_7                            0xCF510C

#define mmNIC0_TMR_TMR_DBG_COUNT_SELECT_8                            0xCF5110

#define mmNIC0_TMR_TMR_DBG_COUNT_SELECT_9                            0xCF5114

#define mmNIC0_TMR_TMR_DBG_COUNT_SELECT_10                           0xCF5118

#define mmNIC0_TMR_TMR_DBG_COUNT_SELECT_11                           0xCF511C

#define mmNIC0_TMR_TMR_POP_CACHE_CREDIT                              0xCF5138

#define mmNIC0_TMR_TMR_PIPE_CREDIT                                   0xCF513C

#define mmNIC0_TMR_TMR_DBG_TRIG                                      0xCF5140

#define mmNIC0_TMR_INTERRUPT_CAUSE                                   0xCF5144

#define mmNIC0_TMR_INTERRUPT_MASK                                    0xCF5148

#define mmNIC0_TMR_INTERRUPT_CLR                                     0xCF514C

#define mmNIC0_TMR_TRM_SLICE_CREDIT                                  0xCF5150

#define mmNIC0_TMR_TMR_AXI_CACHE                                     0xCF5154

#define mmNIC0_TMR_FREE_LIST_PUSH_MASK_EN                            0xCF5158

#define mmNIC0_TMR_FREE_AEMPTY_THRESHOLD                             0xCF515C

#endif /* ASIC_REG_NIC0_TMR_REGS_H_ */
