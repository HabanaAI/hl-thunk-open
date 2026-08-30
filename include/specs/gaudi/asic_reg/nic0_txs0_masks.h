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

#ifndef ASIC_REG_NIC0_TXS0_MASKS_H_
#define ASIC_REG_NIC0_TXS0_MASKS_H_

/*
 *****************************************
 *   NIC0_TXS0 (Prototype: NIC_TXS)
 *****************************************
 */

/* NIC0_TXS0_TMR_SCAN_EN */
#define NIC0_TXS0_TMR_SCAN_EN_R_SHIFT                                0
#define NIC0_TXS0_TMR_SCAN_EN_R_MASK                                 0x1

/* NIC0_TXS0_TICK_WRAP */
#define NIC0_TXS0_TICK_WRAP_R_SHIFT                                  0
#define NIC0_TXS0_TICK_WRAP_R_MASK                                   0xFFFF

/* NIC0_TXS0_SCAN_TIME_COMPARE_0 */
#define NIC0_TXS0_SCAN_TIME_COMPARE_0_R_SHIFT                        0
#define NIC0_TXS0_SCAN_TIME_COMPARE_0_R_MASK                         0xFFFFFFFF

/* NIC0_TXS0_SCAN_TIME_COMPARE_1 */
#define NIC0_TXS0_SCAN_TIME_COMPARE_1_R_SHIFT                        0
#define NIC0_TXS0_SCAN_TIME_COMPARE_1_R_MASK                         0xFFFF

/* NIC0_TXS0_SLICE_CREDIT */
#define NIC0_TXS0_SLICE_CREDIT_R_SHIFT                               0
#define NIC0_TXS0_SLICE_CREDIT_R_MASK                                0x3F

/* NIC0_TXS0_SLICE_FORCE_FULL */
#define NIC0_TXS0_SLICE_FORCE_FULL_R_SHIFT                           0
#define NIC0_TXS0_SLICE_FORCE_FULL_R_MASK                            0x1

/* NIC0_TXS0_FIRST_SCHEDQ_ID */
#define NIC0_TXS0_FIRST_SCHEDQ_ID_R0_SHIFT                           0
#define NIC0_TXS0_FIRST_SCHEDQ_ID_R0_MASK                            0xFF
#define NIC0_TXS0_FIRST_SCHEDQ_ID_R1_SHIFT                           8
#define NIC0_TXS0_FIRST_SCHEDQ_ID_R1_MASK                            0xFF00
#define NIC0_TXS0_FIRST_SCHEDQ_ID_R2_SHIFT                           16
#define NIC0_TXS0_FIRST_SCHEDQ_ID_R2_MASK                            0xFF0000
#define NIC0_TXS0_FIRST_SCHEDQ_ID_R3_SHIFT                           24
#define NIC0_TXS0_FIRST_SCHEDQ_ID_R3_MASK                            0xFF000000

/* NIC0_TXS0_LAST_SCHEDQ_ID */
#define NIC0_TXS0_LAST_SCHEDQ_ID_R0_SHIFT                            0
#define NIC0_TXS0_LAST_SCHEDQ_ID_R0_MASK                             0xFF
#define NIC0_TXS0_LAST_SCHEDQ_ID_R1_SHIFT                            8
#define NIC0_TXS0_LAST_SCHEDQ_ID_R1_MASK                             0xFF00
#define NIC0_TXS0_LAST_SCHEDQ_ID_R2_SHIFT                            16
#define NIC0_TXS0_LAST_SCHEDQ_ID_R2_MASK                             0xFF0000
#define NIC0_TXS0_LAST_SCHEDQ_ID_R3_SHIFT                            24
#define NIC0_TXS0_LAST_SCHEDQ_ID_R3_MASK                             0xFF000000

/* NIC0_TXS0_PUSH_MASK */
#define NIC0_TXS0_PUSH_MASK_R_SHIFT                                  0
#define NIC0_TXS0_PUSH_MASK_R_MASK                                   0x1

/* NIC0_TXS0_POP_MASK */
#define NIC0_TXS0_POP_MASK_R_SHIFT                                   0
#define NIC0_TXS0_POP_MASK_R_MASK                                    0x1

/* NIC0_TXS0_PUSH_RELEASE_INVALIDATE */
#define NIC0_TXS0_PUSH_RELEASE_INVALIDATE_R_SHIFT                    0
#define NIC0_TXS0_PUSH_RELEASE_INVALIDATE_R_MASK                     0x1

/* NIC0_TXS0_POP_RELEASE_INVALIDATE */
#define NIC0_TXS0_POP_RELEASE_INVALIDATE_R_SHIFT                     0
#define NIC0_TXS0_POP_RELEASE_INVALIDATE_R_MASK                      0x1

/* NIC0_TXS0_LIST_MEM_READ_MASK */
#define NIC0_TXS0_LIST_MEM_READ_MASK_R_SHIFT                         0
#define NIC0_TXS0_LIST_MEM_READ_MASK_R_MASK                          0x1

/* NIC0_TXS0_FIFO_MEM_READ_MASK */
#define NIC0_TXS0_FIFO_MEM_READ_MASK_R_SHIFT                         0
#define NIC0_TXS0_FIFO_MEM_READ_MASK_R_MASK                          0x1

/* NIC0_TXS0_LIST_MEM_WRITE_MASK */
#define NIC0_TXS0_LIST_MEM_WRITE_MASK_R_SHIFT                        0
#define NIC0_TXS0_LIST_MEM_WRITE_MASK_R_MASK                         0x1

/* NIC0_TXS0_FIFO_MEM_WRITE_MASK */
#define NIC0_TXS0_FIFO_MEM_WRITE_MASK_R_SHIFT                        0
#define NIC0_TXS0_FIFO_MEM_WRITE_MASK_R_MASK                         0x1

/* NIC0_TXS0_BASE_ADDRESS_49_18 */
#define NIC0_TXS0_BASE_ADDRESS_49_18_R_SHIFT                         0
#define NIC0_TXS0_BASE_ADDRESS_49_18_R_MASK                          0xFFFFFFFF

/* NIC0_TXS0_BASE_ADDRESS_17_7 */
#define NIC0_TXS0_BASE_ADDRESS_17_7_R_SHIFT                          0
#define NIC0_TXS0_BASE_ADDRESS_17_7_R_MASK                           0x7FF

/* NIC0_TXS0_AXI_USER */
#define NIC0_TXS0_AXI_USER_R_SHIFT                                   0
#define NIC0_TXS0_AXI_USER_R_MASK                                    0xFFFFFFFF

/* NIC0_TXS0_AXI_PROT */
#define NIC0_TXS0_AXI_PROT_R_SHIFT                                   0
#define NIC0_TXS0_AXI_PROT_R_MASK                                    0x7

/* NIC0_TXS0_RATE_LIMIT */
#define NIC0_TXS0_RATE_LIMIT_ALWAYS_EN_SHIFT                         0
#define NIC0_TXS0_RATE_LIMIT_ALWAYS_EN_MASK                          0x1
#define NIC0_TXS0_RATE_LIMIT_IMMEDIATE_SET_SHIFT                     1
#define NIC0_TXS0_RATE_LIMIT_IMMEDIATE_SET_MASK                      0x2

/* NIC0_TXS0_CACHE_CFG */
#define NIC0_TXS0_CACHE_CFG_LIST_PLRU_EVICTION_SHIFT                 0
#define NIC0_TXS0_CACHE_CFG_LIST_PLRU_EVICTION_MASK                  0x1
#define NIC0_TXS0_CACHE_CFG_LIST_CACHE_STOP_SHIFT                    1
#define NIC0_TXS0_CACHE_CFG_LIST_CACHE_STOP_MASK                     0x2
#define NIC0_TXS0_CACHE_CFG_LIST_INV_WRITEBACK_SHIFT                 2
#define NIC0_TXS0_CACHE_CFG_LIST_INV_WRITEBACK_MASK                  0x4
#define NIC0_TXS0_CACHE_CFG_FREE_LIST_PLRU_EVICTION_SHIFT            3
#define NIC0_TXS0_CACHE_CFG_FREE_LIST_PLRU_EVICTION_MASK             0x8
#define NIC0_TXS0_CACHE_CFG_FREE_LIST_CACHE_STOP_SHIFT               4
#define NIC0_TXS0_CACHE_CFG_FREE_LIST_CACHE_STOP_MASK                0x10
#define NIC0_TXS0_CACHE_CFG_FREE_LIST_INV_WRITEBACK_SHIFT            5
#define NIC0_TXS0_CACHE_CFG_FREE_LIST_INV_WRITEBACK_MASK             0x20

/* NIC0_TXS0_SCHEDQ_UPDATE_EN */
#define NIC0_TXS0_SCHEDQ_UPDATE_EN_R_SHIFT                           0
#define NIC0_TXS0_SCHEDQ_UPDATE_EN_R_MASK                            0x1

/* NIC0_TXS0_SCHEDQ_UPDATE_FIFO */
#define NIC0_TXS0_SCHEDQ_UPDATE_FIFO_R_SHIFT                         0
#define NIC0_TXS0_SCHEDQ_UPDATE_FIFO_R_MASK                          0xFF

/* NIC0_TXS0_SCHEDQ_UPDATE_DESC_31_0 */
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_31_0_R_SHIFT                    0
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_31_0_R_MASK                     0xFFFFFFFF

/* NIC0_TXS0_SCHEDQ_UPDATE_DESC_63_32 */
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_63_32_R_SHIFT                   0
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_63_32_R_MASK                    0xFFFFFFFF

/* NIC0_TXS0_SCHEDQ_UPDATE_DESC_95_64 */
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_95_64_R_SHIFT                   0
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_95_64_R_MASK                    0xFFFFFFFF

/* NIC0_TXS0_SCHEDQ_UPDATE_DESC_127_96 */
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_127_96_R_SHIFT                  0
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_127_96_R_MASK                   0xFFFFFFFF

/* NIC0_TXS0_SCHEDQ_UPDATE_DESC_159_128 */
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_159_128_R_SHIFT                 0
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_159_128_R_MASK                  0xFFFFFFFF

/* NIC0_TXS0_SCHEDQ_UPDATE_DESC_191_160 */
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_191_160_R_SHIFT                 0
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_191_160_R_MASK                  0xFFFFFFFF

/* NIC0_TXS0_SCHEDQ_UPDATE_DESC_217_192 */
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_217_192_R_SHIFT                 0
#define NIC0_TXS0_SCHEDQ_UPDATE_DESC_217_192_R_MASK                  0x1FFFFFF

/* NIC0_TXS0_FORCE_HIT_EN */
#define NIC0_TXS0_FORCE_HIT_EN_R_SHIFT                               0
#define NIC0_TXS0_FORCE_HIT_EN_R_MASK                                0x1

/* NIC0_TXS0_INVALIDATE_LIST */

/* NIC0_TXS0_INVALIDATE_LIST_STATUS */
#define NIC0_TXS0_INVALIDATE_LIST_STATUS_INVALIDATE_DONE_SHIFT       0
#define NIC0_TXS0_INVALIDATE_LIST_STATUS_INVALIDATE_DONE_MASK        0x1
#define NIC0_TXS0_INVALIDATE_LIST_STATUS_CACHE_IDLE_SHIFT            1
#define NIC0_TXS0_INVALIDATE_LIST_STATUS_CACHE_IDLE_MASK             0x2

/* NIC0_TXS0_INVALIDATE_FREE_LIST */

/* NIC0_TXS0_INVALIDATE_FREE_LIST_STAT */
#define NIC0_TXS0_INVALIDATE_FREE_LIST_STAT_INVALIDATE_DONE_SHIFT    0
#define NIC0_TXS0_INVALIDATE_FREE_LIST_STAT_INVALIDATE_DONE_MASK     0x1
#define NIC0_TXS0_INVALIDATE_FREE_LIST_STAT_CACHE_IDLE_SHIFT         1
#define NIC0_TXS0_INVALIDATE_FREE_LIST_STAT_CACHE_IDLE_MASK          0x2

/* NIC0_TXS0_PUSH_PREFETCH_EN */
#define NIC0_TXS0_PUSH_PREFETCH_EN_R_SHIFT                           0
#define NIC0_TXS0_PUSH_PREFETCH_EN_R_MASK                            0x1

/* NIC0_TXS0_PUSH_RELEASE_EN */
#define NIC0_TXS0_PUSH_RELEASE_EN_R_SHIFT                            0
#define NIC0_TXS0_PUSH_RELEASE_EN_R_MASK                             0x1

/* NIC0_TXS0_PUSH_LOCK_EN */
#define NIC0_TXS0_PUSH_LOCK_EN_R_SHIFT                               0
#define NIC0_TXS0_PUSH_LOCK_EN_R_MASK                                0x1

/* NIC0_TXS0_PUSH_PREFETCH_NEXT_EN */
#define NIC0_TXS0_PUSH_PREFETCH_NEXT_EN_R_SHIFT                      0
#define NIC0_TXS0_PUSH_PREFETCH_NEXT_EN_R_MASK                       0x1

/* NIC0_TXS0_POP_PREFETCH_EN */
#define NIC0_TXS0_POP_PREFETCH_EN_R_SHIFT                            0
#define NIC0_TXS0_POP_PREFETCH_EN_R_MASK                             0x1

/* NIC0_TXS0_POP_RELEASE_EN */
#define NIC0_TXS0_POP_RELEASE_EN_R_SHIFT                             0
#define NIC0_TXS0_POP_RELEASE_EN_R_MASK                              0x1

/* NIC0_TXS0_POP_LOCK_EN */
#define NIC0_TXS0_POP_LOCK_EN_R_SHIFT                                0
#define NIC0_TXS0_POP_LOCK_EN_R_MASK                                 0x1

/* NIC0_TXS0_POP_PREFETCH_NEXT_EN */
#define NIC0_TXS0_POP_PREFETCH_NEXT_EN_R_SHIFT                       0
#define NIC0_TXS0_POP_PREFETCH_NEXT_EN_R_MASK                        0x1

/* NIC0_TXS0_LIST_MASK */
#define NIC0_TXS0_LIST_MASK_R_SHIFT                                  0
#define NIC0_TXS0_LIST_MASK_R_MASK                                   0x7FFFFFF

/* NIC0_TXS0_RELEASE_INCALIDATE */
#define NIC0_TXS0_RELEASE_INCALIDATE_R_SHIFT                         0
#define NIC0_TXS0_RELEASE_INCALIDATE_R_MASK                          0x1

/* NIC0_TXS0_BASE_ADDRESS_FREE_LIST_49_32 */
#define NIC0_TXS0_BASE_ADDRESS_FREE_LIST_49_32_R_SHIFT               0
#define NIC0_TXS0_BASE_ADDRESS_FREE_LIST_49_32_R_MASK                0x3FFFF

/* NIC0_TXS0_BASE_ADDRESS_FREE_LIST_31_0 */
#define NIC0_TXS0_BASE_ADDRESS_FREE_LIST_31_0_R_SHIFT                0
#define NIC0_TXS0_BASE_ADDRESS_FREE_LIST_31_0_R_MASK                 0xFFFFFFFF

/* NIC0_TXS0_FREE_LIST_EN */
#define NIC0_TXS0_FREE_LIST_EN_R_SHIFT                               0
#define NIC0_TXS0_FREE_LIST_EN_R_MASK                                0x1

/* NIC0_TXS0_PUSH_FORCE_HIT_EN */
#define NIC0_TXS0_PUSH_FORCE_HIT_EN_R_SHIFT                          0
#define NIC0_TXS0_PUSH_FORCE_HIT_EN_R_MASK                           0x1

/* NIC0_TXS0_PRODUCER_UPDATE_EN */
#define NIC0_TXS0_PRODUCER_UPDATE_EN_R_SHIFT                         0
#define NIC0_TXS0_PRODUCER_UPDATE_EN_R_MASK                          0x1

/* NIC0_TXS0_PRODUCER_UPDATE */
#define NIC0_TXS0_PRODUCER_UPDATE_R_SHIFT                            0
#define NIC0_TXS0_PRODUCER_UPDATE_R_MASK                             0xFFFFFFFF

/* NIC0_TXS0_PRIOQ_CREDIT_FORCE */
#define NIC0_TXS0_PRIOQ_CREDIT_FORCE_FORCE_FULL_SHIFT                0
#define NIC0_TXS0_PRIOQ_CREDIT_FORCE_FORCE_FULL_MASK                 0xFF

/* NIC0_TXS0_PRIOQ_CREDIT */
#define NIC0_TXS0_PRIOQ_CREDIT_R_SHIFT                               0
#define NIC0_TXS0_PRIOQ_CREDIT_R_MASK                                0x3F

/* NIC0_TXS0_DBG_COUNT_SELECT */
#define NIC0_TXS0_DBG_COUNT_SELECT_R_SHIFT                           0
#define NIC0_TXS0_DBG_COUNT_SELECT_R_MASK                            0x3F

/* NIC0_TXS0_IGNORE_BURST_EN */
#define NIC0_TXS0_IGNORE_BURST_EN_R_SHIFT                            0
#define NIC0_TXS0_IGNORE_BURST_EN_R_MASK                             0x1

/* NIC0_TXS0_IGNORE_BURST_THRESHOLD */
#define NIC0_TXS0_IGNORE_BURST_THRESHOLD_R_SHIFT                     0
#define NIC0_TXS0_IGNORE_BURST_THRESHOLD_R_MASK                      0x1FFFFFF

/* NIC0_TXS0_RANDOM_PSUH_CFG */
#define NIC0_TXS0_RANDOM_PSUH_CFG_BYPASS_SHIFT                       0
#define NIC0_TXS0_RANDOM_PSUH_CFG_BYPASS_MASK                        0x1
#define NIC0_TXS0_RANDOM_PSUH_CFG_RATE_LIMIT_EN_SHIFT                1
#define NIC0_TXS0_RANDOM_PSUH_CFG_RATE_LIMIT_EN_MASK                 0x2
#define NIC0_TXS0_RANDOM_PSUH_CFG_SATURATION_SHIFT                   2
#define NIC0_TXS0_RANDOM_PSUH_CFG_SATURATION_MASK                    0x3C
#define NIC0_TXS0_RANDOM_PSUH_CFG_RST_TOKEN_SHIFT                    6
#define NIC0_TXS0_RANDOM_PSUH_CFG_RST_TOKEN_MASK                     0x7FFC0
#define NIC0_TXS0_RANDOM_PSUH_CFG_TIMEOUT_SHIFT                      19
#define NIC0_TXS0_RANDOM_PSUH_CFG_TIMEOUT_MASK                       0xFFF80000

/* NIC0_TXS0_DBG_HW_EVENT_TRIGER */
#define NIC0_TXS0_DBG_HW_EVENT_TRIGER_R_SHIFT                        0
#define NIC0_TXS0_DBG_HW_EVENT_TRIGER_R_MASK                         0x1F

/* NIC0_TXS0_INTERRUPT_CAUSE */
#define NIC0_TXS0_INTERRUPT_CAUSE_R_SHIFT                            0
#define NIC0_TXS0_INTERRUPT_CAUSE_R_MASK                             0xF

/* NIC0_TXS0_INTERRUPT_MASK */
#define NIC0_TXS0_INTERRUPT_MASK_R_SHIFT                             0
#define NIC0_TXS0_INTERRUPT_MASK_R_MASK                              0xF

/* NIC0_TXS0_INTERRUPT_CLR */

/* NIC0_TXS0_LOAD_SLICE_HIT_EN */
#define NIC0_TXS0_LOAD_SLICE_HIT_EN_R_SHIFT                          0
#define NIC0_TXS0_LOAD_SLICE_HIT_EN_R_MASK                           0x1

/* NIC0_TXS0_SLICE_ACTIVE_47_32 */
#define NIC0_TXS0_SLICE_ACTIVE_47_32_R_SHIFT                         0
#define NIC0_TXS0_SLICE_ACTIVE_47_32_R_MASK                          0xFFFF

/* NIC0_TXS0_SLICE_ACTIVE_31_0 */
#define NIC0_TXS0_SLICE_ACTIVE_31_0_R_SHIFT                          0
#define NIC0_TXS0_SLICE_ACTIVE_31_0_R_MASK                           0xFFFFFFFF

/* NIC0_TXS0_AXI_CACHE */
#define NIC0_TXS0_AXI_CACHE_R_SHIFT                                  0
#define NIC0_TXS0_AXI_CACHE_R_MASK                                   0xF

/* NIC0_TXS0_SLICE_GW_ADDR */
#define NIC0_TXS0_SLICE_GW_ADDR_R_SHIFT                              0
#define NIC0_TXS0_SLICE_GW_ADDR_R_MASK                               0x3F

/* NIC0_TXS0_SLICE_GW_DATA */
#define NIC0_TXS0_SLICE_GW_DATA_R_SHIFT                              0
#define NIC0_TXS0_SLICE_GW_DATA_R_MASK                               0x1FFFFFF

/* NIC0_TXS0_SCANNER_CREDIT_EN */
#define NIC0_TXS0_SCANNER_CREDIT_EN_R_SHIFT                          0
#define NIC0_TXS0_SCANNER_CREDIT_EN_R_MASK                           0x3

/* NIC0_TXS0_FREE_LIST_PUSH_MASK_EN */
#define NIC0_TXS0_FREE_LIST_PUSH_MASK_EN_R_SHIFT                     0
#define NIC0_TXS0_FREE_LIST_PUSH_MASK_EN_R_MASK                      0x1

/* NIC0_TXS0_FREE_AEMPTY_THRESHOLD */
#define NIC0_TXS0_FREE_AEMPTY_THRESHOLD_R_SHIFT                      0
#define NIC0_TXS0_FREE_AEMPTY_THRESHOLD_R_MASK                       0xFFFFFFFF

#endif /* ASIC_REG_NIC0_TXS0_MASKS_H_ */
