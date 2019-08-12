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

#ifndef ASIC_REG_MMU_UP_MASKS_H_
#define ASIC_REG_MMU_UP_MASKS_H_

/*
 *****************************************
 *   MMU_UP (Prototype: MMU)
 *****************************************
 */

/* MMU_UP_MMU_ENABLE */
#define MMU_UP_MMU_ENABLE_R_SHIFT                                    0
#define MMU_UP_MMU_ENABLE_R_MASK                                     0x1

/* MMU_UP_FORCE_ORDERING */
#define MMU_UP_FORCE_ORDERING_WEAK_ORDERING_SHIFT                    0
#define MMU_UP_FORCE_ORDERING_WEAK_ORDERING_MASK                     0x1
#define MMU_UP_FORCE_ORDERING_STRONG_ORDERING_SHIFT                  1
#define MMU_UP_FORCE_ORDERING_STRONG_ORDERING_MASK                   0x2

/* MMU_UP_FEATURE_ENABLE */
#define MMU_UP_FEATURE_ENABLE_VA_ORDERING_EN_SHIFT                   0
#define MMU_UP_FEATURE_ENABLE_VA_ORDERING_EN_MASK                    0x1
#define MMU_UP_FEATURE_ENABLE_CLEAN_LINK_LIST_SHIFT                  1
#define MMU_UP_FEATURE_ENABLE_CLEAN_LINK_LIST_MASK                   0x2
#define MMU_UP_FEATURE_ENABLE_HOP_OFFSET_EN_SHIFT                    2
#define MMU_UP_FEATURE_ENABLE_HOP_OFFSET_EN_MASK                     0x4
#define MMU_UP_FEATURE_ENABLE_OBI_ORDERING_EN_SHIFT                  3
#define MMU_UP_FEATURE_ENABLE_OBI_ORDERING_EN_MASK                   0x8
#define MMU_UP_FEATURE_ENABLE_STRONG_ORDERING_READ_EN_SHIFT          4
#define MMU_UP_FEATURE_ENABLE_STRONG_ORDERING_READ_EN_MASK           0x10
#define MMU_UP_FEATURE_ENABLE_TRACE_ENABLE_SHIFT                     5
#define MMU_UP_FEATURE_ENABLE_TRACE_ENABLE_MASK                      0x20

/* MMU_UP_VA_ORDERING_MASK_31_7 */
#define MMU_UP_VA_ORDERING_MASK_31_7_R_SHIFT                         0
#define MMU_UP_VA_ORDERING_MASK_31_7_R_MASK                          0x1FFFFFF

/* MMU_UP_VA_ORDERING_MASK_49_32 */
#define MMU_UP_VA_ORDERING_MASK_49_32_R_SHIFT                        0
#define MMU_UP_VA_ORDERING_MASK_49_32_R_MASK                         0x3FFFF

/* MMU_UP_LOG2_DDR_SIZE */
#define MMU_UP_LOG2_DDR_SIZE_R_SHIFT                                 0
#define MMU_UP_LOG2_DDR_SIZE_R_MASK                                  0xFF

/* MMU_UP_SCRAMBLER */
#define MMU_UP_SCRAMBLER_ADDR_BIT_SHIFT                              0
#define MMU_UP_SCRAMBLER_ADDR_BIT_MASK                               0x3F
#define MMU_UP_SCRAMBLER_SINGLE_DDR_EN_SHIFT                         6
#define MMU_UP_SCRAMBLER_SINGLE_DDR_EN_MASK                          0x40
#define MMU_UP_SCRAMBLER_SINGLE_DDR_ID_SHIFT                         7
#define MMU_UP_SCRAMBLER_SINGLE_DDR_ID_MASK                          0x80

/* MMU_UP_MEM_INIT_BUSY */
#define MMU_UP_MEM_INIT_BUSY_DATA_SHIFT                              0
#define MMU_UP_MEM_INIT_BUSY_DATA_MASK                               0x3
#define MMU_UP_MEM_INIT_BUSY_OBI0_SHIFT                              2
#define MMU_UP_MEM_INIT_BUSY_OBI0_MASK                               0x4
#define MMU_UP_MEM_INIT_BUSY_OBI1_SHIFT                              3
#define MMU_UP_MEM_INIT_BUSY_OBI1_MASK                               0x8

/* MMU_UP_SPI_MASK */
#define MMU_UP_SPI_MASK_R_SHIFT                                      0
#define MMU_UP_SPI_MASK_R_MASK                                       0xFF

/* MMU_UP_SPI_CAUSE */
#define MMU_UP_SPI_CAUSE_R_SHIFT                                     0
#define MMU_UP_SPI_CAUSE_R_MASK                                      0x3FF

/* MMU_UP_PAGE_ERROR_CAPTURE */
#define MMU_UP_PAGE_ERROR_CAPTURE_VA_49_32_SHIFT                     0
#define MMU_UP_PAGE_ERROR_CAPTURE_VA_49_32_MASK                      0x3FFFF
#define MMU_UP_PAGE_ERROR_CAPTURE_ENTRY_VALID_SHIFT                  18
#define MMU_UP_PAGE_ERROR_CAPTURE_ENTRY_VALID_MASK                   0x40000

/* MMU_UP_PAGE_ERROR_CAPTURE_VA */
#define MMU_UP_PAGE_ERROR_CAPTURE_VA_VA_31_0_SHIFT                   0
#define MMU_UP_PAGE_ERROR_CAPTURE_VA_VA_31_0_MASK                    0xFFFFFFFF

/* MMU_UP_ACCESS_ERROR_CAPTURE */
#define MMU_UP_ACCESS_ERROR_CAPTURE_VA_49_32_SHIFT                   0
#define MMU_UP_ACCESS_ERROR_CAPTURE_VA_49_32_MASK                    0x3FFFF
#define MMU_UP_ACCESS_ERROR_CAPTURE_ENTRY_VALID_SHIFT                18
#define MMU_UP_ACCESS_ERROR_CAPTURE_ENTRY_VALID_MASK                 0x40000

/* MMU_UP_ACCESS_ERROR_CAPTURE_VA */
#define MMU_UP_ACCESS_ERROR_CAPTURE_VA_VA_31_0_SHIFT                 0
#define MMU_UP_ACCESS_ERROR_CAPTURE_VA_VA_31_0_MASK                  0xFFFFFFFF

/* MMU_UP_SPI_INTERRUPT_CLR */

/* MMU_UP_SPI_INTERRUPT_MASK */
#define MMU_UP_SPI_INTERRUPT_MASK_R_SHIFT                            0
#define MMU_UP_SPI_INTERRUPT_MASK_R_MASK                             0xFF

/* MMU_UP_DBG_MEM_WRAP_RM */
#define MMU_UP_DBG_MEM_WRAP_RM_R_SHIFT                               0
#define MMU_UP_DBG_MEM_WRAP_RM_R_MASK                                0x3FFFFFFF

/* MMU_UP_SPI_CAUSE_CLR */

/* MMU_UP_SLICE_CREDIT */
#define MMU_UP_SLICE_CREDIT_WRITE_SHIFT                              0
#define MMU_UP_SLICE_CREDIT_WRITE_MASK                               0xFF
#define MMU_UP_SLICE_CREDIT_READ_SHIFT                               8
#define MMU_UP_SLICE_CREDIT_READ_MASK                                0xFF00
#define MMU_UP_SLICE_CREDIT_TOTAL_SHIFT                              16
#define MMU_UP_SLICE_CREDIT_TOTAL_MASK                               0xFF0000
#define MMU_UP_SLICE_CREDIT_FORCE_FULL_WRITE_SHIFT                   24
#define MMU_UP_SLICE_CREDIT_FORCE_FULL_WRITE_MASK                    0x1000000
#define MMU_UP_SLICE_CREDIT_FORCE_FULL_READ_SHIFT                    25
#define MMU_UP_SLICE_CREDIT_FORCE_FULL_READ_MASK                     0x2000000
#define MMU_UP_SLICE_CREDIT_FORCE_FULL_TOTAL_SHIFT                   26
#define MMU_UP_SLICE_CREDIT_FORCE_FULL_TOTAL_MASK                    0x4000000

/* MMU_UP_PIPE_CREDIT */
#define MMU_UP_PIPE_CREDIT_READ_CREDIT_SHIFT                         0
#define MMU_UP_PIPE_CREDIT_READ_CREDIT_MASK                          0xF
#define MMU_UP_PIPE_CREDIT_READ_FORCE_FULL_SHIFT                     7
#define MMU_UP_PIPE_CREDIT_READ_FORCE_FULL_MASK                      0x80
#define MMU_UP_PIPE_CREDIT_WRITE_CREDIT_SHIFT                        8
#define MMU_UP_PIPE_CREDIT_WRITE_CREDIT_MASK                         0xF00
#define MMU_UP_PIPE_CREDIT_WRITE_FORCE_FULL_SHIFT                    15
#define MMU_UP_PIPE_CREDIT_WRITE_FORCE_FULL_MASK                     0x8000

/* MMU_UP_RAZWI_WRITE_VLD */
#define MMU_UP_RAZWI_WRITE_VLD_R_SHIFT                               0
#define MMU_UP_RAZWI_WRITE_VLD_R_MASK                                0x1

/* MMU_UP_RAZWI_WRITE_ID */
#define MMU_UP_RAZWI_WRITE_ID_R_SHIFT                                0
#define MMU_UP_RAZWI_WRITE_ID_R_MASK                                 0xFFFFFFFF

/* MMU_UP_RAZWI_READ_VLD */
#define MMU_UP_RAZWI_READ_VLD_R_SHIFT                                0
#define MMU_UP_RAZWI_READ_VLD_R_MASK                                 0x1

/* MMU_UP_RAZWI_READ_ID */
#define MMU_UP_RAZWI_READ_ID_R_SHIFT                                 0
#define MMU_UP_RAZWI_READ_ID_R_MASK                                  0xFFFFFFFF

/* MMU_UP_MMU_BYPASS */
#define MMU_UP_MMU_BYPASS_R_SHIFT                                    0
#define MMU_UP_MMU_BYPASS_R_MASK                                     0x1

#endif /* ASIC_REG_MMU_UP_MASKS_H_ */
