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

#ifndef ASIC_REG_NIC0_TXE1_REGS_H_
#define ASIC_REG_NIC0_TXE1_REGS_H_

/*
 *****************************************
 *   NIC0_TXE1 (Prototype: NIC_TXE)
 *****************************************
 */

#define mmNIC0_TXE1_WQE_FETCH_REQ_MASK_31_0                          0xCF3000

#define mmNIC0_TXE1_WQE_FETCH_REQ_MASK_47_32                         0xCF3004

#define mmNIC0_TXE1_LOCAL_WQ_BUFFER_SIZE                             0xCF3008

#define mmNIC0_TXE1_LOCAL_WQ_LINE_SIZE                               0xCF300C

#define mmNIC0_TXE1_LOG_MAX_WQ_SIZE_0                                0xCF3010

#define mmNIC0_TXE1_LOG_MAX_WQ_SIZE_1                                0xCF3014

#define mmNIC0_TXE1_LOG_MAX_WQ_SIZE_2                                0xCF3018

#define mmNIC0_TXE1_LOG_MAX_WQ_SIZE_3                                0xCF301C

#define mmNIC0_TXE1_SQ_BASE_ADDRESS_49_32_0                          0xCF3020

#define mmNIC0_TXE1_SQ_BASE_ADDRESS_49_32_1                          0xCF3024

#define mmNIC0_TXE1_SQ_BASE_ADDRESS_49_32_2                          0xCF3028

#define mmNIC0_TXE1_SQ_BASE_ADDRESS_49_32_3                          0xCF302C

#define mmNIC0_TXE1_SQ_BASE_ADDRESS_31_0_0                           0xCF3030

#define mmNIC0_TXE1_SQ_BASE_ADDRESS_31_0_1                           0xCF3034

#define mmNIC0_TXE1_SQ_BASE_ADDRESS_31_0_2                           0xCF3038

#define mmNIC0_TXE1_SQ_BASE_ADDRESS_31_0_3                           0xCF303C

#define mmNIC0_TXE1_SQ_BASE_ADDRESS_SEL                              0xCF3040

#define mmNIC0_TXE1_ALLOC_CREDIT                                     0xCF3044

#define mmNIC0_TXE1_ALLOC_CREDIT_FORCE_FULL                          0xCF3048

#define mmNIC0_TXE1_READ_CREDIT                                      0xCF304C

#define mmNIC0_TXE1_READ_CREDIT_FORCE_FULL                           0xCF3050

#define mmNIC0_TXE1_BURST_ENABLE                                     0xCF3054

#define mmNIC0_TXE1_WR_INIT_BUSY                                     0xCF3058

#define mmNIC0_TXE1_READ_RES_WT_INIT_BUSY                            0xCF305C

#define mmNIC0_TXE1_BTH_TVER                                         0xCF3060

#define mmNIC0_TXE1_IPV4_IDENTIFICATION                              0xCF3064

#define mmNIC0_TXE1_IPV4_FLAGS                                       0xCF3068

#define mmNIC0_TXE1_PAD                                              0xCF306C

#define mmNIC0_TXE1_ADD_PAD_TO_IPV4_LEN                              0xCF3070

#define mmNIC0_TXE1_ADD_PAD_TO_UDP_LEN                               0xCF3074

#define mmNIC0_TXE1_ICRC_EN                                          0xCF3078

#define mmNIC0_TXE1_UDP_MASK_S_PORT                                  0xCF307C

#define mmNIC0_TXE1_UDP_CHECKSUM                                     0xCF3080

#define mmNIC0_TXE1_UDP_DEST_PORT                                    0xCF3084

#define mmNIC0_TXE1_PORT0_MAC_CFG_47_32                              0xCF3088

#define mmNIC0_TXE1_PORT0_MAC_CFG_31_0                               0xCF308C

#define mmNIC0_TXE1_PORT1_MAC_CFG_47_32                              0xCF3090

#define mmNIC0_TXE1_PORT1_MAC_CFG_31_0                               0xCF3094

#define mmNIC0_TXE1_PRIO_TO_DSCP_0                                   0xCF309C

#define mmNIC0_TXE1_PRIO_TO_DSCP_1                                   0xCF30A0

#define mmNIC0_TXE1_PRIO_TO_PCP                                      0xCF30B0

#define mmNIC0_TXE1_MAC_ETHER_TYPE                                   0xCF30B4

#define mmNIC0_TXE1_MAC_ETHER_TYPE_VLAN                              0xCF30B8

#define mmNIC0_TXE1_ECN_0                                            0xCF30BC

#define mmNIC0_TXE1_ECN_1                                            0xCF30C0

#define mmNIC0_TXE1_IPV4_TIME_TO_LIVE_0                              0xCF30C4

#define mmNIC0_TXE1_IPV4_TIME_TO_LIVE_1                              0xCF30C8

#define mmNIC0_TXE1_PRIO_PORT_CREDIT_FORCE                           0xCF30CC

#define mmNIC0_TXE1_PRIO_PORT_CRDIT_0                                0xCF30D0

#define mmNIC0_TXE1_PRIO_PORT_CRDIT_1                                0xCF30D4

#define mmNIC0_TXE1_PRIO_PORT_CRDIT_2                                0xCF30D8

#define mmNIC0_TXE1_PRIO_PORT_CRDIT_3                                0xCF30DC

#define mmNIC0_TXE1_PRIO_PORT_CRDIT_4                                0xCF30E0

#define mmNIC0_TXE1_PRIO_PORT_CRDIT_5                                0xCF30E4

#define mmNIC0_TXE1_PRIO_PORT_CRDIT_6                                0xCF30E8

#define mmNIC0_TXE1_PRIO_PORT_CRDIT_7                                0xCF30EC

#define mmNIC0_TXE1_WQE_FETCH_TOKEN_EN                               0xCF30F0

#define mmNIC0_TXE1_NACK_SYNDROME                                    0xCF30F4

#define mmNIC0_TXE1_WQE_FETCH_AXI_USER                               0xCF30F8

#define mmNIC0_TXE1_WQE_FETCH_AXI_PROT                               0xCF30FC

#define mmNIC0_TXE1_DATA_FETCH_AXI_USER                              0xCF3100

#define mmNIC0_TXE1_DATA_FETCH_AXI_PROT                              0xCF3104

#define mmNIC0_TXE1_FETCH_OUT_OF_TOKEN                               0xCF3108

#define mmNIC0_TXE1_ECN_COUNT_EN                                     0xCF310C

#define mmNIC0_TXE1_INERRUPT_CAUSE                                   0xCF3110

#define mmNIC0_TXE1_INTERRUPT_MASK                                   0xCF3114

#define mmNIC0_TXE1_INTERRUPT_CLR                                    0xCF3118

#define mmNIC0_TXE1_VLAN_TAG_QPN_OFFSET                              0xCF311C

#define mmNIC0_TXE1_VALN_TAG_CFG_0                                   0xCF3120

#define mmNIC0_TXE1_VALN_TAG_CFG_1                                   0xCF3124

#define mmNIC0_TXE1_VALN_TAG_CFG_2                                   0xCF3128

#define mmNIC0_TXE1_VALN_TAG_CFG_3                                   0xCF312C

#define mmNIC0_TXE1_VALN_TAG_CFG_4                                   0xCF3130

#define mmNIC0_TXE1_VALN_TAG_CFG_5                                   0xCF3134

#define mmNIC0_TXE1_VALN_TAG_CFG_6                                   0xCF3138

#define mmNIC0_TXE1_VALN_TAG_CFG_7                                   0xCF313C

#define mmNIC0_TXE1_VALN_TAG_CFG_8                                   0xCF3140

#define mmNIC0_TXE1_VALN_TAG_CFG_9                                   0xCF3144

#define mmNIC0_TXE1_VALN_TAG_CFG_10                                  0xCF3148

#define mmNIC0_TXE1_VALN_TAG_CFG_11                                  0xCF314C

#define mmNIC0_TXE1_VALN_TAG_CFG_12                                  0xCF3150

#define mmNIC0_TXE1_VALN_TAG_CFG_13                                  0xCF3154

#define mmNIC0_TXE1_VALN_TAG_CFG_14                                  0xCF3158

#define mmNIC0_TXE1_VALN_TAG_CFG_15                                  0xCF315C

#define mmNIC0_TXE1_DBG_TRIG                                         0xCF3160

#define mmNIC0_TXE1_WQE_PREFETCH_CFG                                 0xCF3164

#define mmNIC0_TXE1_WQE_PREFETCH_INVALIDATE                          0xCF3168

#define mmNIC0_TXE1_SWAP_MEMORY_ENDIANNESS                           0xCF316C

#define mmNIC0_TXE1_WQE_FETCH_SLICE_47_32                            0xCF3170

#define mmNIC0_TXE1_WQE_FETCH_SLICE_31_0                             0xCF3174

#define mmNIC0_TXE1_WQE_EXE_SLICE_47_32                              0xCF3178

#define mmNIC0_TXE1_WQE_EXE_SLICE_31_0                               0xCF317C

#define mmNIC0_TXE1_DBG_COUNT_SELECT_0                               0xCF3180

#define mmNIC0_TXE1_DBG_COUNT_SELECT_1                               0xCF3184

#define mmNIC0_TXE1_DBG_COUNT_SELECT_2                               0xCF3188

#define mmNIC0_TXE1_DBG_COUNT_SELECT_3                               0xCF318C

#define mmNIC0_TXE1_DBG_COUNT_SELECT_4                               0xCF3190

#define mmNIC0_TXE1_DBG_COUNT_SELECT_5                               0xCF3194

#define mmNIC0_TXE1_DBG_COUNT_SELECT_6                               0xCF3198

#define mmNIC0_TXE1_DBG_COUNT_SELECT_7                               0xCF319C

#define mmNIC0_TXE1_DBG_COUNT_SELECT_8                               0xCF31A0

#define mmNIC0_TXE1_DBG_COUNT_SELECT_9                               0xCF31A4

#define mmNIC0_TXE1_DBG_COUNT_SELECT_10                              0xCF31A8

#define mmNIC0_TXE1_DBG_COUNT_SELECT_11                              0xCF31AC

#define mmNIC0_TXE1_BTH_MKEY                                         0xCF31B0

#define mmNIC0_TXE1_WQE_BUFF_FLUSH_SLICE_47_3                        0xCF31B4

#define mmNIC0_TXE1_WQE_BUFF_FLUSH_SLICE_31_0                        0xCF31B8

#define mmNIC0_TXE1_INTERRUPT_INDEX_MASK_RING_0                      0xCF31BC

#define mmNIC0_TXE1_INTERRUPT_INDEX_MASK_RING_1                      0xCF31C0

#define mmNIC0_TXE1_INTERRUPT_INDEX_MASK_RING_2                      0xCF31C4

#define mmNIC0_TXE1_INTERRUPT_INDEX_MASK_RING_3                      0xCF31C8

#define mmNIC0_TXE1_INTERRUPT_INDEX_MASK_RING_4                      0xCF31CC

#define mmNIC0_TXE1_QPN_RING_0                                       0xCF31D0

#define mmNIC0_TXE1_QPN_RING_1                                       0xCF31D4

#define mmNIC0_TXE1_QPN_RING_2                                       0xCF31D8

#define mmNIC0_TXE1_QPN_RING_3                                       0xCF31DC

#define mmNIC0_TXE1_INTERRUPT_EACH_PACKET                            0xCF31F0

#define mmNIC0_TXE1_EXECUTIN_INDEX_RING_0                            0xCF31F4

#define mmNIC0_TXE1_EXECUTIN_INDEX_RING_1                            0xCF31F8

#define mmNIC0_TXE1_EXECUTIN_INDEX_RING_2                            0xCF31FC

#define mmNIC0_TXE1_EXECUTIN_INDEX_RING_3                            0xCF3200

#endif /* ASIC_REG_NIC0_TXE1_REGS_H_ */
