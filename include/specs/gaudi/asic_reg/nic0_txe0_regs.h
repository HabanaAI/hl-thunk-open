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

#ifndef ASIC_REG_NIC0_TXE0_REGS_H_
#define ASIC_REG_NIC0_TXE0_REGS_H_

/*
 *****************************************
 *   NIC0_TXE0 (Prototype: NIC_TXE)
 *****************************************
 */

#define mmNIC0_TXE0_WQE_FETCH_REQ_MASK_31_0                          0xCF2000

#define mmNIC0_TXE0_WQE_FETCH_REQ_MASK_47_32                         0xCF2004

#define mmNIC0_TXE0_LOCAL_WQ_BUFFER_SIZE                             0xCF2008

#define mmNIC0_TXE0_LOCAL_WQ_LINE_SIZE                               0xCF200C

#define mmNIC0_TXE0_LOG_MAX_WQ_SIZE_0                                0xCF2010

#define mmNIC0_TXE0_LOG_MAX_WQ_SIZE_1                                0xCF2014

#define mmNIC0_TXE0_LOG_MAX_WQ_SIZE_2                                0xCF2018

#define mmNIC0_TXE0_LOG_MAX_WQ_SIZE_3                                0xCF201C

#define mmNIC0_TXE0_SQ_BASE_ADDRESS_49_32_0                          0xCF2020

#define mmNIC0_TXE0_SQ_BASE_ADDRESS_49_32_1                          0xCF2024

#define mmNIC0_TXE0_SQ_BASE_ADDRESS_49_32_2                          0xCF2028

#define mmNIC0_TXE0_SQ_BASE_ADDRESS_49_32_3                          0xCF202C

#define mmNIC0_TXE0_SQ_BASE_ADDRESS_31_0_0                           0xCF2030

#define mmNIC0_TXE0_SQ_BASE_ADDRESS_31_0_1                           0xCF2034

#define mmNIC0_TXE0_SQ_BASE_ADDRESS_31_0_2                           0xCF2038

#define mmNIC0_TXE0_SQ_BASE_ADDRESS_31_0_3                           0xCF203C

#define mmNIC0_TXE0_SQ_BASE_ADDRESS_SEL                              0xCF2040

#define mmNIC0_TXE0_ALLOC_CREDIT                                     0xCF2044

#define mmNIC0_TXE0_ALLOC_CREDIT_FORCE_FULL                          0xCF2048

#define mmNIC0_TXE0_READ_CREDIT                                      0xCF204C

#define mmNIC0_TXE0_READ_CREDIT_FORCE_FULL                           0xCF2050

#define mmNIC0_TXE0_BURST_ENABLE                                     0xCF2054

#define mmNIC0_TXE0_WR_INIT_BUSY                                     0xCF2058

#define mmNIC0_TXE0_READ_RES_WT_INIT_BUSY                            0xCF205C

#define mmNIC0_TXE0_BTH_TVER                                         0xCF2060

#define mmNIC0_TXE0_IPV4_IDENTIFICATION                              0xCF2064

#define mmNIC0_TXE0_IPV4_FLAGS                                       0xCF2068

#define mmNIC0_TXE0_PAD                                              0xCF206C

#define mmNIC0_TXE0_ADD_PAD_TO_IPV4_LEN                              0xCF2070

#define mmNIC0_TXE0_ADD_PAD_TO_UDP_LEN                               0xCF2074

#define mmNIC0_TXE0_ICRC_EN                                          0xCF2078

#define mmNIC0_TXE0_UDP_MASK_S_PORT                                  0xCF207C

#define mmNIC0_TXE0_UDP_CHECKSUM                                     0xCF2080

#define mmNIC0_TXE0_UDP_DEST_PORT                                    0xCF2084

#define mmNIC0_TXE0_PORT0_MAC_CFG_47_32                              0xCF2088

#define mmNIC0_TXE0_PORT0_MAC_CFG_31_0                               0xCF208C

#define mmNIC0_TXE0_PORT1_MAC_CFG_47_32                              0xCF2090

#define mmNIC0_TXE0_PORT1_MAC_CFG_31_0                               0xCF2094

#define mmNIC0_TXE0_PRIO_TO_DSCP_0                                   0xCF209C

#define mmNIC0_TXE0_PRIO_TO_DSCP_1                                   0xCF20A0

#define mmNIC0_TXE0_PRIO_TO_PCP                                      0xCF20B0

#define mmNIC0_TXE0_MAC_ETHER_TYPE                                   0xCF20B4

#define mmNIC0_TXE0_MAC_ETHER_TYPE_VLAN                              0xCF20B8

#define mmNIC0_TXE0_ECN_0                                            0xCF20BC

#define mmNIC0_TXE0_ECN_1                                            0xCF20C0

#define mmNIC0_TXE0_IPV4_TIME_TO_LIVE_0                              0xCF20C4

#define mmNIC0_TXE0_IPV4_TIME_TO_LIVE_1                              0xCF20C8

#define mmNIC0_TXE0_PRIO_PORT_CREDIT_FORCE                           0xCF20CC

#define mmNIC0_TXE0_PRIO_PORT_CRDIT_0                                0xCF20D0

#define mmNIC0_TXE0_PRIO_PORT_CRDIT_1                                0xCF20D4

#define mmNIC0_TXE0_PRIO_PORT_CRDIT_2                                0xCF20D8

#define mmNIC0_TXE0_PRIO_PORT_CRDIT_3                                0xCF20DC

#define mmNIC0_TXE0_PRIO_PORT_CRDIT_4                                0xCF20E0

#define mmNIC0_TXE0_PRIO_PORT_CRDIT_5                                0xCF20E4

#define mmNIC0_TXE0_PRIO_PORT_CRDIT_6                                0xCF20E8

#define mmNIC0_TXE0_PRIO_PORT_CRDIT_7                                0xCF20EC

#define mmNIC0_TXE0_WQE_FETCH_TOKEN_EN                               0xCF20F0

#define mmNIC0_TXE0_NACK_SYNDROME                                    0xCF20F4

#define mmNIC0_TXE0_WQE_FETCH_AXI_USER                               0xCF20F8

#define mmNIC0_TXE0_WQE_FETCH_AXI_PROT                               0xCF20FC

#define mmNIC0_TXE0_DATA_FETCH_AXI_USER                              0xCF2100

#define mmNIC0_TXE0_DATA_FETCH_AXI_PROT                              0xCF2104

#define mmNIC0_TXE0_FETCH_OUT_OF_TOKEN                               0xCF2108

#define mmNIC0_TXE0_ECN_COUNT_EN                                     0xCF210C

#define mmNIC0_TXE0_INERRUPT_CAUSE                                   0xCF2110

#define mmNIC0_TXE0_INTERRUPT_MASK                                   0xCF2114

#define mmNIC0_TXE0_INTERRUPT_CLR                                    0xCF2118

#define mmNIC0_TXE0_VLAN_TAG_QPN_OFFSET                              0xCF211C

#define mmNIC0_TXE0_VALN_TAG_CFG_0                                   0xCF2120

#define mmNIC0_TXE0_VALN_TAG_CFG_1                                   0xCF2124

#define mmNIC0_TXE0_VALN_TAG_CFG_2                                   0xCF2128

#define mmNIC0_TXE0_VALN_TAG_CFG_3                                   0xCF212C

#define mmNIC0_TXE0_VALN_TAG_CFG_4                                   0xCF2130

#define mmNIC0_TXE0_VALN_TAG_CFG_5                                   0xCF2134

#define mmNIC0_TXE0_VALN_TAG_CFG_6                                   0xCF2138

#define mmNIC0_TXE0_VALN_TAG_CFG_7                                   0xCF213C

#define mmNIC0_TXE0_VALN_TAG_CFG_8                                   0xCF2140

#define mmNIC0_TXE0_VALN_TAG_CFG_9                                   0xCF2144

#define mmNIC0_TXE0_VALN_TAG_CFG_10                                  0xCF2148

#define mmNIC0_TXE0_VALN_TAG_CFG_11                                  0xCF214C

#define mmNIC0_TXE0_VALN_TAG_CFG_12                                  0xCF2150

#define mmNIC0_TXE0_VALN_TAG_CFG_13                                  0xCF2154

#define mmNIC0_TXE0_VALN_TAG_CFG_14                                  0xCF2158

#define mmNIC0_TXE0_VALN_TAG_CFG_15                                  0xCF215C

#define mmNIC0_TXE0_DBG_TRIG                                         0xCF2160

#define mmNIC0_TXE0_WQE_PREFETCH_CFG                                 0xCF2164

#define mmNIC0_TXE0_WQE_PREFETCH_INVALIDATE                          0xCF2168

#define mmNIC0_TXE0_SWAP_MEMORY_ENDIANNESS                           0xCF216C

#define mmNIC0_TXE0_WQE_FETCH_SLICE_47_32                            0xCF2170

#define mmNIC0_TXE0_WQE_FETCH_SLICE_31_0                             0xCF2174

#define mmNIC0_TXE0_WQE_EXE_SLICE_47_32                              0xCF2178

#define mmNIC0_TXE0_WQE_EXE_SLICE_31_0                               0xCF217C

#define mmNIC0_TXE0_DBG_COUNT_SELECT_0                               0xCF2180

#define mmNIC0_TXE0_DBG_COUNT_SELECT_1                               0xCF2184

#define mmNIC0_TXE0_DBG_COUNT_SELECT_2                               0xCF2188

#define mmNIC0_TXE0_DBG_COUNT_SELECT_3                               0xCF218C

#define mmNIC0_TXE0_DBG_COUNT_SELECT_4                               0xCF2190

#define mmNIC0_TXE0_DBG_COUNT_SELECT_5                               0xCF2194

#define mmNIC0_TXE0_DBG_COUNT_SELECT_6                               0xCF2198

#define mmNIC0_TXE0_DBG_COUNT_SELECT_7                               0xCF219C

#define mmNIC0_TXE0_DBG_COUNT_SELECT_8                               0xCF21A0

#define mmNIC0_TXE0_DBG_COUNT_SELECT_9                               0xCF21A4

#define mmNIC0_TXE0_DBG_COUNT_SELECT_10                              0xCF21A8

#define mmNIC0_TXE0_DBG_COUNT_SELECT_11                              0xCF21AC

#define mmNIC0_TXE0_BTH_MKEY                                         0xCF21B0

#define mmNIC0_TXE0_WQE_BUFF_FLUSH_SLICE_47_3                        0xCF21B4

#define mmNIC0_TXE0_WQE_BUFF_FLUSH_SLICE_31_0                        0xCF21B8

#define mmNIC0_TXE0_INTERRUPT_INDEX_MASK_RING_0                      0xCF21BC

#define mmNIC0_TXE0_INTERRUPT_INDEX_MASK_RING_1                      0xCF21C0

#define mmNIC0_TXE0_INTERRUPT_INDEX_MASK_RING_2                      0xCF21C4

#define mmNIC0_TXE0_INTERRUPT_INDEX_MASK_RING_3                      0xCF21C8

#define mmNIC0_TXE0_INTERRUPT_INDEX_MASK_RING_4                      0xCF21CC

#define mmNIC0_TXE0_QPN_RING_0                                       0xCF21D0

#define mmNIC0_TXE0_QPN_RING_1                                       0xCF21D4

#define mmNIC0_TXE0_QPN_RING_2                                       0xCF21D8

#define mmNIC0_TXE0_QPN_RING_3                                       0xCF21DC

#define mmNIC0_TXE0_INTERRUPT_EACH_PACKET                            0xCF21F0

#define mmNIC0_TXE0_EXECUTIN_INDEX_RING_0                            0xCF21F4

#define mmNIC0_TXE0_EXECUTIN_INDEX_RING_1                            0xCF21F8

#define mmNIC0_TXE0_EXECUTIN_INDEX_RING_2                            0xCF21FC

#define mmNIC0_TXE0_EXECUTIN_INDEX_RING_3                            0xCF2200

#endif /* ASIC_REG_NIC0_TXE0_REGS_H_ */
