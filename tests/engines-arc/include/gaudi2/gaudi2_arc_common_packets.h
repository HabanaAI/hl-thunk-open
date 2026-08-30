/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 */

#ifndef __GAUDI2_ARC_COMMON_PACKETS_H__
#define __GAUDI2_ARC_COMMON_PACKETS_H__

/**
 * \file    gaudi2_arc_common_packets.h
 * \brief   IDs for QMAN ARC CPUs
 *          This defines IDs that needs to be programmed into CPU ID
 *          register xx_ARC_AUX_ARC_NUM
 */

/**
 * CPU IDs for each ARC CPUs
 */

#define CPU_ID_SCHED_ARC0		0
#define CPU_ID_SCHED_ARC1		1
#define CPU_ID_SCHED_ARC2		2
#define CPU_ID_SCHED_ARC3		3
/* Dcore1 MME Engine ARC instance used as scheduler */
#define CPU_ID_SCHED_ARC4		4
/* Dcore3 MME Engine ARC instance used as scheduler */
#define CPU_ID_SCHED_ARC5		5

#define CPU_ID_TPC_QMAN_ARC0		6
#define CPU_ID_TPC_QMAN_ARC1		7
#define CPU_ID_TPC_QMAN_ARC2		8
#define CPU_ID_TPC_QMAN_ARC3		9
#define CPU_ID_TPC_QMAN_ARC4		10
#define CPU_ID_TPC_QMAN_ARC5		11
#define CPU_ID_TPC_QMAN_ARC6		12
#define CPU_ID_TPC_QMAN_ARC7		13
#define CPU_ID_TPC_QMAN_ARC8		14
#define CPU_ID_TPC_QMAN_ARC9		15
#define CPU_ID_TPC_QMAN_ARC10		16
#define CPU_ID_TPC_QMAN_ARC11		17
#define CPU_ID_TPC_QMAN_ARC12		18
#define CPU_ID_TPC_QMAN_ARC13		19
#define CPU_ID_TPC_QMAN_ARC14		20
#define CPU_ID_TPC_QMAN_ARC15		21
#define CPU_ID_TPC_QMAN_ARC16		22
#define CPU_ID_TPC_QMAN_ARC17		23
#define CPU_ID_TPC_QMAN_ARC18		24
#define CPU_ID_TPC_QMAN_ARC19		25
#define CPU_ID_TPC_QMAN_ARC20		26
#define CPU_ID_TPC_QMAN_ARC21		27
#define CPU_ID_TPC_QMAN_ARC22		28
#define CPU_ID_TPC_QMAN_ARC23		29
#define CPU_ID_TPC_QMAN_ARC24		30

#define CPU_ID_MME_QMAN_ARC0		31
#define CPU_ID_MME_QMAN_ARC1		32

#define CPU_ID_EDMA_QMAN_ARC0		33
#define CPU_ID_EDMA_QMAN_ARC1		34
#define CPU_ID_EDMA_QMAN_ARC2		35
#define CPU_ID_EDMA_QMAN_ARC3		36
#define CPU_ID_EDMA_QMAN_ARC4		37
#define CPU_ID_EDMA_QMAN_ARC5		38
#define CPU_ID_EDMA_QMAN_ARC6		39
#define CPU_ID_EDMA_QMAN_ARC7		40

#define CPU_ID_PDMA_QMAN_ARC0		41
#define CPU_ID_PDMA_QMAN_ARC1		42

#define CPU_ID_ROT_QMAN_ARC0		43
#define CPU_ID_ROT_QMAN_ARC1		44

#define CPU_ID_NIC_QMAN_ARC0		45
#define CPU_ID_NIC_QMAN_ARC1		46
#define CPU_ID_NIC_QMAN_ARC2		47
#define CPU_ID_NIC_QMAN_ARC3		48
#define CPU_ID_NIC_QMAN_ARC4		49
#define CPU_ID_NIC_QMAN_ARC5		50
#define CPU_ID_NIC_QMAN_ARC6		51
#define CPU_ID_NIC_QMAN_ARC7		52
#define CPU_ID_NIC_QMAN_ARC8		53
#define CPU_ID_NIC_QMAN_ARC9		54
#define CPU_ID_NIC_QMAN_ARC10		55
#define CPU_ID_NIC_QMAN_ARC11		56
#define CPU_ID_NIC_QMAN_ARC12		57
#define CPU_ID_NIC_QMAN_ARC13		58
#define CPU_ID_NIC_QMAN_ARC14		59
#define CPU_ID_NIC_QMAN_ARC15		60
#define CPU_ID_NIC_QMAN_ARC16		61
#define CPU_ID_NIC_QMAN_ARC17		62
#define CPU_ID_NIC_QMAN_ARC18		63
#define CPU_ID_NIC_QMAN_ARC19		64
#define CPU_ID_NIC_QMAN_ARC20		65
#define CPU_ID_NIC_QMAN_ARC21		66
#define CPU_ID_NIC_QMAN_ARC22		67
#define CPU_ID_NIC_QMAN_ARC23		68

#define CPU_ID_MAX			69
#define CPU_ID_SCHED_MAX		6

#define CPU_ID_ALL			0xFE
#define CPU_ID_INVALID			0xFF

#define SCHED_QUEUES_IN_USE		1
#define SCHED_QUEUE_SIZE		4096

/**
 * \enum    arc_regions_t
 * \brief   ARC address map
 * \details Address map of scheduler as well as engine ARC.
 *          Each region is of size 256MB. Driver programs the extension
 *          registers.
 */
enum arc_regions_t {
	ARC_REGION0_UNSED  = 0,
	/*
	 * Extension registers
	 * None
	 */
	ARC_REGION1_SRAM = 1,
	/*
	 * Extension registers
	 * AUX_SRAM_LSB_ADDR
	 * AUX_SRAM_MSB_ADDR
	 * ARC Address: 0x1000_0000
	 */
	ARC_REGION2_CFG = 2,
	/*
	 * Extension registers
	 * AUX_CFG_LSB_ADDR
	 * AUX_CFG_MSB_ADDR
	 * ARC Address: 0x2000_0000
	 */
	ARC_REGION3_GENERAL = 3,
	/*
	 * Extension registers
	 * AUX_GENERAL_PURPOSE_LSB_ADDR_0
	 * AUX_GENERAL_PURPOSE_MSB_ADDR_0
	 * ARC Address: 0x3000_0000
	 */
	ARC_REGION4_HBM0_FW = 4,
	/*
	 * Extension registers
	 * AUX_HBM0_LSB_ADDR
	 * AUX_HBM0_MSB_ADDR
	 * AUX_HBM0_OFFSET
	 * ARC Address: 0x4000_0000
	 */
	ARC_REGION5_HBM1_GC_DATA = 5,
	/*
	 * Extension registers
	 * AUX_HBM1_LSB_ADDR
	 * AUX_HBM1_MSB_ADDR
	 * AUX_HBM1_OFFSET
	 * ARC Address: 0x5000_0000
	 */
	ARC_REGION6_HBM2_GC_DATA = 6,
	/*
	 * Extension registers
	 * AUX_HBM2_LSB_ADDR
	 * AUX_HBM2_MSB_ADDR
	 * AUX_HBM2_OFFSET
	 * ARC Address: 0x6000_0000
	 */
	ARC_REGION7_HBM3_GC_DATA = 7,
	/*
	 * Extension registers
	 * AUX_HBM3_LSB_ADDR
	 * AUX_HBM3_MSB_ADDR
	 * AUX_HBM3_OFFSET
	 * ARC Address: 0x7000_0000
	 */
	ARC_REGION8_DCCM = 8,
	/*
	 * Extension registers
	 * None
	 * ARC Address: 0x8000_0000
	 */
	ARC_REGION9_PCIE = 9,
	/*
	 * Extension registers
	 * AUX_PCIE_LSB_ADDR
	 * AUX_PCIE_MSB_ADDR
	 * ARC Address: 0x9000_0000
	 */
	ARC_REGION10_GENERAL = 10,
	/*
	 * Extension registers
	 * AUX_GENERAL_PURPOSE_LSB_ADDR_1
	 * AUX_GENERAL_PURPOSE_MSB_ADDR_1
	 * ARC Address: 0xA000_0000
	 */
	ARC_REGION11_GENERAL = 11,
	/*
	 * Extension registers
	 * AUX_GENERAL_PURPOSE_LSB_ADDR_2
	 * AUX_GENERAL_PURPOSE_MSB_ADDR_2
	 * ARC Address: 0xB000_0000
	 */
	ARC_REGION12_GENERAL = 12,
	/*
	 * Extension registers
	 * AUX_GENERAL_PURPOSE_LSB_ADDR_3
	 * AUX_GENERAL_PURPOSE_MSB_ADDR_3
	 * ARC Address: 0xC000_0000
	 */
	ARC_REGION13_GENERAL = 13,
	/*
	 * Extension registers
	 * AUX_GENERAL_PURPOSE_LSB_ADDR_4
	 * AUX_GENERAL_PURPOSE_MSB_ADDR_4
	 * ARC Address: 0xD000_0000
	 */
	ARC_REGION14_GENERAL = 14,
	/*
	 * Extension registers
	 * AUX_GENERAL_PURPOSE_LSB_ADDR_5
	 * AUX_GENERAL_PURPOSE_MSB_ADDR_5
	 * ARC Address: 0xE000_0000
	 */
	ARC_REGION15_LBU = 15
	/*
	 * Extension registers
	 * None
	 * ARC Address: 0xF000_0000
	 */
};

#endif /* __GAUDI2_ARC_COMMON_PACKETS_H__ */
