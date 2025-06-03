/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __UTILS_H__
#define __UTILS_H__

#include "arc_types.h"

/**
 * \file    utils.h
 * \brief   Various utility functions
 */

#ifdef CORAL_BFM_MODE
typedef unsigned long long uintptr;
#else
typedef u32 uintptr;
#endif

#ifdef CORAL_BFM_MODE

#define USE_FS_MEM_TOKENS
#ifdef USE_FS_MEM_TOKENS

#define soc_reg_read(reg) soc_reg_read_cb(reg, __FILE__, __LINE__)
#define soc_reg_write(val, reg) soc_reg_write_cb (val, reg, __FILE__, __LINE__)
#define _sr(val, reg) sr_cb(val, reg, __FILE__, __LINE__)
#define _lr(reg) lr_cb(reg, __FILE__, __LINE__)

#else

#define soc_reg_read(reg) soc_reg_read_cb(reg, 0, 0)
#define soc_reg_write(val, reg) soc_reg_write_cb (val, reg, 0, 0)
#define _sr(val, reg) sr_cb(val, reg, 0, 0)
#define _lr(reg) lr_cb(reg, 0, 0)

#endif

#else
/*
 * APIs for reading and writing into LBW registers
 * This takes LBU interface on the ARC
 */
#define soc_reg_read(reg)					\
	({							\
		*(volatile unsigned int *)(reg); 		\
	})

#define soc_reg_write(val, reg)				\
	({							\
		*(volatile unsigned int *)(reg) = val;		\
	})
#endif

#define MIN(x,y) ((x < y) ? (x) : (y))
#define MAX(x,y) ((x > y) ? (x) : (y))

/*
 * All the SoC registers are accessed using LBU interface
 * which is connected to LBW fabric and its Region15 of ARC
 */
#define ARC_LBU_BASE_ADDR	0xF0000000

#define ARC_LBU_ADDR(reg)	(0xF0000000 + (reg))

#define ARC_QM_ADDR(reg)	ARC_LBU_ADDR(get_qm_base() + ((reg) & 0xfff))

/*
 * This dead code is to route the LBU traffic via AUX interface
 * for testing purpose
 */
#ifdef TARGET_SIM_NSIM
#define arc_aux_reg_read(reg)			0
#define arc_aux_reg_write(val, reg)
#else
#define arc_aux_reg_read(reg)			_lr(reg)
#define arc_aux_reg_write(val, reg)		_sr(val, reg)
#endif

#define arc_reg_read(reg)			_lr(reg)
#define arc_reg_write(val, reg)		_sr(val, reg)

/*
 * SoC online generated header files contain offsets
 * User defined AUX registers in ARC starts at 0x80000000
 */
#define ARC_AUX_ADDR(reg) (0x80000000 + ((reg) & 0xFFF))

/*
 * This macro converts a local DCCM address to DCCM offset
 * Mostly used for getting LBW address and ARC DCCM queues programming
 */
#ifndef CORAL_BFM_MODE
#define ARC_DCCM_OFFSET(addr)	((uintptr)(addr - 0x80000000))
#define ARC_HBM_OFFSET(addr)	((uintptr)(addr - 0x40000000))
#else
#define ARC_DCCM_OFFSET(addr)  (u32)(static_cast<char*>((void*)addr) - static_cast<char*>(get_dccm_base()))
#define ARC_HBM_OFFSET(addr)  (u32)(static_cast<char*>((void*)addr) - static_cast<char*>(get_hbm_base()))
#endif
#define ARC_DCCM_ADDR(addr) (0x80000000 + ARC_DCCM_OFFSET((uintptr)addr))
#define ARC_HBM_ADDR(addr) (0x40000000 + ARC_HBM_OFFSET((uintptr)addr))
/*
 * Local address offsets for various blocks which can be accessed
 * from ARCs
 */
#define LOCAL_ACP_OFFSET 0xF000
#define LOCAL_DUP_OFFSET 0x9000
#define LOCAL_QM_OFFSET	 0xA000

/*
 * Local address of DCCM to access it from QM
 */
#define LOCAL_DCCM_ADDRESS_LO 0xFCA00000
#define LOCAL_DCCM_ADDRESS_HI 0x1000007F

#define MON_COUNT_PER_DCORE		2048
#define SOB_COUNT_PER_DCORE		8192

#ifndef CORAL_BFM_MODE
#include "utils_fns.h"
#endif

/*
 * Avoid compiler warnings on unaligned accesses
 * taken from Linux kernel include/asm-generic/unaligned.h
 * Note that we still get the penalty of unaligned accesses on architectures that do not support it.
 */

/* workaround checkpatch warnings over this pragma */
#ifndef __packed
#define ATTRIB(NAME)    __attribute__((__ ## NAME ## __))
#define __packed        ATTRIB(packed)
#endif

#define __get_unaligned_t(type, ptr) ({						\
	const struct __packed { type x; } *__pptr = (__typeof__(__pptr))(ptr);	\
	__pptr->x;								\
})

#define __put_unaligned_t(type, val, ptr) do {					\
	struct  __packed { type x; } *__pptr = (__typeof__(__pptr))(ptr);	\
	__pptr->x = (val);							\
} while (0)

#define get_unaligned(ptr)	__get_unaligned_t(__typeof__(*(ptr)), (ptr))
#define put_unaligned(val, ptr) __put_unaligned_t(__typeof__(*(ptr)), (val), (ptr))

#endif /* __UTILS_H__ */
