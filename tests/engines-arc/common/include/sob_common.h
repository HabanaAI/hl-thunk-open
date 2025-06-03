/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __SOB_COMMON_H__
#define __SOB_COMMON_H__

#include "arc_common_packets.h"
#include "arc_types.h"
#include "utils.h"


/**
 * \file    sob_common.h
 * \brief   Various SOB related functions used in common code
 */

#define SOB_OP_GREQ		0
#define SOB_OP_EQ		1

#define SOB_COUNT_PER_DCCM_QUEUE	2

#define GET_SOB_NEG_VALUE(x)	(0 - x)

struct sm_addr_t {
	u32 sob_obj;
	u32 mon_pay_addr_lo;
	u32 mon_pay_addr_hi;
	u32 mon_pay_data;
	u32 mon_arm;
	u32 mon_config;
} __attribute__ ((__packed__));

#endif /* __SOB_COMMON_H__ */
