/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __SOB_COMMON_FNS_H__
#define __SOB_COMMON_FNS_H__

#include "arc_types.h"
#include "sob_common.h"

void init_mon_config(struct sm_addr_t *sm, u32 sob_id, u32 mon_id, u32 wr_num, u32 long_sob, u32 cq_en);

void update_sob(struct sm_addr_t *sm, u32 sob_id, u16 value, u8 increment);

void arm_mon(struct sm_addr_t *sm, u32 mon_id, u32 sob_id, u32 threshold, u32 op);

void init_sched_mon(struct sm_addr_t *sm, u32 mon_id, u32 addr_hi, u32 addr_lo, u32 data);

void update_mon_pay_addr_lo(struct sm_addr_t *sm, u32 mon_id, u32 addr_lo);

#endif /* __SOB_COMMON_FNS_H__ */
