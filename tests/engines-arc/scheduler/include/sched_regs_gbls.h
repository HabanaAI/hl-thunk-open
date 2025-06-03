/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef __SCHED_REGS_GBLS_H__
#define __SCHED_REGS_GBLS_H__

/*
 * Place registers in the begining of the DCCM memory
 */
#ifdef CORAL_BFM_MODE
struct sched_interface_ctxt_t& sched_interface_ctxt;
#else
struct sched_interface_ctxt_t sched_interface_ctxt __attribute__((section(".arc_regs")));
#endif

#endif /* __SCHED_REGS_GBLS_H__ */
