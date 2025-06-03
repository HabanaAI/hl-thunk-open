/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef __ENG_REGS_GBLS_H__
#define __ENG_REGS_GBLS_H__

/*
 * Place registers in the begining of the DCCM memory
 */
#ifdef CORAL_BFM_MODE
struct engine_interface_ctxt_t& engine_interface_ctxt;
#else
struct engine_interface_ctxt_t engine_interface_ctxt __attribute__ ((section(".arc_regs")));
#endif

#endif /* __ENG_REGS_GBLS_H__ */
