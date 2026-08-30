/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __ENG_REGS_H__
#define __ENG_REGS_H__

#include "arc_types.h"
#include "arc_common_packets.h"
#include "arc_host_packets.h"

/**
 * \file    regs.h
 * \brief   Registers exposed by the scheduler ARC for host
 *          This defines data structures to be used by both the ARCs i.e.
 *          scheduler ARC and Engine ARC to communicate
 */
#ifndef CORAL_BFM_MODE
#include "eng_regs_fns.h"
#endif

#endif /* __ENG_REGS_H__ */
