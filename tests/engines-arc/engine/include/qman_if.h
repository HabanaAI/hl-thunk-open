/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _QMAN_IF_H_
#define _QMAN_IF_H_

#include "arc_types.h"

/*
 * Create AUX address from the header files generated
 * by SoC Online database
 */
#define QMAN_ARC_CQ_FIFO_SIZE	(8)
#define QMAN_CQ_FIFO_SIZE		(8)

#define QMAN_ARC_CQ_CTL_DEFAULT_VALUE	0x0
#define QMAN_CQ_CTL_DEFAULT_VALUE		0x0

#ifndef CORAL_BFM_MODE
#include "qman_if_fns.h"
#endif

#endif /* _QMAN_IF_H_ */
