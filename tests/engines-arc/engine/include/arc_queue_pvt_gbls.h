/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef __ARC_QUEUE_PVT_GBLS_H__
#define __ARC_QUEUE_PVT_GBLS_H__

/*
 * TODO: size of this can be reduced from MAX_DCCM_QUEUE_COUNT
 * to actual number of queues, that would require the data structure
 * to be moved into per engine context, so no doing it now
 */
struct arc_queue_ctxt_t arc_queue_ctxt[MAX_DCCM_QUEUE_COUNT];

#endif
