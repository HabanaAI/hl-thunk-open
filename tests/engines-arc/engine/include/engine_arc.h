/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ENGINE_ARC_H_
#define _ENGINE_ARC_H_

#ifdef CORAL_BFM_MODE
#include <functional>
#endif

#include "arc_common_packets.h"
#include "arc_host_packets.h"
#include "arc_eng_packets.h"


#include "compile_target.h"

#include "arc_types.h"
#include "common_params.h"
#include "arc_queue_pvt.h"
#include "arc_queue_local.h"
#include "hw_qman.h"
#include "qman_if.h"
#include "compute_wd.h"
#include "sob_common.h"
#include "arc_msgs.h"

#define ENG_BLOCK_COUNT	4

struct engine_interface_ctxt_t {
	struct engine_arc_reg_t regs;
	u32 arc_queue_buff_q[MAX_DCCM_QUEUE_COUNT][ENGINE_ARC_DCCM_QUEUE_SIZE_DWORD];
} __attribute__ ((aligned(4), __packed__));

struct eng_hbm_data_t {
	u32 init_config_buffer[FIRMWARE_CONFIG_SIZE];
	char log_str[ARC_LOG_STR_BUF_SIZE];
}  __attribute__ ((aligned(4), __packed__));

struct engine_ctxt_t {
	u8 eng_cpu_id;
	u32 arc_cq_fifo_pi;
	u32 log_pi;
	uint32_t qm_base;
}
#ifdef CORAL_BFM_MODE
;
#else
__attribute__ ((aligned(4), __packed__));
#endif

extern struct eng_hbm_data_t eng_hbm_data;
extern struct engine_config_t *eng_post_init_config;
extern struct engine_ctxt_t engine_ctxt;
extern struct engine_interface_ctxt_t engine_interface_ctxt;

extern void (*const eng_blocks_pre_init[ENG_BLOCK_COUNT])(void);
extern void (*const eng_blocks_post_init[ENG_BLOCK_COUNT])(void);

extern void (*process_static_ecb_cmd[ECB_CMD_COUNT]) (struct engine_ctxt_t *eng_ctxt);
extern void (*process_dynamic_ecb_cmd[ECB_CMD_COUNT]) (struct engine_ctxt_t *eng_ctxt);

#ifndef CORAL_BFM_MODE
#include "engine_arc_fns.h"
#endif

#endif /* _ENGINE_ARC_H_ */
