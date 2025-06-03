/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __SCHED_H__
#define __SCHED_H__


#include "arc_common_packets.h"
#include "arc_host_packets.h"
#include "arc_sched_packets.h"

#include "arc_types.h"
#include "common_params.h"
#include "sob_common.h"
#include "arc_msgs.h"

/**
 * \file    arc_sched.h
 * \brief   Scheduler ARC private APIs
 * 	    Stream scheduler running on Scheduler ARC
 */
enum ccb_state_t {
	CCB_STATE_IDLE = 0,
	CCB_STATE_CCB_DMA_STARTED,
	CCB_STATE_PROCESSING_CMD,
	CCB_STATE_END_OF_CCB,
	CCB_STATE_SUSPENDED,
	CCB_STATE_LAST = 0xFF
};

#define SCHED_STREAM_ID_INVALID		0xFF

#define CCB_BUFFER_SIZE_U8		CCB_STREAM_BUFF_SIZE
#define CCB_BUFFER_SIZE_U32		(CCB_BUFFER_SIZE_U8 / 4)

struct cmd_arb_point_ctxt_t {
	u8 arb_priority;
	u16 requested_engine_group;
	u8 reserved2;
} __attribute__ ((__packed__));

struct cmd_fence_ctxt_t {
	u32 reg_index:6;
	u32 reserved:26;
} __attribute__ ((__packed__));

struct cmd_dispatch_ctxt_t {
	u32 engine_group_bitmap:16;
	/*!<
	 * bitmap of engine groups which are involved in the current
	 * command buffer. This is required to send barrier message.
	 */
	u32 reserved:16;
} __attribute__ ((__packed__));

struct cmd_ctxt_t {
	struct cmd_arb_point_ctxt_t arb_point;
	struct cmd_fence_ctxt_t fence;
	struct cmd_dispatch_ctxt_t dispatch;
} __attribute__ ((__packed__));

struct global_fence_ctxt_t {
	s8 fence_cntr;
	u8 suspended_stream_index;
} __attribute__ ((__packed__));

struct firmware_ctxt_t {
	u32 sched_arc_num;
	u32 log_pi;
	struct sched_engine_arc_config_t eng_arc_cfg[MAX_ARC_CPUS];
};

struct sched_interface_ctxt_t {
	struct sched_registers_t sched_regs;
}  __attribute__ ((aligned(4), __packed__));

struct sched_hbm_data_t {
	u32 init_config_buffer[FIRMWARE_CONFIG_SIZE];
	char log_str[ARC_LOG_STR_BUF_SIZE];
}  __attribute__ ((aligned(4), __packed__));

int scheduler_main_init();
void scheduler_init();
void schedule();

#define SCHED_BLOCK_COUNT	3

extern struct sched_hbm_data_t sched_hbm_data;
extern struct scheduler_config_t *sched_post_init_config;
extern struct firmware_ctxt_t firmware_ctxt;
extern struct firmware_ctxt_t *fw_ctxt;
extern struct sched_interface_ctxt_t sched_interface_ctxt;
extern void (*const sched_blocks_pre_init[])(void);
extern void (*const sched_blocks_post_init[])(void);

#define engines_acquire(engine_group_type) (fw_ctxt->engine_groups_bitmap |= (1 << engine_group_type))
#define engines_release(engine_group_type) (fw_ctxt->engine_groups_bitmap &= ~(1 << engine_group_type))
#define engines_available(engine_group_type) ((fw_ctxt->engine_groups_bitmap & (1 << engine_group_type)) == 0)


#ifndef CORAL_BFM_MODE
#include "sched_fns.h"
#endif

#endif /* __SCHED_H__ */
