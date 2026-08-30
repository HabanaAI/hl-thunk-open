/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef CORAL_BFM_MODE
#include <arc_intrinsics.h>
#endif

#include "compile_target.h"

#ifdef CORAL_BFM_MODE
#include "scheduler_bfm.hpp"
#endif
#include "arc_types.h"
#include "common_params.h"
#include "dma.h"

#include "arc_sched.h"
#include "sw_queues.h"
#include "utils.h"
#include "arc_queues.h"
#include "arc_queue_local.h"
#include "arc_msgs.h"
#include "sob_common.h"
#include "sob_common_fns.h"
#include "debug.h"
#include "logger.h"

#include "sched_asic_specific_data.h"
#include "comm_asic_specific_data.h"

void CORAL_CLS_PREFIX send_data_to_queue(void *_buffer, u32 len, u32 cpu_id, u32 qid)
{
	u32 push_reg, *buffer = (u32 *)_buffer;

	push_reg = ARC_LBU_ADDR(fw_ctxt->eng_arc_cfg[cpu_id].arc_aux_base + (cr->push_reg & 0xfff) +
				qid * sizeof(u32));

	arc_printf(">>> %s forwarding %u bytes to engine %u via reg 0x%x\n",
		  __func__, len, cpu_id, push_reg);

	arc_assert(len % sizeof(u32) == 0);

	while (len) {
		len -= sizeof(u32);
		soc_reg_write(*(buffer++), push_reg);
	}
}

u32 CORAL_CLS_PREFIX sched_cmd_process_dispatch_static_ecb(u32 qid, u32 pi, u32 ci)
{
	struct sched_soft_queue_t *q = &sched_interface_ctxt.sched_regs.qs[qid];
	struct sched_arc_cmd_dispatch_static_ecb_t cmd;
	struct arc_cmd_dispatch_static_ecb_t msg;
	u32 cpu_id;

	if (arc_queue_data_length(pi, ci, sr->defs.dccm_q_act_size) < sizeof(cmd))
		return 0;

	arc_queue_grab_data(&cmd, q->q, sizeof(cmd), pi, ci, sr->defs.dccm_q_act_size);

	arc_printf(">>> %s qid = %u pi = %u ci = %u\n", __func__, qid, pi, ci);

	msg.opcode = ARC_CMD_DISPATCH_STATIC_ECB_OPCODE;
	msg.address = cmd.addr;
	msg.ecb_size = cmd.size;
	msg.engine_cpu_id = cmd.engine_cpu_id;

	for (cpu_id = cr->last_sched_id + 1; cpu_id < cr->max_arc_cpu_id; ++cpu_id) {
		if (!fw_ctxt->eng_arc_cfg[cpu_id].enabled)
			continue;
		if (cmd.engine_group_type == fw_ctxt->eng_arc_cfg[cpu_id].engine_group_type) {
			/* always send to engine queue 0 */
			send_data_to_queue(&msg, sizeof(msg), cpu_id, 0);
		}
	}

	return sizeof(cmd);
}

u32 CORAL_CLS_PREFIX sched_cmd_process_nop(u32 qid, u32 pi, u32 ci)
{
	struct sched_arc_cmd_nop_t cmd;

	if (arc_queue_data_length(pi, ci, sr->defs.dccm_q_act_size) < sizeof(cmd))
		return 0;

	arc_printf(">>> %s qid = %u pi = %u ci = %u\n", __func__, qid, pi, ci);

	arc_printf("Hello, I am NOP and I love to nop!\n");

	return sizeof(cmd);
}
