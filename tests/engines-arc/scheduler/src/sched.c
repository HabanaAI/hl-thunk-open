/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */

#include "arc_host_packets.h"
#include "arc_sched_packets.h"

#include "compile_target.h"

#include "sched_asic_specific_data.h"
#include "comm_asic_specific_data.h"

#ifdef CORAL_BFM_MODE
#include "scheduler_bfm.hpp"
#else
#include <arc_intrinsics.h>
#endif

#include "arc_types.h"
#include "common_params.h"
#include "dma.h"
#include "arc_sched.h"
#include "utils.h"
#include "debug.h"
#include "arc_queues.h"
#include "arc_queue_local.h"
#include "arc_msgs.h"

#include "sob_common.h"
#include "sob_common_fns.h"
#include "common_logs.h"
#include "logger.h"

#ifndef CORAL_BFM_MODE
#include "dma_fns.h"
#include "sched_fns.h"
#include "sched_gbls.h"
#include "sched_regs_gbls.h"
#endif

void CORAL_CLS_PREFIX sched_ctxt_pre_init()
{
	u32 asic_model = sched_interface_ctxt.sched_regs.common_regs.asic_model;

	FW_UPDATE_BOOT_STATUS(SCHED_CTXT_PRE_INIT_ENTRY);

	switch (asic_model) {
		case ARC_ASIC_MODEL_GAUDI2:
			LOG_INFO(get_module_name(), "Running GAUDI2 FW");
			sr = &gaudi2_sched_regs;
			cr = &gaudi2_comm_regs;
			break;
		case ARC_ASIC_MODEL_GAUDI3:
			LOG_INFO(get_module_name(), "Running GAUDI3 FW");
			sr = &gaudi3_sched_regs;
			cr = &gaudi3_comm_regs;
			break;
		default:
			/* TODO: We currently don't have a way to fail FW load */
			LOG_INFO(get_module_name(), "Unknown ASIC model {}", asic_model);
			break;
	}

	fw_ctxt = &firmware_ctxt;

	arc_memset(&sched_interface_ctxt, 0x0, sizeof(sched_interface_ctxt));
	arc_memset(&firmware_ctxt, 0x0, sizeof(firmware_ctxt));

	sched_interface_ctxt.sched_regs.common_regs.asic_model = asic_model;

	fw_ctxt->sched_arc_num = arc_aux_reg_read(ARC_AUX_ADDR(sr->arc_num));

	LOG_INFO(get_module_name(), "SCHED_ARC_CPU_ID = {}", fw_ctxt->sched_arc_num);

	FW_UPDATE_BOOT_STATUS(SCHED_CTXT_PRE_INIT_EXIT);
}

void CORAL_CLS_PREFIX sched_ctxt_post_init()
{
	arc_memcpy(fw_ctxt->eng_arc_cfg, sched_post_init_config->eng_arc_cfg,
		   sizeof(fw_ctxt->eng_arc_cfg));
}

u32 CORAL_CLS_PREFIX compute_process_host_queue(u32 qid, u32 pi, u32 ci)
{
	u32 cmd_opcode;
	u32 step = 0;
	struct sched_soft_queue_t *q = &sched_interface_ctxt.sched_regs.qs[qid];

	arc_assert(arc_queue_data_length(pi, ci, sr->defs.dccm_q_act_size) >= sizeof(uint32_t));

	arc_printf("New command first 4 bytes: 0x%x, qid = %u pi = %u ci = %u\n",
		  __get_unaligned_t(u32, q->q + ci), qid, pi, ci);

	cmd_opcode = __get_unaligned_t(u32, q->q + ci) & 0x1F;

	arc_assert_msg(cmd_opcode < SCHED_ARC_CMD_COUNT, "%d", cmd_opcode);

	step = qman_cmds_api[cmd_opcode](qid, pi, ci);
	arc_assert(step % sizeof(u32) == 0);

	return step;
}

void CORAL_CLS_PREFIX schedule()
{
	u32 ret = 1;
	u32 qid;
	u32 pi, cis[MAX_SCHED_QUEUE_COUNT], step;

	arc_printf("Scheduler %u main loop started\n", fw_ctxt->sched_arc_num);

	arc_memset(cis, 0, MAX_SCHED_QUEUE_COUNT * sizeof(*cis));
	for (qid = 0; qid < sr->defs.dccm_qs_in_use; ++qid)
		cis[qid] = arc_queue_local_ci(qid);

	while (ret) {
#ifdef CORAL_BFM_MODE
		FW_WHILE(ret);
		if (!yield(true))
			break;
#endif
		for (qid = 0; qid < sr->defs.dccm_qs_in_use; ++qid) {
			pi = arc_queue_local_pi(qid);
			if (pi != cis[qid]) {
				step = compute_process_host_queue(qid, pi,
								  cis[qid]);
				if (step) {
					cis[qid] = arc_queue_move_ci(
						step, cis[qid],
						sr->defs.dccm_q_act_size);
					arc_queue_local_update_ci(qid,
								  cis[qid]);
				}
			}
		}
	}
}
