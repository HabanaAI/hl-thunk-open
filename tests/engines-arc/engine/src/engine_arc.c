/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#include "compile_target.h"

#ifdef CORAL_BFM_MODE
#include "engine_bfm.hpp"
#endif

#include "arc_types.h"
#include "engine_arc.h"
#include "arc_queues.h"
#include "arc_msgs.h"
#include "debug.h"
#include "qman_if.h"
#include "dma.h"
#include "sob_common.h"
#include "sob_common_fns.h"
#include "compute_wd.h"
#include "eng_regs.h"
#include "logger.h"

#ifndef CORAL_BFM_MODE
#include "dma_fns.h"
#include "engine_arc_gbls.h"

extern struct arc_queue_ctxt_t arc_queue_ctxt[];

#endif

#include "eng_asic_specific_data.h"
#include "comm_asic_specific_data.h"

u32 CORAL_CLS_PREFIX get_qm_base()
{
	return engine_ctxt.qm_base;
}

void CORAL_CLS_PREFIX eng_ctxt_pre_init()
{
	u32 arc_num;
	u32 asic_model = engine_interface_ctxt.regs.common_regs.asic_model;

	switch (asic_model) {
		case ARC_ASIC_MODEL_GAUDI2:
			LOG_INFO(get_module_name(), "Running GAUDI2 FW");
			sr = &gaudi2_eng_regs;
			cr = &gaudi2_comm_regs;
			break;
		case ARC_ASIC_MODEL_GAUDI3:
			LOG_INFO(get_module_name(), "Running GAUDI3 FW");
			sr = &gaudi3_eng_regs;
			cr = &gaudi3_comm_regs;
			break;
		default:
			/* TODO: We currently don't have a way to fail FW load */
			LOG_ERR(get_module_name(), "Unknown ASIC model {}", asic_model);
			break;
	}

	arc_memset(&engine_interface_ctxt, 0x0, sizeof(engine_interface_ctxt));
	arc_memset(&engine_ctxt, 0x0, sizeof(engine_ctxt));

	engine_interface_ctxt.regs.common_regs.asic_model = asic_model;

	arc_num = arc_aux_reg_read(ARC_AUX_ADDR(sr->mme_qm.arc_num));

	LOG_INFO(get_module_name(), "ARC_CPU_ID = {}", arc_num);
	arc_assert((arc_num > cr->last_sched_id) && (arc_num < cr->max_arc_cpu_id));

	engine_ctxt.eng_cpu_id = arc_num;
}

void CORAL_CLS_PREFIX eng_ctxt_post_init()
{
	engine_ctxt.qm_base = eng_post_init_config->qm_base;

	/*
	 * Read the CI registers again to align with our internal PI registers
	 * This is because host SW may have pushed some packets into CQ Fetcher
	 *
	 * Since the shadow register write back is not enabled yet we have to
	 * read from the actual QMAN registers, after that always read from AUX Shadow copies
	 */
	engine_ctxt.arc_cq_fifo_pi = soc_reg_read(ARC_QM_ADDR(sr->mme_qm.ififo_ci));

	/*
	 * Enable shadow register writing
	 */
	soc_reg_write(0x6, ARC_QM_ADDR(sr->mme_qm.arc_cq_cfg0));

	/*
	 * Write to shadow registers to ensure the registers were updated
	 */
	arc_aux_reg_write(engine_ctxt.arc_cq_fifo_pi, ARC_AUX_ADDR(sr->mme_qm.arc_cq_shadow_ci));

	/*
	 * Wrapping to FIFO size
	 */
	engine_ctxt.arc_cq_fifo_pi %= (QMAN_ARC_CQ_FIFO_SIZE * 2);


	/* TODO: Understand what this one does. Do we need it? */
	/*
	 * Enable the switching
	 */
	soc_reg_write(0x1, ARC_QM_ADDR(sr->mme_qm.cp_ext_switch));
	soc_reg_write(0x1, ARC_QM_ADDR(sr->mme_qm.cp_ext_switch));
}

void CORAL_CLS_PREFIX copy_command_from_queue(u32 local_q_id,
			     u32 *cmd_buffer, u8 cmd_size)
{
	struct arc_queue_ctxt_t *queue_ctxt;
	u16 queue_size;
	u32 *buff_ptr;
	u16 i = 0, ci;

	queue_ctxt = (struct arc_queue_ctxt_t *)&arc_queue_ctxt[local_q_id];

	ci = queue_ctxt->ci;
	queue_size = queue_ctxt->size;
	buff_ptr = (u32 *)(queue_ctxt->base + ci);

	while (ci < queue_size) {
		cmd_buffer[i] = *buff_ptr;
		buff_ptr++; i++;
		ci += 4;
	}

	buff_ptr = (u32 *)queue_ctxt->base;
	while (i < cmd_size) {
		cmd_buffer[i] = *buff_ptr;
		buff_ptr++; i++;
	}
}

void CORAL_CLS_PREFIX copy_command_to_queue(u32 local_q_id,
			     u32 *cmd_buffer, u8 cmd_size)
{
	struct arc_queue_ctxt_t *queue_ctxt;
	u16 queue_size;
	u32 *buff_ptr;
	u16 i = 0, ci;

	queue_ctxt = (struct arc_queue_ctxt_t *)&arc_queue_ctxt[local_q_id];

	ci = queue_ctxt->ci;
	queue_size = queue_ctxt->size;
	buff_ptr = (u32 *)(queue_ctxt->base + ci);

	while (ci < queue_size) {
		*buff_ptr = cmd_buffer[i];
		buff_ptr++; i++;
		ci += 4;
	}

	buff_ptr = (u32 *)queue_ctxt->base;
	while (i < cmd_size) {
		*buff_ptr = cmd_buffer[i];
		buff_ptr++; i++;
	}
}

void CORAL_CLS_PREFIX process_dispatch_static_ecb(u32 local_q_id)
{
	u32 cmd_buffer[ARC_CMD_DISPATCH_STATIC_ECB_SIZE_DWORD];
	struct arc_cmd_dispatch_static_ecb_t *cmd_ptr;
	struct arc_queue_ctxt_t *queue_ctxt;
	u32 valid_entries, blocking = 1;
	u32 addr_lo, addr_hi, size;
	u16 queue_size, ci;

	queue_ctxt = (struct arc_queue_ctxt_t *)&arc_queue_ctxt[local_q_id];
	ci = queue_ctxt->ci;

	valid_entries = arc_queue_local_valid_entries(local_q_id);

	if (valid_entries < ARC_CMD_DISPATCH_STATIC_ECB_SIZE) {
		return;
	}

	queue_size = queue_ctxt->size;
	if (ci + ARC_CMD_DISPATCH_STATIC_ECB_SIZE <= queue_size) {
		cmd_ptr = (struct arc_cmd_dispatch_static_ecb_t *)(queue_ctxt->base + ci);
	} else {
		cmd_ptr = (struct arc_cmd_dispatch_static_ecb_t *)cmd_buffer;
		copy_command_from_queue(local_q_id, cmd_buffer,
				ARC_CMD_DISPATCH_STATIC_ECB_SIZE_DWORD);
	}

	/*
	 * check if the command needs to be processed by this engine
	 * arc instance, else skip it.
	 */
	if (cmd_ptr->engine_cpu_id != engine_ctxt.eng_cpu_id) {
		queue_ctxt->ci += ARC_CMD_DISPATCH_STATIC_ECB_SIZE;
		arc_printf(">>> %s qid %u arc %u - skipping, command is not for me but for %u\n",
			  __func__, local_q_id, engine_ctxt.eng_cpu_id, cmd_ptr->engine_cpu_id);
		return;
	}

	arc_printf(">>> %s qid %u arc %u\n", __func__, local_q_id, engine_ctxt.eng_cpu_id);

	addr_lo = (u32)cmd_ptr->address;
	addr_hi = (u32)(cmd_ptr->address >> 32ULL);
	size = cmd_ptr->ecb_size;

	/* TODO: remove all this queue_ctxt */
	/*
	 * Note: In order to avoid switching the static ECB command is also
	 * pushed into ARC CQ fetcher.
	 */
	arc_cq_fetcher_check_fifo_level(blocking);
	arc_cq_fetcher_push_dynamic_desc(addr_lo, addr_hi, size);

	queue_ctxt->ci += ARC_CMD_DISPATCH_STATIC_ECB_SIZE;
}

u32 CORAL_CLS_PREFIX arc_cq_fetcher_check_fifo_level(u32 blocking)
{
	struct engine_ctxt_t *eng_ctxt;
	u32 pi, ci, free_space;

	eng_ctxt = &engine_ctxt;

	/*
	 * In the case of ARC CQ Fetcher, we need to see if the packet
	 * has actually been processed, so that we can reuse that memory
	 * for the next packet and so on.
	 */
	pi = eng_ctxt->arc_cq_fifo_pi;

	do {
		ci = arc_aux_reg_read(ARC_AUX_ADDR(sr->mme_qm.arc_cq_shadow_ci));
		free_space = QMAN_ARC_CQ_FIFO_SIZE - (((ci > pi) ? (ci - pi) : (pi - ci)) & 0xF);
		FW_WHILE(true);
	} while (!free_space && blocking);

	return free_space;
}

/*
 * This API assumes there is a space in the FIFO
 * else it may create back pressure
 */
void CORAL_CLS_PREFIX arc_cq_fetcher_push_dynamic_desc(u32 addr_lo, u32 addr_hi, u32 size)
{
	struct engine_ctxt_t *eng_ctxt;

	eng_ctxt = &engine_ctxt;

	/*
	 * Buffer should have at least one command and size of the command
	 * is at least 8 bytes
	 */
	arc_assert(size >= 8);

	soc_reg_write(addr_hi, ARC_QM_ADDR(sr->arc_cq.lbu_arc_cq_ptr_hi));
	soc_reg_write((u32)addr_lo, ARC_QM_ADDR(sr->arc_cq.lbu_arc_cq_ptr_lo));
	soc_reg_write(size, ARC_QM_ADDR(sr->arc_cq.lbu_arc_cq_tsize));
	soc_reg_write((u32)QMAN_ARC_CQ_CTL_DEFAULT_VALUE, ARC_QM_ADDR(sr->arc_cq.lbu_arc_cq_ctl));

	/*
	 * Note: The PI and CI indexes of the ARC CQ Fetcher and CQ Fetcher
	 * wraps around at 16, but the FIFO sizes are only 8
	 */
	eng_ctxt->arc_cq_fifo_pi++;
	eng_ctxt->arc_cq_fifo_pi %= (QMAN_ARC_CQ_FIFO_SIZE * 2);
}

void CORAL_CLS_PREFIX compute_process_sched_queue(u32 local_q_id)
{
	struct arc_queue_ctxt_t *queue_ctxt;
	struct arc_cmd_generic_t *cmd_ptr;

	queue_ctxt = (struct arc_queue_ctxt_t *)&arc_queue_ctxt[local_q_id];

	cmd_ptr = (struct arc_cmd_generic_t *)(queue_ctxt->base + queue_ctxt->ci);

	switch(cmd_ptr->opcode) {
	case ARC_CMD_DISPATCH_STATIC_ECB_OPCODE:
		process_dispatch_static_ecb(local_q_id);
	break;
	default:
		arc_assert(0);
	break;
	}

	queue_ctxt->ci %= queue_ctxt->size;

	arc_queue_local_update_ci(local_q_id, queue_ctxt->ci);
}

void CORAL_CLS_PREFIX compute_process_sched_queues()
{
	u32 prio;
	u32 ret = 1;

	checkpoint(0x11000011);

#ifdef CORAL_BFM_MODE
	bool wait_for_new_input = false;
#endif

	while (ret) {

#ifdef CORAL_BFM_MODE
		FW_WHILE(ret);
		if (!yield(wait_for_new_input))
			break;

		wait_for_new_input = true;
#endif

		prio = ENGINE_ARC_QUEUE_SCHED_QID0;

		do {

			if (arc_queue_local_valid_entries((u32) prio)) {

				checkpoint(0x11000012);

				compute_process_sched_queue((u32)prio);

#ifdef CORAL_BFM_MODE
				wait_for_new_input = false;
#endif

				continue;
			}
			prio++;

		} while (prio < COMPUTE_DCCM_QUEUE_COUNT);
	}
}
