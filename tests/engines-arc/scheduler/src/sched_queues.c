#include "compile_target.h"

#ifdef CORAL_BFM_MODE
#include "scheduler_bfm.hpp"
#endif

#include "arc_types.h"

#include "dma.h"
#include "arc_sched.h"
#include "utils.h"
#include "debug.h"
#include "sw_queues.h"
#include "arc_msgs.h"
#include "arc_queue_local.h"
#include "common_logs.h"

#include "sched_asic_specific_data.h"

void CORAL_CLS_PREFIX sched_queues_pre_init()
{
	u32 i, pi;

	FW_UPDATE_BOOT_STATUS(SCHED_QUEUES_PRE_INIT_ENTRY);

	for (i = 0; i < sr->defs.dccm_qs_in_use; i++) {
		arc_aux_reg_write(
			ARC_DCCM_OFFSET(
				sched_interface_ctxt.sched_regs.qs[i].q),
			ARC_AUX_ADDR(sr->dccm_queue.base_addr) + i * 4);
		arc_aux_reg_write(
			sr->defs.dccm_q_act_size,
			ARC_AUX_ADDR(sr->dccm_queue.size) + i * 4);
		pi = arc_aux_reg_read(ARC_AUX_ADDR(sr->dccm_queue.pi) + i * 4);
		arc_aux_reg_write(pi, ARC_AUX_ADDR(sr->dccm_queue.ci) + i * 4);
	}

	FW_UPDATE_BOOT_STATUS(SCHED_QUEUES_PRE_INIT_EXIT);
}

void CORAL_CLS_PREFIX sched_queues_post_init()
{
	FW_UPDATE_BOOT_STATUS(SCHED_QUEUES_POST_INIT_ENTRY);

	FW_UPDATE_BOOT_STATUS(SCHED_QUEUES_POST_INIT_EXIT);
}
