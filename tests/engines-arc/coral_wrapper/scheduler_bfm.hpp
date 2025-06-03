#ifndef SCHEDULER_ARC_BFM_INC_HPP_
#define SCHEDULER_ARC_BFM_INC_HPP_

#include "arc_common_packets.h"
#include "arc_host_packets.h"

#include "compile_target.h"

#include "arc_types.h"
#include "common_params.h"
#include "arc_queues.h"
#include "arc_sched.h"
#include "sw_queues.h"
#include "arc_queue_local.h"
#include "utils.h"
#include "sob_common.h"

#include "bfm.hpp"

class SchedulerBFM : public ArcBFM
{
public:
#include "dma_fns.h"
#include "logger_fns.h"
#include "sched_fns.h"
#include "arc_queue_local_fns.h"
#include "debug_fns.h"
#include "utils_fns.h"
#include "sched_regs_gbls.h"

SchedulerBFM(void* dccmMem, void *hbmMem):
    sched_interface_ctxt(*(sched_interface_ctxt_t*)dccmMem),
    sched_hbm_data(*(sched_hbm_data_t*)hbmMem),
    sched_post_init_config(0)
    {}

~SchedulerBFM() = default;

void main_init()
{
    scheduler_main_init();
}

void main_exec_flow(coro_t::push_type& source)
{
    while_yield_ptr = &source;
    scheduler_main_init();
}

void* get_dccm_base()
{
    return (void*)&sched_interface_ctxt;
}

void* get_hbm_base()
{
    return (void*)&sched_hbm_data;
}

size_t get_dccm_contents_size()
{
    return sizeof(sched_interface_ctxt_t);
}

private:
#include "sched_gbls.h"
#include "sob_common_fns.h"

};

#endif //SCHEDULER_ARC_BFM_INC_HPP_
