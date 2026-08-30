
#ifndef ENGINE_ARC_BFM_INC_HPP_
#define ENGINE_ARC_BFM_INC_HPP_

#include "arc_common_packets.h"
#include "arc_host_packets.h"

#include "compile_target.h"

#include "common_params.h"
#include "arc_queue_local.h"
#include "engine_arc.h"
#include "arc_msgs.h"
#include "compute_wd.h"
#include "qman_if.h"
#include "hw_qman.h"
#include "sob_common.h"

#include "bfm.hpp"

class EngineBFM : public ArcBFM
{
public:
#include "dma_fns.h"
#include "logger_fns.h"
#include "utils_fns.h"
#include "debug_fns.h"
#include "arc_queue_pvt_fns.h"
#include "engine_arc_fns.h"
#include "qman_if_fns.h"
#include "arc_queue_local_fns.h"
#include "eng_regs_fns.h"
#include "eng_regs_gbls.h"

EngineBFM(void* dccmMem, void *hbmMem):
    engine_interface_ctxt(*(engine_interface_ctxt_t*)dccmMem),
    eng_hbm_data(*(eng_hbm_data_t*)hbmMem),
    eng_post_init_config(0)
    {}

~EngineBFM() = default;

void main_init()
{
    engine_main_init();
}

void main_exec_flow(coro_t::push_type& source){
    while_yield_ptr = &source;
    engine_main_init();
}

void* get_dccm_base()
{
    return (void*)&engine_interface_ctxt;
}

void* get_hbm_base()
{
    return (void*)&eng_hbm_data;
}

size_t get_dccm_contents_size()
{
    return sizeof(engine_interface_ctxt_t);
}

private:
#include "engine_arc_gbls.h"
#include "arc_queue_pvt_gbls.h"
#include "qman_if_gbls.h"
#include "main_gbls.h"
#include "sob_common_fns.h"
};

#endif// ENGINE_ARC_BFM_INC_H_


