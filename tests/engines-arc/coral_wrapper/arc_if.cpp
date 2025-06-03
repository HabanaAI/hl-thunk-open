#include <iostream>

#ifdef ENGINE_ARC
#include "engine_bfm.hpp"
#endif
#ifdef SCHED_ARC
#include "scheduler_bfm.hpp"
#endif

#include "arc_bfm.h"
#include "bfm.hpp"

extern "C" ArcBFMIf* create_engine_v2(void* dccmMem, void* hbmMem){
    return new ArcBFMIf(dccmMem, hbmMem);
}

extern "C" void register_cb_handler(ArcBFMIf* module, Engine_Fw_Cb_Handler_t* _fw_handle){
    module->register_handler(_fw_handle);
    module->register_sim_handler();
}

extern "C" Simulator_Fw_Handler_t* get_sim_handler(ArcBFMIf *module)
{
    return &module->sim_handler;
}

extern "C" void delete_engine(ArcBFMIf* module){
    delete module;
}

ArcBFMIf::ArcBFMIf(void* dccmMem, void* hbmMem)
{
#ifdef ENGINE_ARC
    impl = std::unique_ptr<EngineBFM>(new EngineBFM(dccmMem, hbmMem));
#endif
#ifdef SCHED_ARC
    impl = std::unique_ptr<SchedulerBFM>(new SchedulerBFM(dccmMem, hbmMem));
#endif
}

ArcBFMIf::~ArcBFMIf() = default;

void ArcBFMIf::main_init(){
    impl->main_init();
}

void ArcBFMIf::main_exec(coro_t::push_type& source){
    impl->main_exec_flow(source);
}

size_t ArcBFMIf::get_dccm_contents_size(){
    return impl->get_dccm_contents_size();
}

void* ArcBFMIf::get_dccm_base(){
    return impl->get_dccm_base();
}

void* ArcBFMIf::get_hbm_base(){
    return impl->get_hbm_base();
}

void ArcBFMIf::register_handler(Engine_Fw_Cb_Handler_t* _fw_handle)
{
    impl->register_handler(_fw_handle);
}

void ArcBFMIf::update_terminate(){
    impl->update_terminate();
}

void ArcBFMIf::register_sim_handler()
{
    using std::placeholders::_1;
    sim_handler.main_init_api = std::bind(&ArcBFMIf::main_init, this);
    sim_handler.main_exec_api = std::bind(&ArcBFMIf::main_exec, this, _1);
    sim_handler.get_dccm_base_api = std::bind(&ArcBFMIf::get_dccm_base, this);
    sim_handler.get_hbm_base_api = std::bind(&ArcBFMIf::get_hbm_base, this);
    sim_handler.get_dccm_contents_size_api = std::bind(&ArcBFMIf::get_dccm_contents_size, this);
    sim_handler.update_terminate_api = std::bind(&ArcBFMIf::update_terminate, this);
}