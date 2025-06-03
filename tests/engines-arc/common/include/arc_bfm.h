#ifndef ENGINE_IF_TO_BFM_
#define ENGINE_IF_TO_BFM_

#include <memory>
#include <functional>
#include <exception>
#include <linux/types.h>

#include <boost/bind.hpp>
#include <boost/coroutine2/all.hpp>
#include <boost/optional.hpp>

using coro_t = boost::coroutines2::coroutine<boost::optional<std::function<bool()>>>;
typedef std::function<void(bool)> assert_fn;
typedef std::function<__u8(__u8,__u32,void*,__u32)> dma_read_fn;
typedef std::function<void(__u32, std::string &)> regread_fn;
typedef std::function<void(__u32,__u32, const char*, __u32)> store_reg_token_fn;
typedef std::function<__u32(__u32, const char*, __u32)> load_reg_token_fn;
typedef std::function<__u32(__u64, const char*, __u32)> lbw_read_token_fn;
typedef std::function<void(__u32,__u64, const char*, __u32)> lbw_write_token_fn;
typedef std::function<bool(bool)> yield_fn;
typedef std::function<void(void)> dsync_fn;
typedef std::function<__u32(__u8)> is_dma_completed_fn;
typedef std::function<__u8(__u8,__u8 *)> dma_check_completion_fn;
typedef std::function<void(__u8)> dma_wait_for_completion_fn;
typedef std::function<void(__u32)> dma_wait_for_multiple_completions_fn;
typedef std::function<__u32()> get_dma_completion_fn;
typedef std::function<void(__u32)> set_dma_completion_clear_fn;


struct Engine_Fw_Cb_Handler_t
{

    Engine_Fw_Cb_Handler_t& operator=(const Engine_Fw_Cb_Handler_t& handle)
    {
        assert_api = handle.assert_api;
        dma_read_api = handle.dma_read_api;
        store_reg_token_api = handle.store_reg_token_api;
        load_reg_token_api = handle.load_reg_token_api;
        lbw_read_token_api = handle.lbw_read_token_api;
        lbw_write_token_api = handle.lbw_write_token_api;
        yield_api = handle.yield_api;
        dsync_api = handle.dsync_api;
        dma_status_api = handle.dma_status_api;
        dma_check_completion_api = handle.dma_check_completion_api;
        dma_wait_for_completion_api = handle.dma_wait_for_completion_api;
        dma_wait_for_multiple_completions_api = handle.dma_wait_for_multiple_completions_api;
        get_dma_completion_api = handle.get_dma_completion_api;
        set_dma_completion_clear_api = handle.set_dma_completion_clear_api;
        module_name = handle.module_name;
        regread_api = handle.regread_api;
        device_instance = handle.device_instance;

        return *this;
    }

    assert_fn   assert_api;
    dma_read_fn dma_read_api;
    store_reg_token_fn store_reg_token_api;
    load_reg_token_fn load_reg_token_api;
    lbw_read_token_fn lbw_read_token_api;
    lbw_write_token_fn lbw_write_token_api;
    yield_fn yield_api;
    dsync_fn dsync_api;
    is_dma_completed_fn dma_status_api;
    dma_check_completion_fn dma_check_completion_api;
    dma_wait_for_completion_fn dma_wait_for_completion_api;
    dma_wait_for_multiple_completions_fn dma_wait_for_multiple_completions_api;
    get_dma_completion_fn get_dma_completion_api;
    set_dma_completion_clear_fn set_dma_completion_clear_api;
    const char * module_name;
    regread_fn  regread_api;
    int32_t   device_instance;
};


typedef std::function<void()> main_init_fn;
typedef std::function<void(coro_t::push_type& source)> main_exec_fn;
typedef std::function<void*()> get_dccm_base_fn;
typedef std::function<void*()> get_hbm_base_fn;
typedef std::function<size_t()> get_dccm_contents_size_fn;
typedef std::function<void()> update_terminate_fn;

struct Simulator_Fw_Handler_t
{
    Simulator_Fw_Handler_t& operator=(const Simulator_Fw_Handler_t& handle)
    {
        main_init_api = handle.main_init_api;
        main_exec_api = handle.main_exec_api;
        get_dccm_base_api = handle.get_dccm_base_api;
        get_dccm_contents_size_api = handle.get_dccm_contents_size_api;
        update_terminate_api = handle.update_terminate_api;
        return *this;
    }

    main_init_fn main_init_api;
    main_exec_fn main_exec_api;
    get_dccm_base_fn get_dccm_base_api;
    get_dccm_contents_size_fn get_dccm_contents_size_api;
    update_terminate_fn update_terminate_api;
    get_hbm_base_fn get_hbm_base_api;
};


class ArcBFM;
class ArcBFMIf
{
public:

    ArcBFMIf(void* dccmMem, void *hbmMem);
    ~ArcBFMIf();

    void main_init();
    void main_exec(coro_t::push_type& source);
    void* get_dccm_base();
    void* get_hbm_base();
    size_t get_dccm_contents_size();
    void register_handler(Engine_Fw_Cb_Handler_t* _fw_handle);
    void register_sim_handler();
    void update_terminate();

    Simulator_Fw_Handler_t sim_handler;
private:
    std::unique_ptr<ArcBFM> impl;
};

class terminate_exec : std::exception {
};

extern "C"
{
    ArcBFMIf *create_engine_v2(void* dccmMem, void* hbmMem);
    void register_cb_handler(ArcBFMIf* module, Engine_Fw_Cb_Handler_t* _fw_handle);
    Simulator_Fw_Handler_t* get_sim_handler(ArcBFMIf* module);
    void delete_engine(ArcBFMIf* module);
};

#endif //ENGINE_IF_TO_BFM_
