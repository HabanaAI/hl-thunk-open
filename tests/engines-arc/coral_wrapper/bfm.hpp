#ifndef ARC_BFM_INC_HPP_
#define ARC_BFM_INC_HPP_
#include <functional>
#include <map>
#include <iostream>
#include <linux/types.h>

#include <boost/bind.hpp>
#include <boost/coroutine2/all.hpp>
#include <boost/optional.hpp>

#include "compile_target.h"
#include "arc_types.h"
#include "sw_queues.h"
#include "arc_bfm.h"
#include "dma.h"
#include "utils.h"
#include "logger.h"

class ArcBFM
{
public:

    ~ArcBFM()
    {
        DROP_LOGGER(get_module_name());
    }

    void register_handler(Engine_Fw_Cb_Handler_t* _fw_handle)
    {
        assert = _fw_handle->assert_api;
        m_cb_handler = *_fw_handle;
        CREATE_LOGGER(m_cb_handler.module_name, QMAN_LOG_FILE, LOG_SIZE, LOG_AMOUNT);
    }

    void update_terminate()
    {
        terminate = true;
    }

    virtual void main_init() = 0;
    virtual void main_exec_flow(coro_t::push_type& source) = 0;
    virtual void* get_dccm_base() = 0;
    virtual void* get_hbm_base() = 0;
    virtual size_t get_dccm_contents_size() = 0;

protected:

    void while_yield(std::function<bool()> fn){
        if(!while_yield_ptr){
            return;//support for FS6. TODO:: replace with assert
        }
        while_yield_ptr->operator()(fn);
        if(terminate){
            throw terminate_exec();
        }
    }

    void sr_cb(__u32 val, __u32 reg_addr, const char *file, __u32 line)
    {
        m_cb_handler.store_reg_token_api(val, reg_addr, file, line);
    }

    __u32 lr_cb(__u32 reg_addr, const char *file, __u32 line)
    {
        return m_cb_handler.load_reg_token_api(reg_addr, file, line);
    }

    u64 soc_reg_read_cb(__u32 reg_addr, const char *file, __u32 line)
    {
        return m_cb_handler.lbw_read_token_api(reg_addr, file, line);
    }

    void soc_reg_write_cb(__u32 val, __u32 reg_addr, const char *file, __u32 line)
    {
        m_cb_handler.lbw_write_token_api(val, reg_addr, file, line);
    }

    bool yield(bool wait_for_writes)
    {
        return m_cb_handler.yield_api(wait_for_writes);
    }

    void _dsync(void)
    {
        m_cb_handler.dsync_api();
    }

    u32 _ffs(u32 value)
    {
        u32 i = 0;
        while (i < 32) {
            if (value & (1 << i)) {
                return i;
            }
            i++;
        }
        return 0;
    }

    const char * get_module_name()
    {
        return m_cb_handler.module_name;
    }

    void arc_assert(bool flag)
    {
       assert(flag);
    }

    Engine_Fw_Cb_Handler_t m_cb_handler;
    assert_fn assert;
    bool terminate = false;
    coro_t::push_type* while_yield_ptr = nullptr;

};

#endif //ARC_BFM_INC_HPP_
