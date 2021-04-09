# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

project(commontests C)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/specs
)

set(COMMON_UNIT_TESTS
    open_close
    command_buffer
    command_submission
    sync_manager
    memory
    dma
    dma_sram
    dma_dram
    dma_perf
    dma_buf
    debug
    profiling
    control_device
    error_injection
    root_debug
)

foreach(_UNIT_TEST ${COMMON_UNIT_TESTS})
    add_cmocka_test(${_UNIT_TEST}
                    SOURCES ${_UNIT_TEST}.c
                    COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                    LINK_LIBRARIES ${TEST_TARGET_LIBRARIES} ${HLTHUNK_ERR_INJECT_TARGET}
    )
endforeach()
