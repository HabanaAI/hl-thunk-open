# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

project(commontests C)

find_library(LIBFDT_LIBRARY fdt REQUIRED)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/specs
    ${CMAKE_SOURCE_DIR}/include/uapi
    ${LIBFDT_INCLUDE_DIR}
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
    dmabuf
    dma_buf
    dma_all2all
    debug
    profiling
    control_device
    error_injection
    root_debug
    tc
    nic_root
    debugfs
    nic
    cpucp
    odp
    negative_tests
    dfa
)

find_library(LIBFDT_LIBRARY fdt REQUIRED)
foreach(_UNIT_TEST ${COMMON_UNIT_TESTS})
    if (_UNIT_TEST STREQUAL "cpucp")
        add_cmocka_test(${_UNIT_TEST}
            SOURCES ${_UNIT_TEST}.c
            COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
            LINK_LIBRARIES
                ${TEST_TARGET_LIBRARIES}
                ${HLTHUNK_ERR_INJECT_TARGET}
                ${LIBFDT_LIBRARY}
        )
    else()
        add_cmocka_test(${_UNIT_TEST}
            SOURCES ${_UNIT_TEST}.c
            COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
            LINK_LIBRARIES
                ${TEST_TARGET_LIBRARIES}
                ${HLTHUNK_ERR_INJECT_TARGET}
        )
    endif()
endforeach()
