# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

project(commontests C)

include_directories(${CMAKE_SOURCE_DIR}/include)

set(COMMON_UNIT_TESTS
    open_close
    command_buffer
    command_submission
    dma
    dma_1KB_inc
    dma_4KB_inc
    dma_32KB_inc
    dma_128KB_inc
    dma_1MB_inc
    dma_4MB_inc
    dma_64MB_inc
    memory
    sync_manager
    tdr
    dma_perf
)

foreach(_UNIT_TEST ${COMMON_UNIT_TESTS})
    add_cmocka_test(${_UNIT_TEST}
                    SOURCES ${_UNIT_TEST}.c
                    COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                    LINK_LIBRARIES ${TEST_TARGET_LIBRARIES}
    )
endforeach()
