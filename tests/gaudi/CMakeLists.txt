# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

project(gauditests C)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/specs
)

set(GAUDI_UNIT_TESTS
    gaudi_dma
    gaudi_root
    gaudi_root_debug
    gaudi_mme_conv
)

foreach(_UNIT_TEST ${GAUDI_UNIT_TESTS})
    add_cmocka_test(${_UNIT_TEST}
                    SOURCES ${_UNIT_TEST}.c
                    COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                    LINK_LIBRARIES ${TEST_TARGET_LIBRARIES}
    )
endforeach()
