# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

project(goyatests C)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/specs
)

set(GOYA_UNIT_TESTS
    goya_root
    goya_dma
)

foreach(_UNIT_TEST ${GOYA_UNIT_TESTS})
    add_cmocka_test(${_UNIT_TEST}
                    SOURCES ${_UNIT_TEST}.c
                    COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                    LINK_LIBRARIES ${TEST_TARGET_LIBRARIES}
    )
endforeach()
