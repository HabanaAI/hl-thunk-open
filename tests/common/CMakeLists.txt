# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

project(commontests C)

include_directories(${CMAKE_SOURCE_DIR}/include)

set(COMMON_UNIT_TESTS
    basic
)

foreach(_UNIT_TEST ${COMMON_UNIT_TESTS})
    add_cmocka_test(${_UNIT_TEST}
                    SOURCES ${_UNIT_TEST}.c
                    COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                    LINK_LIBRARIES ${TEST_TARGET_LIBRARIES}
    )
endforeach()
