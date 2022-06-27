# COPYRIGHT (c) 2020-2021 Habanalabs Ltd. See COPYING.md file

project(gaudi2tests C)

set(GAUDI2_UNIT_TESTS
    gaudi2_dma
)

foreach(_UNIT_TEST ${GAUDI2_UNIT_TESTS})
    add_cmocka_test(${_UNIT_TEST}
                    SOURCES ${_UNIT_TEST}.c
                    COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                    LINK_LIBRARIES ${TEST_TARGET_LIBRARIES}
    )
endforeach()
