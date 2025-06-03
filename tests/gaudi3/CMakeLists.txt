# COPYRIGHT (c) 2021-2022 Habanalabs Ltd. See COPYING.md file

project(gaudi3tests C)

set(GAUDI3_UNIT_TESTS
    gaudi3_dma
    gaudi3_cbc
    gaudi3_sm
    gaudi3_root
    gaudi3_hldio
)

foreach(_UNIT_TEST ${GAUDI3_UNIT_TESTS})
    add_cmocka_test(${_UNIT_TEST}
                    SOURCES ${_UNIT_TEST}.c
                    COMPILE_OPTIONS ${DEFAULT_C_COMPILE_FLAGS}
                    LINK_LIBRARIES ${TEST_TARGET_LIBRARIES}
    )
endforeach()
