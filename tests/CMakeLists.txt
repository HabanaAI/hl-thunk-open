# COPYRIGHT (c) 2019-2021 Habanalabs Ltd. See COPYING.md file

project(libhl-thunk-tests C)

set(HLTHUNK_TESTS_LIBRARY hl-thunk-tests)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")

set(hbldv $ENV{RDMA_CORE_ROOT}/build/lib/libhbl.so)
set(ibverbs $ENV{RDMA_CORE_ROOT}/build/lib/libibverbshl.so)
include_directories($ENV{RDMA_CORE_ROOT}/build/include)

add_definitions(-DHLTHUNK_BUILD_PATH="${CMAKE_BUILD_PATH}")
add_definitions(-DHLTESTS_ENG_ARC_IMG_DCCM_SIZE="${HLTESTS_ENG_ARC_IMG_DCCM_SIZE}")
add_definitions(-DHLTESTS_SCHED_ARC_IMG_DCCM_SIZE="${HLTESTS_SCHED_ARC_IMG_DCCM_SIZE}")

if (SANITIZE_ON)
    add_definitions(-DHLTHUNK_TESTS_SANITIZER)
endif()

find_package(Boost
    REQUIRED
)

if (HLTESTS_LIB_MODE)
    include_directories(
        ${CMAKE_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include/specs
        ${CMAKE_SOURCE_DIR}/include/specs/common
        ${CMAKE_SOURCE_DIR}/include/uapi
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/klib
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/argparse
        ${CMAKE_CURRENT_SOURCE_DIR}/inih
        ${Boost_INCLUDE_DIRS}
    )

    set(HLTHUNK_TESTS_LINK_LIBRARIES
        ${HLTHUNK_TARGET})

    file(GLOB SRC common/*.c gaudi/*.c gaudi2/*.c gaudi3/*.c goya/*.c
	inih/*.c mersenne-twister/*.c argparse/*.c config_iterator/*.c) # compile all files with *.c suffix

    exec_program(
        "git"
        ${CMAKE_CURRENT_SOURCE_DIR}
        ARGS "rev-parse --short HEAD"
        OUTPUT_VARIABLE HLTHUNK_TESTS_SHA1_VERSION
        RETURN_VALUE GIT_RC)

    IF(NOT "${GIT_RC}" EQUAL 0)
        set(HLTHUNK_TESTS_SHA1_VERSION "")
    ENDIF()

    # generate version.c
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.c.in" "${CMAKE_CURRENT_BINARY_DIR}/version.c" @ONLY)

    # Build shared/static libraries from all specified source files
    add_library(${HLTHUNK_TESTS_LIBRARY} SHARED ${SRC} ${CMAKE_CURRENT_BINARY_DIR}/version.c)

    set_target_properties(${HLTHUNK_TESTS_LIBRARY} PROPERTIES
        C_VISIBILITY_PRESET       default
        VISIBILITY_INLINES_HIDDEN NO
    )

    target_link_libraries(${HLTHUNK_TESTS_LIBRARY} ${HLTHUNK_TESTS_LINK_LIBRARIES} m)
    target_link_libraries(${HLTHUNK_TESTS_LIBRARY} ${ibverbs} ${hbldv})

    add_library(${HLTHUNK_TESTS_LIBRARY}-static STATIC ${SRC} ${CMAKE_CURRENT_BINARY_DIR}/version.c)

    target_link_libraries(${HLTHUNK_TESTS_LIBRARY}-static ${HLTHUNK_TESTS_LINK_LIBRARIES})
    target_link_libraries(${HLTHUNK_TESTS_LIBRARY}-static ${ibverbs} ${hbldv})

    # Copy executable files to a "bin/lib_mode" sub-directory
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/lib_mode")

    if (HLTESTS_BUILD_DEMOS)

        add_subdirectory(demo)

    endif()

else ()
    include_directories(
        ${CMOCKA_INCLUDE_DIR}
        ${CMAKE_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include/specs
        ${CMAKE_SOURCE_DIR}/include/specs/common
        ${CMAKE_SOURCE_DIR}/include/uapi
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/klib
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/argparse
        ${CMAKE_CURRENT_SOURCE_DIR}/inih
        ${Boost_INCLUDE_DIRS}
    )

    set(HLTHUNK_TESTS_LINK_LIBRARIES
        ${CMOCKA_LIBRARY}
        ${HLTHUNK_TARGET})

    # create test library
    add_library(${HLTHUNK_TESTS_LIBRARY}-static-internal
        STATIC
        argparse/argparse.c
        common/hlthunk_completion.c
        common/hlthunk_nic_tests.c
        common/hlthunk_tests.c
        common/hlthunk_tests_arc.c
        common/nic_atomic_fna.c
        common/nic_basic.c
        common/nic_bp_offs.c
        common/nic_collective.c
        common/nic_common.c
        common/nic_eq.c
        common/reduction_test.c
        config_iterator/config_iterator.c
        common/nic_dna.c
        gaudi/hlthunk_tests_gaudi.c
        gaudi2/hlthunk_tests_gaudi2.c
        gaudi3/hlthunk_tests_gaudi3.c
        goya/hlthunk_tests_goya.c
        inih/ini.c
        mersenne-twister/mersenne-twister.c
    )

    target_link_libraries(${HLTHUNK_TESTS_LIBRARY}-static-internal ${HLTHUNK_TESTS_LINK_LIBRARIES})
    target_link_libraries(${HLTHUNK_TESTS_LIBRARY}-static-internal ${ibverbs} ${hbldv})

    set(TEST_TARGET_LIBRARIES
        ${HLTHUNK_TESTS_LIBRARY}-static-internal
        ${HLTHUNK_TESTS_LINK_LIBRARIES})

    # Copy executable files to a "bin" sub-directory
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

    add_subdirectory(common)
    add_subdirectory(goya)
    add_subdirectory(gaudi)
    add_subdirectory(gaudi2)
    add_subdirectory(gaudi3)

endif ()
