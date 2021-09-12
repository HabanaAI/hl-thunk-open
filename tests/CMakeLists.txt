# COPYRIGHT (c) 2019-2021 Habanalabs Ltd. See COPYING.md file

project(libhl-thunk-tests C)

set(HLTHUNK_TESTS_LIBRARY hl-thunk-tests)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")

add_definitions(-DHLTHUNK_BUILD_PATH="${CMAKE_BUILD_PATH}")

if (SANITIZE_ON)
    add_definitions(-DHLTHUNK_TESTS_SANITIZER)
endif()

if (HLTESTS_LIB_MODE)
    include_directories(
        ${CMAKE_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include/specs
        ${CMAKE_SOURCE_DIR}/include/uapi
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/klib
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/argparse
        ${CMAKE_CURRENT_SOURCE_DIR}/inih
    )

    set(HLTHUNK_TESTS_LINK_LIBRARIES
        ${HLTHUNK_TARGET})

    file(GLOB SRC common/*.c gaudi/*.c goya/*.c inih/*.c
	mersenne-twister/*.c argparse/*.c) # compile all files with *.c suffix

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

    target_link_libraries(${HLTHUNK_TESTS_LIBRARY} ${HLTHUNK_TESTS_LINK_LIBRARIES})

    add_library(${HLTHUNK_TESTS_LIBRARY}-static STATIC ${SRC} ${CMAKE_CURRENT_BINARY_DIR}/version.c)

    target_link_libraries(${HLTHUNK_TESTS_LIBRARY}-static ${HLTHUNK_TESTS_LINK_LIBRARIES})

    add_subdirectory(demo)

else ()
    include_directories(
        ${CMOCKA_INCLUDE_DIR}
        ${CMAKE_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include/specs
        ${CMAKE_SOURCE_DIR}/include/uapi
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/klib
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/argparse
        ${CMAKE_CURRENT_SOURCE_DIR}/inih
    )

    set(HLTHUNK_TESTS_LINK_LIBRARIES
        ${CMOCKA_LIBRARY}
        ${HLTHUNK_TARGET})

    # create test library
    add_library(${HLTHUNK_TESTS_LIBRARY}
        STATIC
        common/hlthunk_tests.c
        goya/hlthunk_tests_goya.c
        gaudi/hlthunk_tests_gaudi.c
        mersenne-twister/mersenne-twister.c
        argparse/argparse.c
        inih/ini.c)

    target_link_libraries(${HLTHUNK_TESTS_LIBRARY} ${HLTHUNK_TESTS_LINK_LIBRARIES})

    set(TEST_TARGET_LIBRARIES
        ${HLTHUNK_TESTS_LIBRARY}
        ${HLTHUNK_TESTS_LINK_LIBRARIES})

    add_subdirectory(common)
    add_subdirectory(goya)
    add_subdirectory(gaudi)

endif ()
