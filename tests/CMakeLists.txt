# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

project(libhl-thunk-tests C)

set(HLTHUNK_TESTS_LIBRARY hlthunk-tests)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")

include_directories(
    ${CMOCKA_INCLUDE_DIR}
    ${CMAKE_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/specs
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/klib
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/argparse
)

set(HLTHUNK_TESTS_LINK_LIBRARIES
    ${CMOCKA_LIBRARY}
    ${HLTHUNK_TARGET})

# create test library
add_library(${HLTHUNK_TESTS_LIBRARY}
            STATIC
            hlthunk_tests.c
            hlthunk_tests_goya.c
            argparse/argparse.c)
target_link_libraries(${HLTHUNK_TESTS_LIBRARY} ${HLTHUNK_TESTS_LINK_LIBRARIES})

set(TEST_TARGET_LIBRARIES
    ${HLTHUNK_TESTS_LIBRARY}
    ${HLTHUNK_TESTS_LINK_LIBRARIES}
)

add_subdirectory(common)
add_subdirectory(goya)
