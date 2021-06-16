# COPYRIGHT (c) 2021 Habanalabs Ltd. See COPYING.md file

file(GLOB SRC *.c) # compile all files with *.c suffix

include_directories(
        ${CMAKE_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include/specs
        ${CMAKE_SOURCE_DIR}/include/uapi
)

add_executable (demo ${SRC})

set(DEMO_LINK_LIBRARIES
    ${HLTHUNK_TARGET} ${HLTHUNK_TESTS_LIBRARY} ${HLTHUNK_ERR_INJECT_TARGET})

target_link_libraries(demo ${DEMO_LINK_LIBRARIES})
