# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

file(GLOB SRC *.c) # compile all files with *.c suffix

# Build shared/static libraries from all specified source files
add_library(${HLTHUNK_ERR_INJECT_TARGET} SHARED ${SRC})
add_library(${HLTHUNK_ERR_INJECT_TARGET}-static STATIC ${SRC})

target_link_libraries(${HLTHUNK_ERR_INJECT_TARGET} ${HLTHUNK_TARGET})
