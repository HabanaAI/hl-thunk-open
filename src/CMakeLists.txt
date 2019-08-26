# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

file(GLOB SRC *.c) # compile all files with *.c suffix

include_directories(klib)

# Build shared/static libraries from all specified source files
add_library(${HLTHUNK_TARGET} SHARED ${SRC})
add_library(${HLTHUNK_TARGET}-static STATIC ${SRC})
