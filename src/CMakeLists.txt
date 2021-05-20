# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

file(GLOB SRC *.c) # compile all files with *.c suffix

include_directories(klib)

exec_program(
    "git"
    ${CMAKE_CURRENT_SOURCE_DIR}
    ARGS "rev-parse --short HEAD"
    OUTPUT_VARIABLE HLTHUNK_SHA1_VERSION
    RETURN_VALUE GIT_RC)

IF(NOT "${GIT_RC}" EQUAL 0)
    set(HLTHUNK_SHA1_VERSION "")
ENDIF()

add_definitions(-DHLTHUNK_GIT_SHA=${HLTHUNK_SHA1_VERSION})
set(LIB_VERSION_MAJOR 1)
set(LIB_VERSION_MINOR 1)
set(LIB_VERSION_PATCH 0)
set(LIB_VERSION ${LIB_VERSION_MAJOR}.${LIB_VERSION_MINOR}.${LIB_VERSION_PATCH})

# generate version.c
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.c.in" "${CMAKE_CURRENT_BINARY_DIR}/version.c" @ONLY)

# Build shared/static libraries from all specified source files
add_library(${HLTHUNK_TARGET} SHARED ${SRC} ${CMAKE_CURRENT_BINARY_DIR}/version.c)

set_target_properties(${HLTHUNK_TARGET} PROPERTIES
					SOVERSION ${LIB_VERSION_MAJOR}
					VERSION ${LIB_VERSION}
					COMPILE_DEFINITIONS "HL_BUILD_SHARED_LIB")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/${HLTHUNK_TARGET}_version.map")
add_library(${HLTHUNK_TARGET}-static STATIC ${SRC} ${CMAKE_CURRENT_BINARY_DIR}/version.c)

target_compile_definitions(${HLTHUNK_TARGET}-static PUBLIC DISABLE_PROFILER)
