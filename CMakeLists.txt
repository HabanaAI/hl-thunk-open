# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

cmake_minimum_required(VERSION 3.5.1 FATAL_ERROR)
project(hl-thunk C)

set(HLTHUNK "hlthunk")
set(HLTHUNK_PACKAGE "hl-thunk")
set(HLTHUNK_COMPONENT "lib${HLTHUNK}")
set(HLTHUNK_TARGET "${HLTHUNK}")

include(GNUInstallDirs)

set(BUILD_VERSION_MAJOR ${VERSION_MAJOR})
set(BUILD_VERSION_MINOR ${VERSION_MINOR})
set(BUILD_VERSION_PATCH ${VERSION_PATCH})
set(LIB_VERSION_STRING "${BUILD_VERSION_MAJOR}.${BUILD_VERSION_MINOR}.${BUILD_VERSION_PATCH}")

set(LIBRARY_OUTPUT_PATH "${CMAKE_BINARY_DIR}/lib")
set(EXECUTABLE_OUTPUT_PATH "${CMAKE_BINARY_DIR}/bin")

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-fPIC -W -Wall -Wextra -Wno-unused-parameter -Wformat-security -Wswitch-default -Wundef -Wshadow -Wpointer-arith -Wbad-function-cast -Wcast-qual -Wlogical-op -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wunreachable-code -fvisibility=hidden")

if("${CMAKE_BUILD_TYPE}" STREQUAL Release)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
endif()

include_directories(include)

add_subdirectory(src)
