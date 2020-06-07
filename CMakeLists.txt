# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

cmake_minimum_required(VERSION 3.0.1 FATAL_ERROR)

# Specify search path for CMake modules to be loaded by include() 
# and find_package()
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

# Add defaults for cmake
# Those need to be set before the project() call.
include(DefineCMakeDefaults)
include(DefineCompilerFlags)

project(hl-thunk LANGUAGES C)

# Reduce "warm" compilation time if ccache is available
find_program(CCACHE_PROGRAM ccache)
if (CCACHE_PROGRAM)
    set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
endif()

set(HLTHUNK "hl-thunk")
set(HLTHUNK_PACKAGE "hl-thunk")
set(HLTHUNK_COMPONENT "lib${HLTHUNK}")
set(HLTHUNK_TARGET "${HLTHUNK}")

set(HLTHUNK_ERR_INJECT "hl-thunk-err_injection")
set(HLTHUNK_ERR_INJECT_PACKAGE "hl-thunk-err_injection")
set(HLTHUNK_ERR_INJECT_COMPONENT "lib${HLTHUNK_ERR_INJECT}")
set(HLTHUNK_ERR_INJECT_TARGET "${HLTHUNK_ERR_INJECT}")

include(GNUInstallDirs)

set(BUILD_VERSION_MAJOR ${VERSION_MAJOR})
set(BUILD_VERSION_MINOR ${VERSION_MINOR})
set(BUILD_VERSION_PATCH ${VERSION_PATCH})
set(LIB_VERSION_STRING "${BUILD_VERSION_MAJOR}.${BUILD_VERSION_MINOR}.${BUILD_VERSION_PATCH}")

if (NOT ALLOW_IN_SOURCE_BUILD)
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")
endif()

# Copy library files to a lib sub-directory
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# Copy executable files to a bin sub-directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-fPIC -W -Werror -Wall -Wextra -Wno-unused-parameter")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers -Wno-type-limits")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function -Wno-sign-compare")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-variable -Wno-unused-result")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-strict-aliasing")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat-security -Wswitch-default -Wundef")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow -Wpointer-arith -Wcast-qual")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wstrict-prototypes -Wredundant-decls")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunreachable-code -fvisibility=hidden")
# -Wl,--no-as-needed -ldl flag is needed for dynamic library loading (for profiler use)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,--no-as-needed -ldl")
if (CMAKE_C_COMPILER_ID MATCHES "GNU")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-but-set-variable -Wlogical-op")
    if (NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 7.0)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-stringop-truncation -Wno-format-truncation")
    endif()
endif()

if("${CMAKE_BUILD_TYPE}" STREQUAL Release)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -O0")
endif()

if (SANITIZE_ON)
    set(SANITIZE "-fsanitize=undefined")
    set(SANITIZE "${SANITIZE} -fsanitize=leak")
    set(SANITIZE "${SANITIZE} -fno-omit-frame-pointer -fsanitize=address")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SANITIZE}")

include_directories(include)

add_subdirectory(src)

add_subdirectory(err_inject)

if (UNIT_TESTING)
    find_package(CMocka 1.1.3 REQUIRED)
    include(AddCMockaTest)
    add_subdirectory(tests)
endif ()
