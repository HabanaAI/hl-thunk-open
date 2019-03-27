# COPYRIGHT (c) 2019 Habanalabs Ltd. See COPYING.md file

cmake_minimum_required(VERSION 3.5.1 FATAL_ERROR)

# Specify search path for CMake modules to be loaded by include() 
# and find_package()
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

# Add defaults for cmake
# Those need to be set before the project() call.
include(DefineCMakeDefaults)
include(DefineCompilerFlags)

project(hl-thunk LANGUAGES C)

set(HLTHUNK "hl-thunk")
set(HLTHUNK_PACKAGE "hl-thunk")
set(HLTHUNK_COMPONENT "lib${HLTHUNK}")
set(HLTHUNK_TARGET "${HLTHUNK}")

include(GNUInstallDirs)

set(BUILD_VERSION_MAJOR ${VERSION_MAJOR})
set(BUILD_VERSION_MINOR ${VERSION_MINOR})
set(BUILD_VERSION_PATCH ${VERSION_PATCH})
set(LIB_VERSION_STRING "${BUILD_VERSION_MAJOR}.${BUILD_VERSION_MINOR}.${BUILD_VERSION_PATCH}")

# disallow in-source build
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")

# Copy library files to a lib sub-directory
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "-fPIC -W -Werror -Wall -Wextra -Wno-unused-parameter")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers -Wno-type-limits")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function -Wno-sign-compare")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-variable -Wno-unused-result")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-strict-aliasing -Wno-unused-but-set-variable")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wformat-security -Wswitch-default -Wundef")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow -Wpointer-arith -Wcast-qual")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wlogical-op -Wstrict-prototypes -Wredundant-decls")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wunreachable-code -fvisibility=hidden")

if("${CMAKE_BUILD_TYPE}" STREQUAL Release)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ggdb -O0")
endif()

include_directories(include)

add_subdirectory(src)

if (UNIT_TESTING)
    find_package(CMocka REQUIRED)
    include(AddCMockaTest)
    add_subdirectory(tests)
endif ()
