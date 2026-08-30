cmake_minimum_required(VERSION 3.5)

project(coral_bfm LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Build type not specified. Setting build type to Debug")
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "" FORCE)
endif()
message(STATUS "Build type ${CMAKE_BUILD_TYPE}")

set(ROOT ${CMAKE_CURRENT_LIST_DIR}/../)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -W -Wall -Werror")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-parameter -Wno-missing-field-initializers -Wno-misleading-indentation")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -fstack-clash-protection")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstack-protector-strong -fstack-clash-protection")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro,-z,now")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro,-z,now")

if(EXISTS "/tools/synopsys/arc_MWDT_ARC/2020_03")
	set(SYNOPSYS_ROOT "/tools/synopsys/arc_MWDT_ARC/2020_03")
else()
	set(SYNOPSYS_ROOT "/synopsys/arc_MWDT_ARC/2020_03")
endif()

set(METAWARE_ROOT "${SYNOPSYS_ROOT}/MetaWare")
set(METAWARE_INCLUDE "${METAWARE_ROOT}/arc/inc")

if (SANITIZE_ON)
    set(SANITIZE "-fsanitize=undefined")
    set(SANITIZE "${SANITIZE} -fsanitize=leak")
    set(SANITIZE "${SANITIZE} -fno-omit-frame-pointer -fsanitize=address")

    if (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
        if (NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 8.0)
            set(SANITIZE "${SANITIZE} -fsanitize-undefined-trap-on-error")
            set(SANITIZE "${SANITIZE} -fsanitize=pointer-compare")
            set(SANITIZE "${SANITIZE} -fsanitize=pointer-subtract")
            set(SANITIZE "${SANITIZE} -fsanitize-address-use-after-scope")
        endif()
    else()
        set(SANITIZE "${SANITIZE} -Wno-pass-failed")
    endif()

    message(STATUS "Enabling sanitizers: ${SANITIZE}")
endif()

set(engine_SRCS ${ROOT}/engine/src/arc_queue_pvt.c
		${ROOT}/engine/src/gaudi2_eng_regs.c
		${ROOT}/engine/src/gaudi3_eng_regs.c
		${ROOT}/engine/src/engine_arc.c
		${ROOT}/engine/src/regs.c
		${ROOT}/engine/src/init.c
		${ROOT}/engine/src/main.c
		${ROOT}/engine/src/qman_if.c)
set(engine_common_SRCS ${ROOT}/common/src/arc_queue_local.c
		       ${ROOT}/common/src/gaudi2_comm_regs.c
		       ${ROOT}/common/src/gaudi3_comm_regs.c
		       ${ROOT}/common/src/utils.c
		       ${ROOT}/common/src/logger.c
		       ${ROOT}/common/src/debug.c
		       ${ROOT}/common/src/dma.c
		       ${ROOT}/common/src/printf.c)

set_source_files_properties(${engine_SRCS} ${engine_common_SRCS} PROPERTIES LANGUAGE CXX)

add_library(engine_bfm SHARED engine_bfm.hpp arc_if.cpp ${engine_SRCS} ${engine_common_SRCS})
target_include_directories(engine_bfm PRIVATE ${ROOT}/engine/include
					      ${ROOT}/common/include
					      ${ROOT}/include
					      $ENV{SPECS_EXT_ROOT}
					      $ENV{SPDLOG_ROOT}
					      $ENV{HLTHUNK_ROOT}/include/specs
					      ${ROOT}/coral_wrapper
					      $ENV{THIRD_PARTIES_ROOT}/boost
					      ${METAWARE_INCLUDE}/arc)
#target_compile_options(engine_bfm PRIVATE -Wall -Wextra -fpermissive)
if (USE_CORAL_CYCLIC_MODE STREQUAL "yes")
	target_compile_definitions(engine_bfm PRIVATE ENGINE_ARC CORAL_BFM_MODE CORAL_BFM_CYCLIC_MODE)
else()
	target_compile_definitions(engine_bfm PRIVATE ENGINE_ARC CORAL_BFM_MODE)
endif()

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
	target_compile_definitions(engine_bfm PRIVATE ARC_DEBUG)
endif()

set_target_properties(engine_bfm PROPERTIES LINKER_LANGUAGE CXX)

set(scheduler_SRCS ${ROOT}/scheduler/src/qman_cmds.c
		   ${ROOT}/scheduler/src/gaudi2_sched_regs.c
		   ${ROOT}/scheduler/src/gaudi3_sched_regs.c
		   ${ROOT}/scheduler/src/sched.c
		   ${ROOT}/scheduler/src/init.c
		   ${ROOT}/scheduler/src/main.c
		   ${ROOT}/scheduler/src/sched_queues.c)
set(scheduler_common_SRCS ${ROOT}/common/src/gaudi2_comm_regs.c
		          ${ROOT}/common/src/gaudi3_comm_regs.c
		          ${ROOT}/common/src/arc_queue_local.c
		          ${ROOT}/common/src/utils.c
		          ${ROOT}/common/src/logger.c
		          ${ROOT}/common/src/debug.c
		          ${ROOT}/common/src/dma.c
			  ${ROOT}/common/src/printf.c)
set_source_files_properties(${scheduler_SRCS} ${scheduler_common_SRCS} PROPERTIES LANGUAGE CXX)
add_library(scheduler_bfm SHARED scheduler_bfm.hpp arc_if.cpp ${scheduler_SRCS} ${scheduler_common_SRCS})
target_include_directories(scheduler_bfm PRIVATE ${ROOT}/scheduler/include
					      ${ROOT}/common/include
					      ${ROOT}/common/src
					      ${ROOT}/include
					      $ENV{SPECS_EXT_ROOT}
					      $ENV{SPDLOG_ROOT}
					      $ENV{HLTHUNK_ROOT}/include/specs
					      ${ROOT}/coral_wrapper
					      $ENV{THIRD_PARTIES_ROOT}/boost
					      ${METAWARE_INCLUDE}/arc)
if (USE_CORAL_CYCLIC_MODE STREQUAL "yes")
	target_compile_definitions(scheduler_bfm PRIVATE SCHED_ARC CORAL_BFM_MODE CORAL_BFM_CYCLIC_MODE)
else()
	target_compile_definitions(scheduler_bfm PRIVATE SCHED_ARC CORAL_BFM_MODE)
endif()

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
	target_compile_definitions(scheduler_bfm PRIVATE ARC_DEBUG)
endif()

#target_compile_options(scheduler_bfm PRIVATE -Wall -Wextra -fpermissive)
set_target_properties(scheduler_bfm PROPERTIES LINKER_LANGUAGE CXX)
