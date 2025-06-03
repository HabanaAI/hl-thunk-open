/*
 * Copyright (C) 2020 HabanaLabs Ltd.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __LOGGER_H__
#define __LOGGER_H__

#ifdef CORAL_BFM_MODE
/* 'struct char8_t' is defined in format.h (spdlog) but 'char8_t' is a keyword in C++20 */
#define char8_t _char8_t
#include "logging.h"
#undef char8_t

#define KB            1024
#define MB            (KB * KB)
#define LOG_SIZE      (200 * MB)
#define LOG_AMOUNT    1
#define QMAN_LOG_FILE "qman.log"

inline std::shared_ptr<spdlog::logger> ___validate(const std::string &logname,
						   const std::string &msg)
{
	auto log = spdlog::get("console");
	if (log == nullptr)
		log = spdlog::stdout_color_mt("console");
	return log;
}

#undef GET_LOGGER
#define GET_LOGGER(logname, msg) ::___validate(logname, msg)

#else

#define SET_LOG_LEVEL(...) do {             \
    } while (0)

#define LOG_TRACE(logname,msg,...) do {     \
    } while (0)

#define LOG_DEBUG(logname,msg,...) do {     \
    } while (0)

#define LOG_INFO(logname,msg,...) do {      \
    } while (0)

#define LOG_WARN(logname,msg,...) do {      \
    } while (0)

#define LOG_ERR(logname,msg,...) do {       \
    } while (0)

#define LOG_CRITICAL(logname,msg,...) do {  \
    } while (0)

#include "logger_fns.h"

#endif

#endif // __LOGGER_H__
