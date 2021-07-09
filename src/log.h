/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef JUICE_LOG_H
#define JUICE_LOG_H

#include "juice.h"

#include <stdarg.h>

bool juice_log_is_enabled(juice_log_level_t level);
void juice_log_write(juice_log_level_t level, const char *file, int line, const char *fmt, ...);

#define JLOG_VERBOSE(...) juice_log_write(JUICE_LOG_LEVEL_VERBOSE, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_DEBUG(...) juice_log_write(JUICE_LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_INFO(...) juice_log_write(JUICE_LOG_LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_WARN(...) juice_log_write(JUICE_LOG_LEVEL_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_ERROR(...) juice_log_write(JUICE_LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define JLOG_FATAL(...) juice_log_write(JUICE_LOG_LEVEL_FATAL, __FILE__, __LINE__, __VA_ARGS__)

#define JLOG_VERBOSE_ENABLED juice_log_is_enabled(JUICE_LOG_LEVEL_VERBOSE)
#define JLOG_DEBUG_ENABLED juice_log_is_enabled(JUICE_LOG_LEVEL_DEBUG)
#define JLOG_INFO_ENABLED juice_log_is_enabled(JUICE_LOG_LEVEL_INFO)
#define JLOG_WARN_ENABLED juice_log_is_enabled(JUICE_LOG_LEVEL_WARN)
#define JLOG_ERROR_ENABLED juice_log_is_enabled(JUICE_LOG_LEVEL_ERROR)
#define JLOG_FATAL_ENABLED juice_log_is_enabled(JUICE_LOG_LEVEL_FATAL)

#endif // JUICE_LOG_H
