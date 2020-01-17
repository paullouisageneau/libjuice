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

#include "log.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define BUFFER_SIZE 4096

static const char *log_level_names[] = {"VERBOSE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"};

static const char *log_level_colors[] = {
    "\x1B[90m",        // grey
    "\x1B[96m",        // cyan
    "\x1B[39m",        // default foreground
    "\x1B[93m",        // yellow
    "\x1B[91m",        // red
    "\x1B[97m\x1B[41m" // white on red
};

static juice_log_level_t log_level = JUICE_LOG_LEVEL_WARN;
static juice_log_cb_t log_cb = NULL;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void juice_set_log_level(juice_log_level_t level) {
	pthread_mutex_lock(&log_mutex);
	log_level = level;
	pthread_mutex_unlock(&log_mutex);
}

void juice_set_log_callback(juice_log_cb_t cb) {
	pthread_mutex_lock(&log_mutex);
	log_cb = cb;
	pthread_mutex_unlock(&log_mutex);
}

void juice_log_write(juice_log_level_t level, const char *file, int line, const char *fmt, ...) {
	pthread_mutex_lock(&log_mutex);
	if (level < log_level) {
		pthread_mutex_unlock(&log_mutex);
		return;
	}
	if (log_cb) {
		char message[BUFFER_SIZE];
		int len = snprintf(message, BUFFER_SIZE, "%s:%d: ", file, line);
		len = len >= 0 ? len : 0;

		va_list args;
		va_start(args, fmt);
		len = vsnprintf(message + len, BUFFER_SIZE - len, fmt, args);
		va_end(args);

		if (len >= 0)
			log_cb(level, message);
	} else {
		time_t t = time(NULL);
		struct tm *lt = localtime(&t);
		char buffer[16];
		if (strftime(buffer, 16, "%H:%M:%S", lt) == 0)
			buffer[0] = '\0';

		fprintf(stdout, "%s", log_level_colors[level]);
		fprintf(stdout, "%s %-7s %s:%d: ", buffer, log_level_names[level], file, line);

		va_list args;
		va_start(args, fmt);
		vfprintf(stdout, fmt, args);
		va_end(args);

		fprintf(stdout, "%s", "\x1B[0m\x1B[0K");
		fprintf(stdout, "\n");
		fflush(stdout);
	}
	pthread_mutex_unlock(&log_mutex);
}
