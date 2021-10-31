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

#include "timestamp.h"

#ifdef _WIN32
#include <windows.h>
#else
#include <time.h>

// clock_gettime() is not implemented on older versions of OS X (< 10.12)
#if defined(__APPLE__) && !defined(CLOCK_MONOTONIC)
#include <sys/time.h>
#define CLOCK_MONOTONIC 0
int clock_gettime(int clk_id, struct timespec *t) {
	(void)clk_id;

	// gettimeofday() does not return monotonic time but it should be good enough.
	struct timeval now;
	if (gettimeofday(&now, NULL))
		return -1;

	t->tv_sec = now.tv_sec;
	t->tv_nsec = now.tv_usec * 1000;
	return 0;
}
#endif // defined(__APPLE__) && !defined(CLOCK_MONOTONIC)

#endif

timestamp_t current_timestamp() {
#ifdef _WIN32
	return (timestamp_t)GetTickCount();
#else // POSIX
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		return 0;
	return (timestamp_t)ts.tv_sec * 1000 + (timestamp_t)ts.tv_nsec / 1000000;
#endif
}
