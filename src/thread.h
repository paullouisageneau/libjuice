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

#ifndef JUICE_THREAD_H
#define JUICE_THREAD_H

#ifdef _WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef __MSVCRT_VERSION__
#define __MSVCRT_VERSION__ 0x0601
#endif

#include <windows.h>

typedef HANDLE mutex_t;
typedef HANDLE thread_t;

#define MUTEX_INITIALIZER NULL

#define MUTEX_PLAIN 0x0
#define MUTEX_RECURSIVE 0x0 // mutexes are recursive on Windows

static int mutex_init_impl(mutex_t *m) {
	return ((*m = CreateMutex(NULL, FALSE, NULL)) != NULL ? 0 : (int)GetLastError());
}

static int mutex_lock_impl(mutex_t *m) {
	// Atomically initialize the mutex on first lock
	if (*m == NULL) {
		HANDLE cm = CreateMutex(NULL, FALSE, NULL);
		if (InterlockedCompareExchangePointer(m, cm, NULL) != NULL)
			CloseHandle(cm);
	}
	return WaitForSingleObject(*m, INFINITE) != WAIT_FAILED ? 0 : (int)GetLastError();
}

#define mutex_init(m, flags) mutex_init_impl(m)
#define mutex_lock(m) mutex_lock_impl(m)
#define mutex_unlock(m) (void)ReleaseMutex(*(m))
#define mutex_destroy(m) (void)CloseHandle(*(m))

#define thread_init(t, func, arg)                                                                  \
	((*(t) = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, arg, 0, NULL)) != NULL            \
	     ? 0                                                                                       \
	     : (int)GetLastError())
#define thread_join(t) (void)WaitForSingleObject((t), INFINITE)

#else // POSIX

#include <pthread.h>

typedef pthread_mutex_t mutex_t;
typedef pthread_t thread_t;

#define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

#define MUTEX_PLAIN PTHREAD_MUTEX_NORMAL
#define MUTEX_RECURSIVE PTHREAD_MUTEX_RECURSIVE

static int mutex_init_impl(mutex_t *m, int flags) {
	pthread_mutexattr_t mutexattr;
	pthread_mutexattr_init(&mutexattr);
	pthread_mutexattr_settype(&mutexattr, flags);
	return pthread_mutex_init(m, &mutexattr);
}

#define mutex_init(m, flags) mutex_init_impl(m, flags)
#define mutex_lock(m) pthread_mutex_lock(m)
#define mutex_unlock(m) (void)pthread_mutex_unlock(m)
#define mutex_destroy(m) (void)pthread_mutex_destroy(m)

#define thread_init(t, func, arg) pthread_create(t, NULL, func, arg)
#define thread_join(t) (void)pthread_join(t, NULL)

#endif

#endif // JUICE_THREAD_H
