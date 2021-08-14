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
#define _WIN32_WINNT 0x0601 // Windows 7
#endif
#ifndef __MSVCRT_VERSION__
#define __MSVCRT_VERSION__ 0x0601
#endif

#include <windows.h>

typedef HANDLE mutex_t;
typedef HANDLE thread_t;
typedef DWORD thread_return_t;
#define THREAD_CALL __stdcall

#define MUTEX_INITIALIZER NULL

#define MUTEX_PLAIN 0x0
#define MUTEX_RECURSIVE 0x0 // mutexes are recursive on Windows

static inline int mutex_init_impl(mutex_t *m) {
	return ((*(m) = CreateMutex(NULL, FALSE, NULL)) != NULL ? 0 : (int)GetLastError());
}

static inline int mutex_lock_impl(volatile mutex_t *m) {
	// Atomically initialize the mutex on first lock
	if (*(m) == NULL) {
		HANDLE cm = CreateMutex(NULL, FALSE, NULL);
		if (cm == NULL)
			return (int)GetLastError();
		if (InterlockedCompareExchangePointer(m, cm, NULL) != NULL)
			CloseHandle(cm);
	}
	return WaitForSingleObject(*m, INFINITE) != WAIT_FAILED ? 0 : (int)GetLastError();
}

#define mutex_init(m, flags) mutex_init_impl(m)
#define mutex_lock(m) mutex_lock_impl(m)
#define mutex_unlock(m) (void)ReleaseMutex(*(m))
#define mutex_destroy(m) (void)CloseHandle(*(m))

static inline void thread_join_impl(thread_t t, thread_return_t *res) {
	WaitForSingleObject(t, INFINITE);
	if (res)
		GetExitCodeThread(t, res);
	CloseHandle(t);
}

#define thread_init(t, func, arg)                                                                  \
	((*(t) = CreateThread(NULL, 0, func, arg, 0, NULL)) != NULL ? 0 : (int)GetLastError())
#define thread_join(t, res) thread_join_impl(t, res)

#else // POSIX

#include <pthread.h>

typedef pthread_mutex_t mutex_t;
typedef pthread_t thread_t;
typedef void *thread_return_t;
#define THREAD_CALL

#define MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

#define MUTEX_PLAIN PTHREAD_MUTEX_NORMAL
#define MUTEX_RECURSIVE PTHREAD_MUTEX_RECURSIVE

static inline int mutex_init_impl(mutex_t *m, int flags) {
	pthread_mutexattr_t mutexattr;
	pthread_mutexattr_init(&mutexattr);
	pthread_mutexattr_settype(&mutexattr, flags);
	int ret = pthread_mutex_init(m, &mutexattr);
	pthread_mutexattr_destroy(&mutexattr);
	return ret;
}

#define mutex_init(m, flags) mutex_init_impl(m, flags)
#define mutex_lock(m) pthread_mutex_lock(m)
#define mutex_unlock(m) (void)pthread_mutex_unlock(m)
#define mutex_destroy(m) (void)pthread_mutex_destroy(m)

#define thread_init(t, func, arg) pthread_create(t, NULL, func, arg)
#define thread_join(t, res) (void)pthread_join(t, res)

#endif // ifdef _WIN32

#if __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)

#include <stdatomic.h>
#define atomic(T) _Atomic(T)
#define atomic_ptr(T) _Atomic(T*)

#else // no atomics

// Since we don't need compare-and-swap, just assume store and load are atomic
#define atomic(T) volatile T
#define atomic_ptr(T) T* volatile
#define atomic_store(a, v) (void)(*(a) = (v))
#define atomic_load(a) (*(a))
#define ATOMIC_VAR_INIT(v) (v)

#endif // if atomics

#endif // JUICE_THREAD_H

