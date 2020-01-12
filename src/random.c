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

#include "random.h"
#include "log.h"

#include <math.h>
#include <stdbool.h>
#include <time.h>

#if defined(__linux__)
#include <errno.h>
#include <sys/random.h>

static int random_bytes(void *buf, size_t size) {
	ssize_t ret = getrandom(buf, size, 0);
	if (ret < 0) {
		JLOG_WARN("getrandom failed, errno=%d", errno);
		return -1;
	}
	if ((size_t)ret < size) {
		JLOG_WARN("getrandom returned too few bytes, size=%zu, returned=%zu",
		          size, (size_t)ret);
		return -1;
	}
	return 0;
}

#elif defined(_WIN32)
#include <wincrypt.h>
#include <windows.h>

static int random_bytes(void *buf, size_t size) {
	HCRYPTPROV prov;
	if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL,
	                         CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		JLOG_WARN("Win32: CryptAcquireContext failed");
		return -1;
	}
	BOOL success;
	if (!(success = CryptGenRandom(prov, (DWORD)size, (BYTE *)buf))) {
		JLOG_WARN("Win32: CryptGenRandom failed");
	}
	CryptReleaseContext(prov, 0);
	return success ? 0 : -1;
}

#else
static int random_bytes(void *buf, size_t size) {
	return -1;
}
#endif

void juice_random(void *buf, size_t size) {
	if (random_bytes(buf, size) == 0)
		return;

#ifdef __unix__
#define random_func random
#define srandom_func srandom
	JLOG_DEBUG("Using random() for random bytes");
#else
#define random_func rand
#define srandom_func srand
	JLOG_WARN("Falling back on rand() for random bytes");
#endif

	static bool srandom_called = false;
	if (!srandom_called) {
		unsigned int seed;
		struct timespec ts;
		if (clock_gettime(CLOCK_REALTIME, &ts) == 0)
			seed = (unsigned int)(ts.tv_sec ^ ts.tv_nsec);
		else
			seed = (unsigned int)time(NULL);
		srandom_func(seed);
		srandom_called = true;
	}
	// RAND_MAX is guaranteed to be at least 2^15 - 1
	uint8_t *bytes = buf;
	for (size_t i = 0; i < size; ++i)
		bytes[i] = (uint8_t)((random_func() & 0x7f80) >> 7);

#undef random_func
#undef srandom_func
}

void juice_random_str64(char *buf, size_t size) {
	static const char chars64[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t i = 0;
	for (i = 0; i + 1 < size; ++i) {
		uint8_t byte = 0;
		juice_random(&byte, 1);
		buf[i] = chars64[byte & 0x3F];
	}
	buf[i] = '\0';
}

uint32_t juice_rand32(void) {
	uint32_t r = 0;
	juice_random(&r, sizeof(r));
	return r;
}

uint64_t juice_rand64(void) {
	uint64_t r = 0;
	juice_random(&r, sizeof(r));
	return r;
}
