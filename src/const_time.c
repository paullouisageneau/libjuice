/**
 * Copyright (c) 2021 Paul-Louis Ageneau
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

#include "const_time.h"

int const_time_memcmp(const void *a, const void *b, size_t len) {
	const unsigned char *ca = a;
	const unsigned char *cb = b;
	unsigned char x = 0;
	for (size_t i = 0; i < len; i++)
		x |= ca[i] ^ cb[i];

	return x;
}

int const_time_strcmp(const void *a, const void *b) {
	const unsigned char *ca = a;
	const unsigned char *cb = b;
	unsigned char x = 0;
	size_t i = 0;
	for(;;) {
		x |= ca[i] ^ cb[i];
		if (!ca[i] || !cb[i])
			break;
		++i;
	}

	return x;
}
