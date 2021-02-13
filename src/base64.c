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

#include "base64.h"

#include <string.h>
#include <ctype.h>

int juice_base64_encode(const void *data, size_t size, char *out, size_t out_size) {
	static const char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	if (out_size < 4 * ((size + 2) / 3) + 1)
		return -1;

	const uint8_t *in = (const uint8_t *)data;
	char *w = out;
	while (size >= 3) {
		*w++ = tab[*in >> 2];
		*w++ = tab[((*in & 0x03) << 4) | (*(in + 1) >> 4)];
		*w++ = tab[((*(in + 1) & 0x0F) << 2) | (*(in + 2) >> 6)];
		*w++ = tab[*(in + 2) & 0x3F];
		in += 3;
		size -= 3;
	}

	if (size) {
		*w++ = tab[*in >> 2];
		if (size == 1) {
			*w++ = tab[(*in & 0x03) << 4];
			*w++ = '=';
		} else { // size == 2
			*w++ = tab[((*in & 0x03) << 4) | (*(in + 1) >> 4)];
			*w++ = tab[(*(in + 1) & 0x0F) << 2];
		}
		*w++ = '=';
	}

	*w = '\0';
	return (int)(w - out);
}

int juice_base64_decode(const char *str, void *out, size_t out_size) {
	const uint8_t *in = (const uint8_t *)str;
	uint8_t *w = (uint8_t *)out;
	while (*in && *in != '=') {
		uint8_t tab[4] = {0, 0, 0, 0};
		size_t size = 0;
		while (*in && size < 4) {
			uint8_t c = *in++;
			if (isspace(c))
				continue;
			if (c == '=')
				break;

			if ('A' <= c && c <= 'Z')
				tab[size++] = c - 'A';
			else if ('a' <= c && c <= 'z')
				tab[size++] = c + 26 - 'a';
			else if ('0' <= c && c <= '9')
				tab[size++] = c + 52 - '0';
			else if (c == '+' || c == '-')
				tab[size++] = 62;
			else if (c == '/' || c == '_')
				tab[size++] = 63;
			else
				return -1; // Invalid character
		}

		if (size > 0) {
			if (out_size < size - 1)
				return -1;

			out_size -= size - 1;

			*w++ = (tab[0] << 2) | (tab[1] >> 4);
			if (size > 1) {
				*w++ = (tab[1] << 4) | (tab[2] >> 2);
				if (size > 2)
					*w++ = (tab[2] << 6) | tab[3];
			}
		}
	}

	return (int)(w - (uint8_t *)out);
}
