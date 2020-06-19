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

#include "crc32.h"

#define CRC32_REVERSED_POLY 0xEDB88320
#define CRC32_INIT 0xFFFFFFFF
#define CRC32_XOR 0xFFFFFFFF

static uint32_t crc32_byte(uint32_t crc) {
	for (int i = 0; i < 8; ++i)
		if (crc & 1)
			crc = (crc >> 1) ^ CRC32_REVERSED_POLY;
		else
			crc = (crc >> 1);
	return crc;
}

static uint32_t crc32_table(const uint8_t *p, size_t size, uint32_t *table) {
	uint32_t crc = CRC32_INIT;
	while (size--)
		crc = table[(uint8_t)(crc & 0xFF) ^ *p++] ^ (crc >> 8);
	return crc ^ CRC32_XOR;
}

JUICE_EXPORT uint32_t juice_crc32(const void *data, size_t size) {
	static uint32_t table[256] = {0};
	if (table[0] == 0)
		for (uint32_t i = 0; i < 256; ++i)
			table[i] = crc32_byte(i);

	return crc32_table(data, size, table);
}
