/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "crc32.h"

#include <stdint.h>
#include <string.h>

int test_crc32(void) {
	const char *str = "The quick brown fox jumps over the lazy dog";
	uint32_t expected = 0x414fa339;

	if (CRC32(str, strlen(str)) != expected)
		return -1;

	return 0;
}
