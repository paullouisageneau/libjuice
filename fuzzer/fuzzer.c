/**
 * Copyright (c) 2022 0x34d (https://github.com/0x34d)
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

#include <stdint.h>
#include <string.h>

#include "stun.h"

#define kMinInputLength 5
#define kMaxInputLength 2048

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

	if (Size < kMinInputLength || Size > kMaxInputLength) {
		return 0;
	}

	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));

	_juice_is_stun_datagram((void *)Data, Size);
	_juice_stun_read((void *)Data, Size, &msg);
	_juice_stun_check_integrity((void *)Data, Size, &msg, "VOkJxbRl1RmTxUk/WvJxBt");

	return 0;
}
