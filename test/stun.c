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

#include "stun.h"

#include <stdint.h>
#include <string.h>

int test_stun(void) {
	uint8_t message[] = {
	    0x00, 0x01, 0x00, 0x58, // Request type and message length
	    0x21, 0x12, 0xa4, 0x42, // Magic cookie
	    0xb7, 0xe7, 0xa7, 0x01, // Transaction ID
	    0xbc, 0x34, 0xd6, 0x86, //
	    0xfa, 0x87, 0xdf, 0xae, //
	    0x80, 0x22, 0x00, 0x10, // SOFTWARE attribute header
	    0x53, 0x54, 0x55, 0x4e, //
	    0x20, 0x74, 0x65, 0x73, //
	    0x74, 0x20, 0x63, 0x6c, //
	    0x69, 0x65, 0x6e, 0x74, //
	    0x00, 0x24, 0x00, 0x04, // PRIORITY attribute header
	    0x6e, 0x00, 0x01, 0xff, //
	    0x80, 0x29, 0x00, 0x08, // ICE-CONTROLLED attribute header
	    0x93, 0x2f, 0xf9, 0xb1, //
	    0x51, 0x26, 0x3b, 0x36, //
	    0x00, 0x06, 0x00, 0x09, // USERNAME attribute header
	    0x65, 0x76, 0x74, 0x6a, //
	    0x3a, 0x68, 0x36, 0x76, //
	    0x59, 0x20, 0x20, 0x20, //
	    0x00, 0x08, 0x00, 0x14, // MESSAGE-INTEGRITY attribute header
	    0x9a, 0xea, 0xa7, 0x0c, //
	    0xbf, 0xd8, 0xcb, 0x56, //
	    0x78, 0x1e, 0xf2, 0xb5, //
	    0xb2, 0xd3, 0xf2, 0x49, //
	    0xc1, 0xb5, 0x71, 0xa2, //
	    0x80, 0x28, 0x00, 0x04, // FINGERPRINT attribute header
	    0xe5, 0x7a, 0x3b, 0xcf, //
	};

	stun_message_t msg;
	strcpy(msg.username, "evtj:h6vY");
	msg.password = "VOkJxbRl1RmTxUk/WvJxBt";

	if (stun_read(message, sizeof(message), &msg) <= 0)
		return -1;

	if (memcmp(msg.transaction_id, message + 8, 12) != 0)
		return -1;

	if (msg.priority != 0x6e0001ff)
		return -1;

	if (!msg.ice_controlled)
		return -1;

	if (!msg.has_integrity)
		return -1;

	return 0;
}
