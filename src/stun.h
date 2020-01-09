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

#ifndef JUICE_STUN_H
#define JUICE_STUN_H

#include "socket.h" // for sockaddr stuff

#include <stdbool.h>
#include <stdint.h>

#pragma pack(push, 1)
/*
 * STUN message header (20 bytes)
 * See https://tools.ietf.org/html/rfc5389#section-6
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |0 0|     STUN Message Type     |         Message Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Magic Cookie = 0x2112A442                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                     Transaction ID (96 bits)                  |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define STUN_TRANSACTION_ID_SIZE 12

struct stun_header {
	uint16_t type;
	uint16_t length;
	uint32_t magic;
	uint8_t transaction_id[STUN_TRANSACTION_ID_SIZE];
};

/*
 * Format of STUN Message Type Field
 *
 *  0                 1
 *  2  3  4 5 6 7 8 9 0 1 2 3 4 5
 * +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
 * |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
 * |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
 * +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
 * Request:    C=b00
 * Indication: C=b01
 * Response:   C=b10 (success)
 *             C=b11 (error)
 */
#define STUN_CLASS_MASK 0x0110

typedef enum stun_class {
	STUN_CLASS_REQUEST = 0x0000,
	STUN_CLASS_INDICATION = 0x0010,
	STUN_CLASS_RESP_SUCCESS = 0x0100,
	STUN_CLASS_RESP_ERROR = 0x0110
} stun_class_t;

typedef enum stun_method {
	STUN_METHOD_BINDING = 0x0001,
} stun_method_t;

/*
 * STUN attribute header
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Value (variable)                     ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct stun_attr {
	uint16_t type;
	uint16_t length;
	uint8_t value[];
};

typedef enum stun_attr_type {
	STUN_ATTR_MAPPED_ADDRESS = 0x0001,
	STUN_ATTR_USERNAME = 0x0003,
	STUN_ATTR_MESSAGE_INTEGRITY = 0x0008,
	STUN_ATTR_ERROR_CODE = 0x0009,
	STUN_ATTR_UNKNOWN_ATTRIBUTES = 0x000A,
	STUN_ATTR_REALM = 0x0014,
	STUN_ATTR_NONCE = 0x0015,
	STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020,
	STUN_ATTR_PRIORITY = 0x0024,
	STUN_ATTR_USE_CANDIDATE = 0x0025,
	STUN_ATTR_SOFTWARE = 0x8022,
	STUN_ATTR_ALTERNATE_SERVER = 0x8023,
	STUN_ATTR_FINGERPRINT = 0x8028,
	STUN_ATTR_ICE_CONTROLLED = 0x8029,
	STUN_ATTR_ICE_CONTROLLING = 0x802A,
} stun_attr_type_t;

/*
 * STUN attribute value for MAPPED-ADDRESS or XOR-MAPPED-ADDRESS
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |X X X X X X X X|    Family     |        Port or X-Port         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |           Address or X-Address (32 bits or 128 bits)          |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct stun_value_mapped_address {
	uint8_t padding;
	uint8_t family;
	uint16_t port;
	uint8_t address[];
};

typedef enum stun_address_family {
	STUN_ADDRESS_FAMILY_IPV4 = 0x01,
	STUN_ADDRESS_FAMILY_IPV6 = 0x02,
} stun_address_family_t;

/*
 * STUN attribute value for ERROR-CODE
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Reserved, should be 0         |Class|     Number    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Reason Phrase (variable)                               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct stun_value_error_code {
	uint16_t padding;
	uint8_t code_class; // lower 3 bits only
	uint8_t code_number;
	uint8_t reason[];
};

#pragma pack(pop)

typedef struct stun_message {
	stun_class_t msg_class;
	stun_method_t msg_method;
	uint8_t transaction_id[STUN_TRANSACTION_ID_SIZE];
	unsigned int error_code;
	bool has_integrity;
	bool has_fingerprint;
	const char *username;
	const char *password;
	unsigned int priority;
	bool use_candidate;
	bool ice_controlling;
	bool ice_controlled;
	struct sockaddr_record mapped;
} stun_message_t;

int stun_write(void *buf, size_t size, const stun_message_t *msg);
int stun_write_header(void *buf, size_t size, stun_class_t class,
                      stun_method_t method, const uint8_t *transaction_id);
size_t stun_update_header_length(void *buf, size_t length);
int stun_write_attr(void *buf, size_t size, uint16_t type, const void *value,
                    size_t length);

int stun_read(void *data, size_t size, stun_message_t *msg);
int stun_read_attr(const void *data, size_t size, stun_message_t *msg,
                   uint8_t *begin, uint8_t *attr_begin);
int stun_read_value_mapped_address(const void *data, size_t size,
                                   stun_message_t *msg, const uint8_t *mask);

#endif
