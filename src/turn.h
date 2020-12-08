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

#ifndef JUICE_TURN_H
#define JUICE_TURN_H

#include "addr.h"
#include "ice.h"
#include "juice.h"
#include "log.h"
#include "stun.h"
#include "timestamp.h"

#include <stdint.h>

#pragma pack(push, 1)
/*
 * TURN ChannelData Message
 * See https://tools.ietf.org/html/rfc8656#section-12.4
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Channel Number        |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * /                       Application Data                        /
 * /                                                               /
 * |                                                               |
 * |                               +-------------------------------+
 * |                               |
 * +-------------------------------+
 */

struct channel_data_header {
	uint16_t channel_number;
	uint16_t length;
};

#pragma pack(pop)

bool is_channel_data(const void *data, size_t size);

int turn_wrap_channel_data(char *buffer, size_t size, const char *data, size_t data_size,
                           uint16_t channel);

#define TURN_MAP_COUNT ICE_MAX_CANDIDATES_COUNT
#define TURN_TRANSACTION_MAP_COUNT ICE_MAX_CANDIDATES_COUNT

typedef struct turn_entry {
	addr_record_t record;
	timestamp_t permission_timestamp;
	timestamp_t bind_timestamp;
	uint16_t channel;
} turn_entry_t;

typedef struct turn_transaction_entry_t {
	uint8_t transaction_id[STUN_TRANSACTION_ID_SIZE];
	addr_record_t record;
} turn_transaction_entry_t;

typedef struct turn_state {
	turn_entry_t map[TURN_MAP_COUNT];
	turn_transaction_entry_t transaction_map[TURN_TRANSACTION_MAP_COUNT];
	int next_transaction_entry_index;
	stun_credentials_t credentials;
	const char *password;
} turn_state_t;

bool turn_get_channel(turn_state_t *state, const addr_record_t *record, uint16_t *channel);
bool turn_find_channel(turn_state_t *state, uint16_t channel, addr_record_t *record);

bool turn_new_transaction_id(turn_state_t *state, const addr_record_t *record,
                             uint8_t *transaction_id);
bool turn_find_transaction_id(turn_state_t *state, const uint8_t *transaction_id,
                              addr_record_t *record);

bool turn_set_permission(turn_state_t *state, const uint8_t *transaction_id);
bool turn_has_permission(turn_state_t *state, const addr_record_t *record);

bool turn_set_bind(turn_state_t *state, const uint8_t *transaction_id);
bool turn_has_bind(turn_state_t *state, const addr_record_t *record);

#endif
