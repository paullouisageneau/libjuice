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
bool is_valid_channel(uint16_t channel);

int turn_wrap_channel_data(char *buffer, size_t size, const char *data, size_t data_size,
                           uint16_t channel);

// TURN state map

typedef enum turn_entry_type {
	TURN_ENTRY_TYPE_EMPTY,
	TURN_ENTRY_TYPE_DELETED,
	TURN_ENTRY_TYPE_PERMISSION,
	TURN_ENTRY_TYPE_CHANNEL
} turn_entry_type_t;

typedef struct turn_entry {
	turn_entry_type_t type;
	timestamp_t timestamp;
	addr_record_t record;
	uint8_t transaction_id[STUN_TRANSACTION_ID_SIZE];
	uint16_t channel;
	bool fresh_transaction_id;
} turn_entry_t;

typedef struct turn_map {
	turn_entry_t *map;
	turn_entry_t **ordered_channels;
	turn_entry_t **ordered_transaction_ids;
	int map_size;
	int channels_count;
	int transaction_ids_count;
} turn_map_t;

int turn_init_map(turn_map_t *map, int size);
void turn_destroy_map(turn_map_t *map);

bool turn_set_permission(turn_map_t *map, const uint8_t *transaction_id,
                         const addr_record_t *record, // record may be NULL
                         timediff_t duration);
bool turn_has_permission(turn_map_t *map, const addr_record_t *record);

bool turn_bind_channel(turn_map_t *map, const addr_record_t *record,
                       const uint8_t *transaction_id, // transaction_id may be NULL
                       uint16_t channel, timediff_t duration);
bool turn_bind_random_channel(turn_map_t *map, const addr_record_t *record, uint16_t *channel,
                              timediff_t duration);
bool turn_bind_current_channel(turn_map_t *map, const uint8_t *transaction_id,
                               const addr_record_t *record, // record may be NULL
                               timediff_t duration);
bool turn_get_channel(turn_map_t *map, const addr_record_t *record, uint16_t *channel);
bool turn_get_bound_channel(turn_map_t *map, const addr_record_t *record, uint16_t *channel);
bool turn_find_channel(turn_map_t *map, uint16_t channel, addr_record_t *record);
bool turn_find_bound_channel(turn_map_t *map, uint16_t channel, addr_record_t *record);

bool turn_set_permission_transaction_id(turn_map_t *map, const addr_record_t *record,
                                        const uint8_t *transaction_id);
bool turn_set_channel_transaction_id(turn_map_t *map, const addr_record_t *record,
                                     const uint8_t *transaction_id);
bool turn_set_random_permission_transaction_id(turn_map_t *map, const addr_record_t *record,
                                               uint8_t *transaction_id);
bool turn_set_random_channel_transaction_id(turn_map_t *map, const addr_record_t *record,
                                            uint8_t *transaction_id);
bool turn_retrieve_transaction_id(turn_map_t *map, const uint8_t *transaction_id,
                              addr_record_t *record);
#endif
