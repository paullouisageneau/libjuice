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

#include "turn.h"
#include "random.h"
#include "socket.h"

#include <string.h>

// RFC 8656: The Permission Lifetime MUST be 300 seconds (= 5 minutes)
#define PERMISSION_LIFETIME 300000 // ms

// RFC 8656: Channel bindings last for 10 minutes unless refreshed
#define BIND_LIFETIME 600000 // ms

int turn_wrap_channel_data(char *buffer, size_t size, const char *data, size_t data_size,
                           uint16_t channel) {
	if (data_size >= 65536) {
		JLOG_ERROR("ChannelData is too long, size=%zu", size);
		return -1;
	}
	if (size < sizeof(struct channel_data_header) + data_size) {
		JLOG_ERROR("Buffer is too small to add ChannelData header, size=%zu, needed=%zu", size,
		           sizeof(struct channel_data_header) + data_size);
		return -1;
	}

	memmove(buffer + sizeof(struct channel_data_header), data, data_size);
	struct channel_data_header *header = (struct channel_data_header *)buffer;
	header->channel_number = htons((uint16_t)channel);
	header->length = htons((uint16_t)data_size);
	return 0;
}

void turn_set_transaction_id(turn_state_t *state, const addr_record_t *record, const uint8_t *transaction_id) {
	for (int i = 0; i < TURN_MAP_COUNT; ++i) {
		turn_entry_t *entry = state->map + i;
		if (!entry->record.len) {
			entry->record = *record;
			memcpy(entry->transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE);
			return;
		}
		if (addr_record_is_equal(&entry->record, record, true)) {
			memcpy(entry->transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE);
			return;
		}
	}

	JLOG_WARN("No more free entries in TURN state map");
}

void turn_set_channel(turn_state_t *state, const addr_record_t *record, uint16_t channel) {
	for (int i = 0; i < TURN_MAP_COUNT; ++i) {
		turn_entry_t *entry = state->map + i;
		if (!entry->record.len) {
			entry->record = *record;
			entry->channel = channel;
			return;
		}
		if (addr_record_is_equal(&entry->record, record, true)) {
			entry->channel = channel;
			return;
		}
	}

	JLOG_WARN("No more free entries in TURN state map");
}

bool turn_get_channel(turn_state_t *state, const addr_record_t *record, uint16_t *channel) {
	for (int i = 0; i < TURN_MAP_COUNT; ++i) {
		const turn_entry_t *entry = state->map + i;
		if(!entry->record.len)
			break;

		if (addr_record_is_equal(&entry->record, record, true)) {
			*channel = entry->channel;
			return true;
		}
	}

	return false;
}

void turn_set_permission(turn_state_t *state, const uint8_t *transaction_id) {
	for (int i = 0; i < TURN_MAP_COUNT; ++i) {
		turn_entry_t *entry = state->map + i;
		if (!entry->record.len)
			return;

		if (memcmp(entry->transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE) == 0) {
			entry->permission_timestamp = current_timestamp();
			return;
		}
	}
}

bool turn_has_permission(turn_state_t *state, const addr_record_t *record) {
	for (int i = 0; i < TURN_MAP_COUNT; ++i) {
		const turn_entry_t *entry = state->map + i;
		if (addr_record_is_equal(&entry->record, record, true))
			return entry->permission_timestamp + PERMISSION_LIFETIME / 2 < current_timestamp();
	}

	return false;
}

void turn_set_bind(turn_state_t *state, const uint8_t *transaction_id) {
	for (int i = 0; i < TURN_MAP_COUNT; ++i) {
		turn_entry_t *entry = state->map + i;
		if (!entry->record.len)
			return;

		if (memcmp(entry->transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE) == 0) {
			entry->bind_timestamp = current_timestamp();
			return;
		}
	}

	JLOG_WARN("No more free entries in TURN state map");
}

bool turn_has_bind(turn_state_t *state, const addr_record_t *record) {
	for (int i = 0; i < TURN_MAP_COUNT; ++i) {
		const turn_entry_t *entry = state->map + i;
		if (addr_record_is_equal(&entry->record, record, true))
			return entry->permission_timestamp + BIND_LIFETIME / 2 < current_timestamp();
	}

	return false;
}
