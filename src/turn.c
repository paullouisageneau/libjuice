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

static uint16_t random_channel_number() {
	/*
	 * RFC 8656 12. Channels
	 * The ChannelData message (see Section 12.4) starts with a two-byte
	 * field that carries the channel number.  The values of this field are
	 * allocated as follows:
	 *
	 *   +------------------------+--------------------------------------+
	 *   | 0x0000 through 0x3FFF: | These values can never be used for   |
	 *   |                        | channel numbers.                     |
	 *   +------------------------+--------------------------------------+
	 *   | 0x4000 through 0x4FFF: | These values are the allowed channel |
	 *   |                        | numbers (4096 possible values).      |
	 *   +------------------------+--------------------------------------+
	 *   | 0x5000 through 0xFFFF: | Reserved (For DTLS-SRTP multiplexing |
	 *   |                        | collision avoidance, see [RFC7983]). |
	 *   +------------------------+--------------------------------------+
	 */
	uint16_t r;
	juice_random(&r, 2);
	return 0x4000 | (r & 0x0FFF);
}

bool is_channel_data(const void *data, size_t size) {
	// According RFC 8656, first byte in [64..79] is TURN Channel
	if (size == 0)
		return false;
	uint8_t b = *((const uint8_t *)data);
	return b >= 64 && b <= 79;
}

int turn_wrap_channel_data(char *buffer, size_t size, const char *data, size_t data_size,
                           uint16_t channel) {
	if (channel < 0x4000 || channel > 0x4FFF) {
		JLOG_ERROR("Invalid channel number: 0x%hX", channel);
		return -1;
	}
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
	return (int)(sizeof(struct channel_data_header) + data_size);
}

bool turn_get_channel(turn_state_t *state, const addr_record_t *record, uint16_t *channel) {
	for (int i = 0; i < TURN_MAP_COUNT; ++i) {
		const turn_entry_t *entry = state->map + i;
		if (!entry->record.len)
			break;

		if (addr_record_is_equal(&entry->record, record, true)) {
			if (entry->channel == 0)
				break;

			*channel = entry->channel;
			return true;
		}
	}

	*channel = 0;
	int attempts = 1000;
	while (*channel == 0 && attempts--) {
		*channel = random_channel_number();
		for (int i = 0; i < TURN_MAP_COUNT; ++i) {
			turn_entry_t *entry = state->map + i;
			if (!entry->record.len)
				break;

			if (entry->channel == *channel) {
				*channel = 0;
				break;
			}
		}
	}

	if(*channel != 0) {
		for (int i = 0; i < TURN_MAP_COUNT; ++i) {
			turn_entry_t *entry = state->map + i;
			if (!entry->record.len || addr_record_is_equal(&entry->record, record, true)) {
				entry->record = *record;
				entry->channel = *channel;
				return true;
			}
		}
	}

	JLOG_ERROR("No more free entries in TURN state map");
	return false;
}

bool turn_find_channel(turn_state_t *state, uint16_t channel, addr_record_t *record) {
	if (channel < 0x4000 || channel > 0x4FFF) {
		JLOG_WARN("Invalid channel number: 0x%hX", channel);
		return false;
	}

	for (int i = 0; i < TURN_MAP_COUNT; ++i) {
		const turn_entry_t *entry = state->map + i;
		if (entry->channel == channel) {
			if (record)
				*record = entry->record;
			return true;
		}
	}

	return false;
}

bool turn_new_transaction_id(turn_state_t *state, const addr_record_t *record,
                             uint8_t *transaction_id) {
	juice_random(transaction_id, STUN_TRANSACTION_ID_SIZE);

	turn_transaction_entry_t *entry = state->transaction_map + state->next_transaction_entry_index;
	entry->record = *record;
	memcpy(entry->transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE);
	state->next_transaction_entry_index =
	    (state->next_transaction_entry_index + 1) % TURN_TRANSACTION_MAP_COUNT;
	return true;
}

bool turn_find_transaction_id(turn_state_t *state, const uint8_t *transaction_id,
                              addr_record_t *record) {
	for (int i = 0; i < TURN_TRANSACTION_MAP_COUNT; ++i) {
		const turn_transaction_entry_t *entry = state->transaction_map + i;
		if (!entry->record.len)
			break;

		if (memcmp(entry->transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE) == 0) {
			if (record)
				*record = entry->record;
			return true;
		}
	}

	return false;
}

bool turn_set_permission(turn_state_t *state, const uint8_t *transaction_id) {
	addr_record_t record;
	if (!turn_find_transaction_id(state, transaction_id, &record))
		return false;

	for (int i = 0; i < TURN_MAP_COUNT; ++i) {
		turn_entry_t *entry = state->map + i;
		if (!entry->record.len) {
			entry->record = record;
			entry->permission_timestamp = current_timestamp();
			return true;
		}

		if (addr_record_is_equal(&entry->record, &record, true)) {
			entry->permission_timestamp = current_timestamp();
			return true;
		}
	}

	JLOG_ERROR("No more free entries in TURN state map");
	return false;
}

bool turn_has_permission(turn_state_t *state, const addr_record_t *record) {
	for (int i = 0; i < TURN_MAP_COUNT; ++i) {
		const turn_entry_t *entry = state->map + i;
		if (!entry->record.len)
			break;

		if (addr_record_is_equal(&entry->record, record, true))
			return entry->permission_timestamp + PERMISSION_LIFETIME / 2 > current_timestamp();
	}

	return false;
}

bool turn_set_bind(turn_state_t *state, const uint8_t *transaction_id) {
	addr_record_t record;
	if (!turn_find_transaction_id(state, transaction_id, &record))
		return false;

	for (int i = 0; i < TURN_MAP_COUNT; ++i) {
		turn_entry_t *entry = state->map + i;
		if (!entry->record.len) {
			entry->record = record;
			entry->bind_timestamp = current_timestamp();
			return true;
		}

		if (addr_record_is_equal(&entry->record, &record, true)) {
			entry->bind_timestamp = current_timestamp();
			return true;
		}
	}

	JLOG_ERROR("No more free entries in TURN state map");
	return false;
}

bool turn_has_bind(turn_state_t *state, const addr_record_t *record) {
	for (int i = 0; i < TURN_MAP_COUNT; ++i) {
		const turn_entry_t *entry = state->map + i;
		if (!entry->record.len)
			break;

		if (addr_record_is_equal(&entry->record, record, true))
			return entry->bind_timestamp + BIND_LIFETIME / 2 > current_timestamp();
	}

	return false;
}
