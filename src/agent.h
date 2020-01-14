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

#ifndef JUICE_AGENT_H
#define JUICE_AGENT_H

#include "ice.h"
#include "juice.h"
#include "socket.h"

#include <pthread.h>
#include <stdbool.h>

// RFC 8445: Agents MUST NOT use an RTO value smaller than 500 ms.
#define MIN_STUN_RETRANSMISSION_TIMEOUT 500 // msecs
#define MAX_STUN_RETRANSMISSION_COUNT 3     // msecs

// RFC 8445: ICE agents SHOULD use a default Ta value, 50 ms, but MAY use
// another value based on the characteristics of the associated data.
#define STUN_PACING_TIME 50 // msecs

#define MAX_CANDIDATE_PAIRS_COUNT ICE_MAX_CANDIDATES_COUNT
#define MAX_STUN_SERVER_RECORDS_COUNT 3
#define MAX_STUN_ENTRIES_COUNT                                                 \
	(MAX_CANDIDATE_PAIRS_COUNT + MAX_STUN_SERVER_RECORDS_COUNT)

typedef int64_t timestamp_t;
typedef timestamp_t timediff_t;

typedef enum agent_stun_entry_type {
	AGENT_STUN_ENTRY_TYPE_SERVER,
	AGENT_STUN_ENTRY_TYPE_CHECK,
} agent_stun_entry_type_t;

typedef struct agent_stun_entry {
	agent_stun_entry_type_t type;
	ice_candidate_pair_t *pair;
	addr_record_t record;
	timestamp_t next_transmission;
	int retransmissions;
} agent_stun_entry_t;

struct juice_agent {
	juice_config_t config;
	socket_t sock;
	pthread_t thread;
	ice_description_t local;
	ice_description_t remote;
	ice_candidate_pair_t candidate_pairs[MAX_CANDIDATE_PAIRS_COUNT];
	size_t candidate_pairs_count;
	agent_stun_entry_t entries[MAX_STUN_ENTRIES_COUNT];
	size_t entries_count;
};

#endif
