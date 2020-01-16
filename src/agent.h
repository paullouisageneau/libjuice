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

#include "addr.h"
#include "ice.h"
#include "juice.h"
#include "socket.h"
#include "stun.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

// RFC 8445: Agents MUST NOT use an RTO value smaller than 500 ms.
#define MIN_STUN_RETRANSMISSION_TIMEOUT 500 // msecs
#define MAX_STUN_RETRANSMISSION_COUNT 4     // count

// RFC 8445: ICE agents SHOULD use a default Ta value, 50 ms, but MAY use
// another value based on the characteristics of the associated data.
#define STUN_PACING_TIME 50 // msecs

#define MAX_CANDIDATE_PAIRS_COUNT ICE_MAX_CANDIDATES_COUNT
#define MAX_STUN_SERVER_RECORDS_COUNT 3
#define MAX_STUN_ENTRIES_COUNT (MAX_CANDIDATE_PAIRS_COUNT + MAX_STUN_SERVER_RECORDS_COUNT)

#define ICE_FAIL_TIMEOUT 30000 // msecs

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
	uint8_t transaction_id[STUN_TRANSACTION_ID_SIZE];
	timestamp_t next_transmission;
	int retransmissions;
} agent_stun_entry_t;

struct juice_agent {
	juice_config_t config;
	juice_state_t state;
	socket_t sock;
	socket_t signal_sock;
	pthread_t thread;
	pthread_mutex_t mutex;
	uint64_t ice_tiebreaker;
	ice_description_t local;
	ice_description_t remote;
	ice_candidate_pair_t candidate_pairs[MAX_CANDIDATE_PAIRS_COUNT];
	ice_candidate_pair_t *ordered_pairs[MAX_CANDIDATE_PAIRS_COUNT];
	ice_candidate_pair_t *selected_pair;
	size_t candidate_pairs_count;
	agent_stun_entry_t entries[MAX_STUN_ENTRIES_COUNT];
	size_t entries_count;
	timestamp_t fail_timestamp;
	bool thread_started;
	bool thread_destroyed;
};

juice_agent_t *agent_create(const juice_config_t *config);
void agent_destroy(juice_agent_t *agent);

int agent_gather_candidates(juice_agent_t *agent);
int agent_get_local_description(juice_agent_t *agent, char *buffer, size_t size);
int agent_set_remote_description(juice_agent_t *agent, const char *sdp);
int agent_add_remote_candidate(juice_agent_t *agent, const char *sdp);
int agent_send(juice_agent_t *agent, const char *data, size_t size);
int agent_get_selected_candidate_pair(juice_agent_t *agent, ice_candidate_t *local,
                                      ice_candidate_t *remote);

void agent_run(juice_agent_t *agent);
void agent_change_state(juice_agent_t *agent, juice_state_t state);
int agent_bookkeeping(juice_agent_t *agent, timestamp_t *next_timestamp);
int agent_stun_dispatch(juice_agent_t *agent, const stun_message_t *msg,
                        const addr_record_t *source);
int agent_process_stun_binding(juice_agent_t *agent, const stun_message_t *msg,
                               agent_stun_entry_t *entry, const addr_record_t *source);
int agent_send_stun_binding(juice_agent_t *agent, agent_stun_entry_t *entry, stun_class_t msg_class,
                            unsigned int error_code, const uint8_t *transaction_id,
                            const addr_record_t *mapped);
int agent_add_local_reflexive_candidate(juice_agent_t *agent, ice_candidate_type_t type,
                                        const addr_record_t *record);
int agent_add_remote_reflexive_candidate(juice_agent_t *agent, ice_candidate_type_t type,
                                         uint32_t priority, const addr_record_t *record);
int agent_add_candidate_pair(juice_agent_t *agent, ice_candidate_t *remote);
void agent_update_candidate_pairs(juice_agent_t *agent);
void agent_update_ordered_pairs(juice_agent_t *agent);
agent_stun_entry_t *agent_find_entry_from_record(juice_agent_t *agent, const addr_record_t *record);

#endif
