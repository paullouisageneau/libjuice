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

#ifdef __STDC_NO_ATOMICS__
#define NO_ATOMICS
#endif

#include "addr.h"
#include "ice.h"
#include "juice.h"
#include "socket.h"
#include "stun.h"
#include "thread.h"
#include "timestamp.h"
#include "turn.h"

#include <stdbool.h>
#include <stdint.h>

#ifndef NO_ATOMICS
#include <stdatomic.h>
#endif

// RFC 8445: Agents MUST NOT use an RTO value smaller than 500 ms.
#define MIN_STUN_RETRANSMISSION_TIMEOUT 500 // msecs
#define MAX_STUN_RETRANSMISSION_COUNT 5     // count (exponential backoff, will give ~30s)

// RFC 8445: ICE agents SHOULD use a default Ta value, 50 ms, but MAY use
// another value based on the characteristics of the associated data.
#define STUN_PACING_TIME 50 // msecs

// RFC 8445: Agents SHOULD use a Tr value of 15 seconds. Agents MAY use a bigger value but MUST NOT
// use a value smaller than 15 seconds.
#define STUN_KEEPALIVE_PERIOD 15000 // msecs

// TURN refresh period
#define TURN_LIFETIME 600000                        // msecs, 10 min
#define TURN_REFRESH_PERIOD (TURN_LIFETIME - 60000) // msecs, lifetime - 1 min

// ICE trickling timeout
#define ICE_FAIL_TIMEOUT 30000 // msecs

// Max STUN and TURN server entries
#define MAX_SERVER_ENTRIES_COUNT 2 // max STUN server entries
#define MAX_RELAY_ENTRIES_COUNT 2  // max TURN server entries

// Compute max candidates and entries count
// This guarantees 8 (+1 to be safe) host candidates slots
#define MAX_STUN_SERVER_RECORDS_COUNT MAX_SERVER_ENTRIES_COUNT
#define MAX_HOST_CANDIDATES_COUNT ((ICE_MAX_CANDIDATES_COUNT - MAX_STUN_SERVER_RECORDS_COUNT) / 2)
#define MAX_PEER_REFLEXIVE_CANDIDATES_COUNT MAX_HOST_CANDIDATES_COUNT
#define MAX_CANDIDATE_PAIRS_COUNT (ICE_MAX_CANDIDATES_COUNT * (1 + MAX_RELAY_ENTRIES_COUNT))
#define MAX_STUN_ENTRIES_COUNT (MAX_CANDIDATE_PAIRS_COUNT + MAX_STUN_SERVER_RECORDS_COUNT)

#define AGENT_TURN_MAP_SIZE ICE_MAX_CANDIDATES_COUNT

typedef enum agent_mode {
	AGENT_MODE_UNKNOWN,
	AGENT_MODE_CONTROLLED,
	AGENT_MODE_CONTROLLING
} agent_mode_t;

typedef enum agent_stun_entry_type {
	AGENT_STUN_ENTRY_TYPE_EMPTY,
	AGENT_STUN_ENTRY_TYPE_SERVER,
	AGENT_STUN_ENTRY_TYPE_RELAY,
	AGENT_STUN_ENTRY_TYPE_CHECK
} agent_stun_entry_type_t;

typedef enum agent_stun_entry_state {
	AGENT_STUN_ENTRY_STATE_PENDING,
	AGENT_STUN_ENTRY_STATE_CANCELLED,
	AGENT_STUN_ENTRY_STATE_FAILED,
	AGENT_STUN_ENTRY_STATE_SUCCEEDED,
	AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE,
	AGENT_STUN_ENTRY_STATE_IDLE
} agent_stun_entry_state_t;

typedef struct agent_turn_state {
	turn_map_t map;
	stun_credentials_t credentials;
	const char *password;
} agent_turn_state_t;

typedef struct agent_stun_entry {
	agent_stun_entry_type_t type;
	agent_stun_entry_state_t state;
	agent_mode_t mode;
	ice_candidate_pair_t *pair;
	addr_record_t record;
	addr_record_t relayed;
	uint8_t transaction_id[STUN_TRANSACTION_ID_SIZE];
	timestamp_t next_transmission;
	timediff_t retransmission_timeout;
	int retransmissions;

	// TURN
	agent_turn_state_t *turn;
	struct agent_stun_entry *relay_entry;

#ifdef NO_ATOMICS
	volatile bool armed;
#else
	atomic_flag armed;
#endif

	juice_transport_t transport;
	socket_t sock;
} agent_stun_entry_t;

struct juice_agent {
	juice_config_t config;
	juice_state_t state;
	agent_mode_t mode;
	socket_t sock;
	thread_t thread;
	mutex_t mutex;

	ice_description_t local;
	ice_description_t remote;

	ice_candidate_pair_t candidate_pairs[MAX_CANDIDATE_PAIRS_COUNT];
	ice_candidate_pair_t *ordered_pairs[MAX_CANDIDATE_PAIRS_COUNT];
	ice_candidate_pair_t *selected_pair;
	int candidate_pairs_count;

	agent_stun_entry_t entries[MAX_STUN_ENTRIES_COUNT];
	int entries_count;
#ifdef NO_ATOMICS
	agent_stun_entry_t *volatile selected_entry;
#else
	_Atomic(agent_stun_entry_t *) selected_entry;
#endif

	uint64_t ice_tiebreaker;
	timestamp_t fail_timestamp;
	bool gathering_done;
	bool thread_started;
	bool thread_stopped;

	mutex_t send_mutex;
	int send_ds;
};

juice_agent_t *agent_create(const juice_config_t *config);
void agent_do_destroy(juice_agent_t *agent);
void agent_destroy(juice_agent_t *agent);

int agent_gather_candidates(juice_agent_t *agent);
int agent_get_local_description(juice_agent_t *agent, char *buffer, size_t size);
int agent_set_remote_description(juice_agent_t *agent, const char *sdp);
int agent_add_remote_candidate(juice_agent_t *agent, const char *sdp);
int agent_set_remote_gathering_done(juice_agent_t *agent);
int agent_send(juice_agent_t *agent, const char *data, size_t size, int ds);
int agent_direct_send(juice_agent_t *agent, const addr_record_t *dst, const char *data, size_t size,
                      int ds);
int agent_direct_send2(juice_agent_t *agent, const agent_stun_entry_t *entry, const char *data,
                       size_t size, int ds);
int agent_relay_send(juice_agent_t *agent, agent_stun_entry_t *entry, const addr_record_t *dst,
                     const char *data, size_t size, int ds);
int agent_channel_send(juice_agent_t *agent, agent_stun_entry_t *entry, const addr_record_t *dst,
                       const char *data, size_t size, int ds);
juice_state_t agent_get_state(juice_agent_t *agent);
int agent_get_selected_candidate_pair(juice_agent_t *agent, ice_candidate_t *local,
                                      ice_candidate_t *remote);

void agent_run(juice_agent_t *agent);
int agent_recv(juice_agent_t *agent, agent_stun_entry_t *entry);
int agent_input(juice_agent_t *agent, char *buf, size_t len, const addr_record_t *src,
                const addr_record_t *relayed); // relayed may be NULL
int agent_interrupt(juice_agent_t *agent);
void agent_change_state(juice_agent_t *agent, juice_state_t state);
int agent_bookkeeping(juice_agent_t *agent, timestamp_t *next_timestamp);
int agent_verify_stun_binding(juice_agent_t *agent, void *buf, size_t size,
                              const stun_message_t *msg);
int agent_verify_credentials(juice_agent_t *agent, const agent_stun_entry_t *entry, void *buf,
                             size_t size, stun_message_t *msg);
int agent_dispatch_stun(juice_agent_t *agent, void *buf, size_t size, stun_message_t *msg,
                        const addr_record_t *src,
                        const addr_record_t *relayed); // relayed may be NULL
int agent_process_stun_binding(juice_agent_t *agent, const stun_message_t *msg,
                               agent_stun_entry_t *entry, const addr_record_t *src,
                               const addr_record_t *relayed); // relayed may be NULL
int agent_send_stun_binding(juice_agent_t *agent, agent_stun_entry_t *entry,
                            stun_class_t msg_class, unsigned int error_code,
                            const uint8_t *transaction_id, const addr_record_t *mapped);
int agent_process_turn_allocate(juice_agent_t *agent, const stun_message_t *msg,
                                agent_stun_entry_t *entry);
int agent_send_turn_allocate_request(juice_agent_t *agent, const agent_stun_entry_t *entry,
                                     stun_method_t method);
int agent_process_turn_create_permission(juice_agent_t *agent, const stun_message_t *msg,
                                         agent_stun_entry_t *entry);
int agent_send_turn_create_permission_request(juice_agent_t *agent, agent_stun_entry_t *entry,
                                              const addr_record_t *record, int ds);
int agent_process_turn_channel_bind(juice_agent_t *agent, const stun_message_t *msg,
                                    agent_stun_entry_t *entry);
int agent_send_turn_channel_bind_request(juice_agent_t *agent, agent_stun_entry_t *entry,
                                         const addr_record_t *record, int ds,
                                         uint16_t *out_channel); // out_channel may be NULL
int agent_process_turn_data(juice_agent_t *agent, const stun_message_t *msg,
                            agent_stun_entry_t *entry);
int agent_process_channel_data(juice_agent_t *agent, agent_stun_entry_t *entry, char *buf,
                               size_t len);

int agent_add_local_relayed_candidate(juice_agent_t *agent, const addr_record_t *record);
int agent_add_local_reflexive_candidate(juice_agent_t *agent, ice_candidate_type_t type,
                                        const addr_record_t *record);
int agent_add_remote_reflexive_candidate(juice_agent_t *agent, ice_candidate_type_t type,
                                         uint32_t priority, const addr_record_t *record);
int agent_add_candidate_pair(juice_agent_t *agent, ice_candidate_t *local,
                             ice_candidate_t *remote); // local may be NULL
int agent_add_candidate_pairs_for_remote(juice_agent_t *agent, ice_candidate_t *remote);
int agent_unfreeze_candidate_pair(juice_agent_t *agent, ice_candidate_pair_t *pair);

void agent_arm_transmission(juice_agent_t *agent, agent_stun_entry_t *entry, timediff_t delay);
void agent_update_gathering_done(juice_agent_t *agent);
void agent_update_candidate_pairs(juice_agent_t *agent);
void agent_update_ordered_pairs(juice_agent_t *agent);

agent_stun_entry_t *
agent_find_entry_from_record(juice_agent_t *agent, const addr_record_t *record,
                             const addr_record_t *relayed); // relayed may be NULL
void agent_translate_host_candidate_entry(juice_agent_t *agent, agent_stun_entry_t *entry);

#endif
