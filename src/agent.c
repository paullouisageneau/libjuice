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

#include "agent.h"
#include "ice.h"
#include "juice.h"
#include "log.h"
#include "random.h"
#include "stun.h"
#include "udp.h"

#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 4096

static timestamp_t current_timestamp() {
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts))
		return 0;
	return (timestamp_t)ts.tv_sec * 1000 + (timestamp_t)ts.tv_nsec / 1000000;
}

juice_agent_t *agent_create(const juice_config_t *config) {
	JLOG_VERBOSE("Creating agent");
	juice_agent_t *agent = malloc(sizeof(juice_agent_t));
	if (!agent) {
		JLOG_FATAL("malloc for agent failed");
		return NULL;
	}
	memset(agent, 0, sizeof(*agent));
	agent->config = *config;
	agent->state = JUICE_STATE_DISCONNECTED;
	agent->mode = AGENT_MODE_UNKNOWN;
	agent->sock = INVALID_SOCKET;

	pthread_mutexattr_t mutexattr;
	pthread_mutexattr_init(&mutexattr);
	pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&agent->mutex, &mutexattr);

	ice_create_local_description(&agent->local);

	// RFC 8445: 16.1. Attributes
	// The content of the [ICE-CONTROLLED/ICE-CONTROLLING] attribute is a 64-bit
	// unsigned integer in network byte order, which contains a random number.
	// The number is used for solving role conflicts, when it is referred to as
	// the "tiebreaker value".  An ICE agent MUST use the same number for
	// all Binding requests, for all streams, within an ICE session, unless
	// it has received a 487 response, in which case it MUST change the
	// number.
	juice_random(&agent->ice_tiebreaker, sizeof(agent->ice_tiebreaker));

	return agent;
}

void agent_do_destroy(juice_agent_t *agent) {
	JLOG_VERBOSE("Destroying agent");
	close(agent->sock);
	pthread_mutex_destroy(&agent->mutex);
	free(agent);
}

void agent_destroy(juice_agent_t *agent) {
	pthread_mutex_lock(&agent->mutex);
	if (!agent->thread_started) {
		pthread_mutex_unlock(&agent->mutex);
		agent_do_destroy(agent);
		return;
	}

	JLOG_VERBOSE("Requesting agent destruction");
	agent->thread_destroyed = true;
	memset(&agent->config, 0, sizeof(agent->config));
	pthread_mutex_unlock(&agent->mutex);
}

void *agent_thread_entry(void *arg) {
	agent_run((juice_agent_t *)arg);
	return NULL;
}

int agent_gather_candidates(juice_agent_t *agent) {
	pthread_mutex_lock(&agent->mutex);
	if (agent->sock != INVALID_SOCKET) {
		JLOG_ERROR("Started candidates gathering twice");
		pthread_mutex_unlock(&agent->mutex);
		return -1;
	}

	agent->sock = udp_create_socket();
	if (agent->sock == INVALID_SOCKET) {
		JLOG_FATAL("UDP socket creation for agent failed");
		pthread_mutex_unlock(&agent->mutex);
		return -1;
	}
	agent_change_state(agent, JUICE_STATE_GATHERING);

	addr_record_t records[ICE_MAX_CANDIDATES_COUNT - 1];
	int records_count = udp_get_addrs(agent->sock, records, ICE_MAX_CANDIDATES_COUNT - 1);
	if (records_count < 0) {
		JLOG_ERROR("Failed to gather local host candidates");
		records_count = 0;
	} else if (records_count == 0) {
		JLOG_WARN("No local host candidates gathered");
	}

	JLOG_VERBOSE("Adding %d local host candidates", records_count);
	for (int i = 0; i < records_count; ++i) {
		ice_candidate_t candidate;
		if (ice_create_local_candidate(ICE_CANDIDATE_TYPE_HOST, 1, records + i, &candidate)) {
			JLOG_ERROR("Failed to create host candidate");
			continue;
		}
		if (ice_add_candidate(&candidate, &agent->local)) {
			JLOG_ERROR("Failed to add candidate to local description");
			continue;
		}
	}
	ice_sort_candidates(&agent->local);

	char buffer[BUFFER_SIZE];
	for (int i = 0; i < agent->local.candidates_count; ++i) {
		ice_candidate_t *candidate = agent->local.candidates + i;
		if (ice_generate_candidate_sdp(candidate, buffer, BUFFER_SIZE) < 0) {
			JLOG_ERROR("Failed to generate SDP for local candidate");
			continue;
		}

		JLOG_DEBUG("Gathered host candidate: %s", buffer);

		if (agent->config.cb_candidate)
			agent->config.cb_candidate(agent, buffer, agent->config.user_ptr);
	}

	if (agent->mode == AGENT_MODE_UNKNOWN) {
		JLOG_DEBUG("Assuming controlling mode");
		agent->mode = AGENT_MODE_CONTROLLING;
	}
	int ret = pthread_create(&agent->thread, NULL, agent_thread_entry, agent);
	if (ret) {
		JLOG_FATAL("pthread_create for agent failed, error=%d", ret);
		pthread_mutex_unlock(&agent->mutex);
		return -1;
	}
	pthread_detach(agent->thread);
	agent->thread_started = true;
	pthread_mutex_unlock(&agent->mutex);
	return 0;
}

int agent_get_local_description(juice_agent_t *agent, char *buffer, size_t size) {
	pthread_mutex_lock(&agent->mutex);
	if (ice_generate_sdp(&agent->local, buffer, size) < 0)
		return -1;
	if (agent->mode == AGENT_MODE_UNKNOWN) {
		JLOG_DEBUG("Assuming controlling mode");
		agent->mode = AGENT_MODE_CONTROLLING;
	}
	pthread_mutex_unlock(&agent->mutex);
	return 0;
}

int agent_set_remote_description(juice_agent_t *agent, const char *sdp) {
	pthread_mutex_lock(&agent->mutex);
	if (ice_parse_sdp(sdp, &agent->remote) < 0) {
		JLOG_ERROR("Failed to parse remote SDP description");
		pthread_mutex_unlock(&agent->mutex);
		return -1;
	}
	for (size_t i = 0; i < agent->remote.candidates_count; ++i) {
		if (agent_add_candidate_pair(agent, agent->remote.candidates + i)) {
			pthread_mutex_unlock(&agent->mutex);
			return -1;
		}
	}
	if (agent->mode == AGENT_MODE_UNKNOWN) {
		JLOG_DEBUG("Assuming controlled mode");
		agent->mode = AGENT_MODE_CONTROLLED;
	}
	pthread_mutex_unlock(&agent->mutex);
	return 0;
}

int agent_add_remote_candidate(juice_agent_t *agent, const char *sdp) {
	pthread_mutex_lock(&agent->mutex);
	ice_candidate_t candidate;
	if (ice_parse_candidate_sdp(sdp, &candidate) < 0) {
		JLOG_ERROR("Failed to parse remote SDP candidate");
		pthread_mutex_unlock(&agent->mutex);
		return -1;
	}
	if (ice_add_candidate(&candidate, &agent->remote)) {
		JLOG_ERROR("Failed to add candidate to remote description");
		pthread_mutex_unlock(&agent->mutex);
		return -1;
	}
	ice_candidate_t *remote = agent->remote.candidates + agent->remote.candidates_count - 1;
	int ret = agent_add_candidate_pair(agent, remote);
	pthread_mutex_unlock(&agent->mutex);
	return ret;
}

int agent_set_remote_gathering_done(juice_agent_t *agent) {
	pthread_mutex_lock(&agent->mutex);
	agent->remote.finished = true;
	agent->fail_timestamp = 0; // So the bookkeeping will recompute it and fail
	pthread_mutex_unlock(&agent->mutex);
	return 0;
}

int agent_send(juice_agent_t *agent, const char *data, size_t size) {
	pthread_mutex_lock(&agent->mutex);
	if (!agent->selected_pair) {
		JLOG_ERROR("Send called before ICE is connected");
		pthread_mutex_unlock(&agent->mutex);
		return -1;
	}
	const addr_record_t *record = &agent->selected_pair->remote->resolved;
	int ret =
	    sendto(agent->sock, data, size, 0, (const struct sockaddr *)&record->addr, record->len);
	pthread_mutex_unlock(&agent->mutex);
	return ret;
}

juice_state_t agent_get_state(juice_agent_t *agent) {
	pthread_mutex_lock(&agent->mutex);
	juice_state_t state = agent->state;
	pthread_mutex_unlock(&agent->mutex);
	return state;
}

int agent_get_selected_candidate_pair(juice_agent_t *agent, ice_candidate_t *local,
                                      ice_candidate_t *remote) {
	pthread_mutex_lock(&agent->mutex);
	ice_candidate_pair_t *pair = agent->selected_pair;
	if (!pair) {
		pthread_mutex_unlock(&agent->mutex);
		return -1;
	}
	*local = pair->local ? *pair->local : agent->local.candidates[0];
	*remote = *pair->remote;
	pthread_mutex_unlock(&agent->mutex);
	return 0;
}

void agent_run(juice_agent_t *agent) {
	pthread_mutex_lock(&agent->mutex);
	agent_change_state(agent, JUICE_STATE_CONNECTING);

	// STUN server handling
	if (agent->config.stun_server_host) {
		if (!agent->config.stun_server_port)
			agent->config.stun_server_port = 3478; // default STUN port
		char service[8];
		snprintf(service, 8, "%hd", (uint16_t)agent->config.stun_server_port);
		addr_record_t records[MAX_STUN_SERVER_RECORDS_COUNT];
		int records_count = addr_resolve(agent->config.stun_server_host, service, records,
		                                 MAX_STUN_SERVER_RECORDS_COUNT);
		if (records_count > 0) {
			JLOG_VERBOSE("Sending STUN binding request to %zu server addresses", records_count);
			for (int i = 0; i < records_count; ++i) {
				if (agent->entries_count >= MAX_STUN_ENTRIES_COUNT)
					break;
				JLOG_VERBOSE("Registering STUN entry %d for server request", agent->entries_count);
				agent_stun_entry_t *entry = agent->entries + agent->entries_count;
				entry->type = AGENT_STUN_ENTRY_TYPE_SERVER;
				entry->pair = NULL;
				entry->record = records[i];
				entry->next_transmission =
				    current_timestamp() + STUN_PACING_TIME * agent->entries_count;
				entry->retransmissions = MAX_STUN_RETRANSMISSION_COUNT;
				juice_random(entry->transaction_id, STUN_TRANSACTION_ID_SIZE);
				++agent->entries_count;
			}
		} else {
			JLOG_ERROR("STUN address resolution failed");
		}
	}

	agent_update_gathering_done(agent);

	// Main loop
	timestamp_t next_timestamp;
	while (agent_bookkeeping(agent, &next_timestamp) == 0) {
		timediff_t timediff = next_timestamp - current_timestamp();
		if (timediff < 0)
			timediff = 0;
		JLOG_VERBOSE("Setting select timeout to %ld ms", (long)timediff);
		struct timeval timeout;
		timeout.tv_sec = timediff / 1000;
		timeout.tv_usec = timediff * 1000;
		fd_set set;
		FD_ZERO(&set);
		FD_SET(agent->sock, &set);
		int n = SOCKET_TO_INT(agent->sock) + 1;
		pthread_mutex_unlock(&agent->mutex);
		int ret = select(n, &set, NULL, NULL, &timeout);
		pthread_mutex_lock(&agent->mutex);
		if (ret < 0) {
			JLOG_ERROR("select failed, errno=%d", errno);
			break;
		}
		if (agent->thread_destroyed) {
			JLOG_VERBOSE("Agent destruction requested");
			break;
		}

		if (FD_ISSET(agent->sock, &set)) {
			char buffer[BUFFER_SIZE];
			addr_record_t record;
			record.len = sizeof(record.addr);
			int len = recvfrom(agent->sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&record.addr,
			                   &record.len);
			if (len < 0) {
				JLOG_ERROR("recvfrom failed, errno=%d", errno);
				break;
			}

			if (record.addr.ss_family == AF_INET6)
				addr_unmap_inet6_v4mapped((struct sockaddr *)&record.addr, &record.len);

			// See agent_send_stun_binding(() for username format
			const size_t username_size = 256 * 2 + 2;
			char username[username_size];
			snprintf(username, username_size, "%s:%s", agent->local.ice_ufrag,
			         agent->remote.ice_ufrag);

			stun_message_t msg;
			int ret = stun_read(buffer, len, &msg);
			if (ret < 0) {
				JLOG_WARN("STUN message read failed");
				continue;
			} else if (ret > 0) {
				JLOG_DEBUG("Received a STUN message");
				if (agent_verify_stun(agent, buffer, len, &msg)) {
					JLOG_ERROR("STUN message verification failed");
					continue;
				}
				if (agent_dispatch_stun(agent, &msg, &record)) {
					JLOG_ERROR("STUN message dispatching failed");
					continue;
				}
			} else {
				JLOG_DEBUG("Received a non-STUN datagram");
				agent_stun_entry_t *entry = agent_find_entry_from_record(agent, &record);
				if (!entry || !entry->pair) {
					JLOG_WARN("Received a datagram from unknown address, ignoring");
					continue;
				}
				if (!entry->pair->nominated) {
					JLOG_WARN("Received a datagram from a non-nominated "
					          "candidate pair, ignoring");
					continue;
				}
				if (agent->config.cb_recv)
					agent->config.cb_recv(agent, buffer, len, agent->config.user_ptr);
			}
		}
	}
	JLOG_DEBUG("Leaving agent thread");
	agent_change_state(agent, JUICE_STATE_DISCONNECTED);
	agent_do_destroy(agent);
}

void agent_change_state(juice_agent_t *agent, juice_state_t state) {
	if (state != agent->state) {
		JLOG_INFO("Changing state to %s", juice_state_to_string(state));
		agent->state = state;
		if (agent->config.cb_state_changed)
			agent->config.cb_state_changed(agent, state, agent->config.user_ptr);
	}
}

int agent_bookkeeping(juice_agent_t *agent, timestamp_t *next_timestamp) {
	timestamp_t now = current_timestamp();
	*next_timestamp = now + 1000;

	if (agent->state == JUICE_STATE_DISCONNECTED)
		return 0;

	for (int i = 0; i < agent->entries_count; ++i) {
		agent_stun_entry_t *entry = agent->entries + i;
		if (entry->pair && (entry->pair->state == ICE_CANDIDATE_PAIR_STATE_FROZEN ||
		                    entry->pair->state == ICE_CANDIDATE_PAIR_STATE_FAILED))
			continue;

		if (entry->next_transmission && entry->next_transmission <= now) {
			JLOG_VERBOSE("STUN entry %d: Transmission time reached", i);
			if (entry->retransmissions > 0) {
				JLOG_DEBUG("STUN entry %d: Sending request", i);
				if (entry->pair)
					entry->pair->state = ICE_CANDIDATE_PAIR_STATE_INPROGRESS;
				agent_send_stun_binding(agent, entry, STUN_CLASS_REQUEST, 0, NULL, NULL);
			} else {
				JLOG_DEBUG("STUN entry %d: Failed", i);
				if (entry->pair)
					entry->pair->state = ICE_CANDIDATE_PAIR_STATE_FAILED;
				entry->next_transmission = 0;
				entry->finished = true;
				if (entry->type == AGENT_STUN_ENTRY_TYPE_SERVER)
					agent_update_gathering_done(agent);
			}
		}
		if (entry->next_transmission && *next_timestamp > entry->next_transmission)
			*next_timestamp = entry->next_transmission;
	}

	if (agent->candidate_pairs_count == 0)
		return 0;

	unsigned int pending_count = 0;
	unsigned int nominated_count = 0;
	ice_candidate_pair_t *selected_pair = NULL;
	for (int i = 0; i < agent->candidate_pairs_count; ++i) {
		ice_candidate_pair_t *pair = *(agent->ordered_pairs + i);
		if (pair->state == ICE_CANDIDATE_PAIR_STATE_WAITING ||
		    pair->state == ICE_CANDIDATE_PAIR_STATE_INPROGRESS) {
			if (nominated_count > 0) {
				// A higher-priority pair was nominated, we can stop checking
				JLOG_VERBOSE("Cancelling check for lower-priority pair");
				pair->state = ICE_CANDIDATE_PAIR_STATE_FROZEN;
			} else {
				++pending_count;
			}
		}
		if (pair->nominated) {
			++nominated_count;
			if (!selected_pair)
				selected_pair = pair;
		}
	}

	if (agent->selected_pair != selected_pair) {
		JLOG_DEBUG("New selected pair");
		agent->selected_pair = selected_pair;
	}

	if (nominated_count > 0) {
		agent->fail_timestamp = 0;
		if (pending_count > 0)
			agent_change_state(agent, JUICE_STATE_CONNECTED);
		else if (agent->state != JUICE_STATE_CONNECTED && agent->state != JUICE_STATE_COMPLETED)
			agent_change_state(agent, JUICE_STATE_CONNECTED);
		else
			agent_change_state(agent, JUICE_STATE_COMPLETED);
	} else if (pending_count > 0) {
		agent->fail_timestamp = 0;
	} else {
		if (!agent->fail_timestamp)
			agent->fail_timestamp = now + (agent->remote.finished ? 0 : ICE_FAIL_TIMEOUT);

		if (agent->fail_timestamp && now >= agent->fail_timestamp)
			agent_change_state(agent, JUICE_STATE_FAILED);
		else if (*next_timestamp > agent->fail_timestamp)
			*next_timestamp = agent->fail_timestamp;
	}
	return 0;
}

int agent_verify_stun(juice_agent_t *agent, void *buf, size_t size, const stun_message_t *msg) {
	if (msg->has_integrity) {
		char expected_username[STUN_MAX_USERNAME_LEN];
		const char *password;
		if (msg->msg_class == STUN_CLASS_REQUEST) {
			snprintf(expected_username, STUN_MAX_USERNAME_LEN, "%s:%s", agent->local.ice_ufrag,
			         agent->remote.ice_ufrag);
			password = agent->local.ice_pwd;
		} else {
			snprintf(expected_username, STUN_MAX_USERNAME_LEN, "%s:%s", agent->remote.ice_ufrag,
			         agent->local.ice_ufrag);
			password = agent->remote.ice_pwd;
		}
		if (strcmp(msg->username, expected_username) != 0) {
			JLOG_WARN("STUN username check failed, expected=\"%s\", actual=\'%s\"",
			          expected_username, msg->username);
			return -1;
		}
		if (!stun_check_integrity(buf, size, msg, password)) {
			JLOG_WARN("STUN integrity check failed, password=\"%s\"", password);
			return -1;
		}
	}
	return 0;
}

int agent_dispatch_stun(juice_agent_t *agent, const stun_message_t *msg,
                        const addr_record_t *source) {
	if (msg->msg_method != STUN_METHOD_BINDING) {
		JLOG_WARN("Unknown STUN method %X, ignoring", msg->msg_method);
		return -1;
	}
	agent_stun_entry_t *entry = NULL;
	if (msg->has_integrity) { // this is a check from the remote peer
		JLOG_VERBOSE("STUN message is from the remote peer");
		if (agent_add_remote_reflexive_candidate(agent, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
		                                         msg->priority, source)) {
			JLOG_WARN("Failed to add remote peer reflexive candidate from "
			          "STUN message");
		}
		if (msg->msg_class != STUN_CLASS_REQUEST) {
			for (int i = 0; i < agent->entries_count; ++i) {
				if (memcmp(msg->transaction_id, agent->entries[i].transaction_id,
				           STUN_TRANSACTION_ID_SIZE) == 0) {
					JLOG_DEBUG("STUN entry %d matching incoming transaction ID", i);
					entry = &agent->entries[i];
					break;
				}
			}
		}
	}
	if (!entry)
		entry = agent_find_entry_from_record(agent, source);

	if (!entry) {
		JLOG_ERROR("STUN entry for message processing not found");
		return -1;
	}
	if (!msg->has_integrity && entry->type == AGENT_STUN_ENTRY_TYPE_CHECK) {
		JLOG_WARN("STUN binding message from remote peer missing integrity");
		return -1;
	}
	if (agent_process_stun_binding(agent, msg, entry, source)) {
		JLOG_ERROR("STUN message processing failed");
		return -1;
	}
	return 0;
}

int agent_process_stun_binding(juice_agent_t *agent, const stun_message_t *msg,
                               agent_stun_entry_t *entry, const addr_record_t *source) {
	switch (msg->msg_class) {
	case STUN_CLASS_REQUEST: {
		JLOG_DEBUG("Got STUN binding request");
		if (entry->type != AGENT_STUN_ENTRY_TYPE_CHECK)
			return -1;
		ice_candidate_pair_t *pair = entry->pair;
		if (msg->ice_controlling == msg->ice_controlled) {
			agent_send_stun_binding(agent, entry, STUN_CLASS_RESP_ERROR, 400, msg->transaction_id,
			                        NULL);
			return -1;
		}
		// RFC8445 7.3.1.1. Detecting and Repairing Role Conflicts:
		// If the agent is in the controlling role, and the ICE-CONTROLLING attribute is present in
		// the request:
		//  * If the agent's tiebreaker value is larger than or equal to the contents of the
		//  ICE-CONTROLLING attribute, the agent generates a Binding error response and includes an
		//  ERROR-CODE attribute with a value of 487 (Role Conflict) but retains its role.
		//  * If the agent's tiebreaker value is less than the contents of the ICE-CONTROLLING
		//  attribute, the agent switches to the controlled role.
		if (msg->ice_controlling && agent->mode == AGENT_MODE_CONTROLLING) {
			JLOG_WARN("ICE role conflict (both controlling)");
			if (agent->ice_tiebreaker >= msg->ice_controlling) {
				JLOG_DEBUG("Asking remote peer to switch roles");
				agent_send_stun_binding(agent, entry, STUN_CLASS_RESP_ERROR, 487,
				                        msg->transaction_id, NULL);
			} else {
				JLOG_DEBUG("Switching to controlled role");
				agent->mode = AGENT_MODE_CONTROLLED;
				agent_update_candidate_pairs(agent);
			}
			break;
		}
		// If the agent is in the controlled role, and the ICE-CONTROLLED attribute is present in
		// the request:
		//  * If the agent's tiebreaker value is larger than or equal to the contents of the
		//  ICE-CONTROLLED attribute, the agent switches to the controlling role.
		//  * If the agent's tiebreaker value is less than the contents of the ICE-CONTROLLED
		//  attribute, the agent generates a Binding error response and includes an ERROR-CODE
		//  attribute with a value of 487 (Role Conflict) but retains its role.
		if (msg->ice_controlled && agent->mode == AGENT_MODE_CONTROLLED) {
			JLOG_WARN("ICE role conflict (both controlled)");
			if (agent->ice_tiebreaker >= msg->ice_controlling) {
				JLOG_DEBUG("Switching to controlling role");
				agent->mode = AGENT_MODE_CONTROLLING;
				agent_update_candidate_pairs(agent);
			} else {
				JLOG_DEBUG("Asking remote peer to switch roles");
				agent_send_stun_binding(agent, entry, STUN_CLASS_RESP_ERROR, 487,
				                        msg->transaction_id, NULL);
			}
			break;
		}
		if (msg->use_candidate) {
			if (!msg->ice_controlling) {
				agent_send_stun_binding(agent, entry, STUN_CLASS_RESP_ERROR, 400,
				                        msg->transaction_id, NULL);
				return -1;
			}
			// RFC 8445 7.3.1.5. Updating the Nominated Flag:
			// If the state of this pair is Succeeded, it means that the check previously sent by
			// this pair produced a successful response and generated a valid pair. The agent sets
			// the nominated flag value of the valid pair to true.
			if (pair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
				JLOG_DEBUG("Got a nominated pair (controlled)");
				pair->nominated = true;
			} else {
				pair->nomination_requested = true;
			}
		}
		if (agent_send_stun_binding(agent, entry, STUN_CLASS_RESP_SUCCESS, 0, msg->transaction_id,
		                            source)) {
			JLOG_ERROR("Failed to send STUN binding response");
			return -1;
		}
		break;
	}
	case STUN_CLASS_RESP_SUCCESS: {
		JLOG_DEBUG("Received STUN binding success response from %s",
		           entry->type == AGENT_STUN_ENTRY_TYPE_CHECK ? "client" : "server");
		entry->next_transmission = 0; // Cancel next retransmissions
		entry->retransmissions = 0;
		entry->finished = true;

		if (msg->mapped.len) {
			ice_candidate_type_t type = (entry->type == AGENT_STUN_ENTRY_TYPE_CHECK)
			                                ? ICE_CANDIDATE_TYPE_PEER_REFLEXIVE
			                                : ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
			if (agent_add_local_reflexive_candidate(agent, type, &msg->mapped)) {
				JLOG_WARN("Failed to add local peer reflexive candidate from "
				          "STUN mapped address");
			}
		}
		if (entry->type == AGENT_STUN_ENTRY_TYPE_CHECK) {
			ice_candidate_pair_t *pair = entry->pair;
			if (!pair->local)
				pair->local = ice_find_candidate_from_addr(&agent->local, &msg->mapped);
			if (pair->state != ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
				JLOG_DEBUG("Got a working pair");
				pair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
			}
			if (pair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
				// RFC 8445 7.3.1.5. Updating the Nominated Flag:
				// [...] once the check is sent and if it generates a successful response, and
				// generates a valid pair, the agent sets the nominated flag of the pair to true.
				if (pair->nomination_requested) {
					JLOG_DEBUG("Got a nominated pair");
					pair->nominated = true;
				} else if (agent->mode == AGENT_MODE_CONTROLLING) {
					JLOG_VERBOSE("Requesting pair nomination (controlling)");
					entry->next_transmission = current_timestamp();
					entry->retransmissions = MAX_STUN_RETRANSMISSION_COUNT;
					pair->nomination_requested = true;
				} else {
					JLOG_VERBOSE("Not requesting pair nomination (controlled)");
				}
			}
		} else { // entry->type == AGENT_STUN_ENTRY_TYPE_SERVER
			agent_update_gathering_done(agent);
		}
		break;
	}
	case STUN_CLASS_RESP_ERROR: {
		JLOG_WARN("Got STUN error binding response, code=%u", (unsigned int)msg->error_code);
		if (entry->type == AGENT_STUN_ENTRY_TYPE_CHECK && msg->error_code == 487) {
			// RFC 8445 7.2.5.1. Role Conflict:
			// If the Binding request generates a 487 (Role Conflict) error response, and if the ICE
			// agent included an ICE-CONTROLLED attribute in the request, the agent MUST switch to
			// the controlling role. If the agent included an ICE-CONTROLLING attribute in the
			// request, the agent MUST switch to the controlled role. Once the agent has switched
			// its role, the agent MUST [...] set the candidate pair state to Waiting [and] change
			// the tiebreaker value.
			if ((agent->mode == AGENT_MODE_CONTROLLING && msg->ice_controlling) ||
			    (agent->mode == AGENT_MODE_CONTROLLED && msg->ice_controlled)) {
				JLOG_WARN("ICE role conflit");
				JLOG_DEBUG("Switching roles to %s as requested",
				           msg->ice_controlling ? "controlled" : "controlling");
				agent->mode = msg->ice_controlling ? AGENT_MODE_CONTROLLED : AGENT_MODE_CONTROLLING;
				agent_update_candidate_pairs(agent);
			}
			entry->pair->state = ICE_CANDIDATE_PAIR_STATE_WAITING;
			entry->next_transmission = current_timestamp();
			++entry->retransmissions;
			juice_random(&agent->ice_tiebreaker, sizeof(agent->ice_tiebreaker));
		}
		break;
	}
	default: {
		JLOG_WARN("Got STUN unexpected binding message, class=%u", (unsigned int)msg->msg_class);
		return -1;
	}
	}
	return 0;
}

int agent_send_stun_binding(juice_agent_t *agent, agent_stun_entry_t *entry, stun_class_t msg_class,
                            unsigned int error_code, const uint8_t *transaction_id,
                            const addr_record_t *mapped) {
	--entry->retransmissions;
	entry->next_transmission = current_timestamp() + MIN_STUN_RETRANSMISSION_TIMEOUT;

	// Send STUN binding request
	JLOG_DEBUG("Sending STUN binding %s", msg_class == STUN_CLASS_REQUEST ? "request" : "response");

	if (!transaction_id)
		transaction_id = entry->transaction_id;

	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_class = msg_class;
	msg.msg_method = STUN_METHOD_BINDING;
	memcpy(msg.transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE);

	if (entry->type == AGENT_STUN_ENTRY_TYPE_CHECK) {
		// RFC 8445 7.2.2. Forming Credentials:
		// A connectivity-check Binding request MUST utilize the STUN short-term credential
		// mechanism. The username for the credential is formed by concatenating the username
		// fragment provided by the peer with the username fragment of the ICE agent sending the
		// request, separated by a colon (":"). The password is equal to the password provided by
		// the peer.
		switch (msg_class) {
		case STUN_CLASS_REQUEST: {
			// Local candidates are undifferentiated, always set the maximum priority
			uint32_t local_priority = 0;
			for (int i = 0; i < agent->local.candidates_count; ++i) {
				ice_candidate_t *candidate = agent->local.candidates + i;
				if (local_priority < candidate->priority)
					local_priority = candidate->priority;
			}
			snprintf(msg.username, STUN_MAX_USERNAME_LEN, "%s:%s", agent->remote.ice_ufrag,
			         agent->local.ice_ufrag);
			msg.password = agent->remote.ice_pwd;
			msg.priority = local_priority;
			msg.ice_controlling = agent->mode == AGENT_MODE_CONTROLLING ? agent->ice_tiebreaker : 0;
			msg.ice_controlled = agent->mode == AGENT_MODE_CONTROLLED ? agent->ice_tiebreaker : 0;

			// RFC 8445 8.1.1. Nominating Pairs:
			// Once the controlling agent has picked a valid pair for nomination, it repeats the
			// connectivity check that produced this valid pair [...], this time with the
			// USE-CANDIDATE attribute.
			msg.use_candidate =
			    agent->mode == AGENT_MODE_CONTROLLING && entry->pair->nomination_requested;
			break;
		}
		case STUN_CLASS_RESP_SUCCESS:
		case STUN_CLASS_RESP_ERROR: {
			snprintf(msg.username, STUN_MAX_USERNAME_LEN, "%s:%s", agent->local.ice_ufrag,
			         agent->remote.ice_ufrag);
			msg.password = agent->local.ice_pwd;
			msg.error_code = error_code;
			if (mapped)
				msg.mapped = *mapped;
			break;
		}
		case STUN_CLASS_INDICATION: {
			// RFC8445 11. Keepalives:
			// When STUN is being used for keepalives, a STUN Binding Indication is used. The
			// Indication MUST NOT utilize any authentication mechanism. It SHOULD contain the
			// FINGERPRINT attribute to aid in demultiplexing, but it SHOULD NOT contain any other
			// attributes.
		}
		}
	}
	char buffer[BUFFER_SIZE];
	int size = stun_write(buffer, BUFFER_SIZE, &msg);
	if (size <= 0) {
		JLOG_ERROR("STUN message write failed");
		return -1;
	}
	if (sendto(agent->sock, buffer, size, 0, (struct sockaddr *)&entry->record.addr,
	           entry->record.len) <= 0) {
		JLOG_ERROR("STUN message send failed");
		return -1;
	}
	return 0;
}

int agent_add_local_reflexive_candidate(juice_agent_t *agent, ice_candidate_type_t type,
                                        const addr_record_t *record) {
	if (type == ICE_CANDIDATE_TYPE_HOST) {
		JLOG_ERROR("Invalid type for reflexive candidate");
		return -1;
	}
	if (ice_find_candidate_from_addr(&agent->local, record)) {
		JLOG_VERBOSE("A local candidate exists for the mapped address");
		return 0;
	}
	ice_candidate_t candidate;
	if (ice_create_local_candidate(type, 1, record, &candidate)) {
		JLOG_ERROR("Failed to create reflexive candidate");
		return -1;
	}
	if (ice_add_candidate(&candidate, &agent->local)) {
		JLOG_ERROR("Failed to add candidate to local description");
		return -1;
	}
	char buffer[BUFFER_SIZE];
	if (ice_generate_candidate_sdp(&candidate, buffer, BUFFER_SIZE) < 0) {
		JLOG_ERROR("Failed to generate SDP for local candidate");
		return -1;
	}
	JLOG_DEBUG("Gathered reflexive candidate: %s", buffer);

	if (agent->config.cb_candidate)
		agent->config.cb_candidate(agent, buffer, agent->config.user_ptr);
	return 0;
}

int agent_add_remote_reflexive_candidate(juice_agent_t *agent, ice_candidate_type_t type,
                                         uint32_t priority, const addr_record_t *record) {
	if (type == ICE_CANDIDATE_TYPE_HOST) {
		JLOG_ERROR("Invalid type for reflexive candidate");
		return -1;
	}
	if (ice_find_candidate_from_addr(&agent->remote, record)) {
		JLOG_VERBOSE("A remote candidate exists for the remote address");
		return 0;
	}
	ice_candidate_t candidate;
	if (ice_create_local_candidate(type, 1, record, &candidate)) {
		JLOG_ERROR("Failed to create reflexive candidate");
		return -1;
	}
	if (ice_add_candidate(&candidate, &agent->remote)) {
		JLOG_ERROR("Failed to add candidate to remote description");
		return -1;
	}
	JLOG_DEBUG("Obtained a new remote reflexive candidate, priority=%lu", (unsigned long)priority);
	ice_candidate_t *remote = agent->remote.candidates + agent->remote.candidates_count - 1;
	remote->priority = priority;
	return agent_add_candidate_pair(agent, remote);
}

int agent_add_candidate_pair(juice_agent_t *agent, ice_candidate_t *remote) {
	// Here is the trick: local candidates are undifferentiated for sending. Therefore, we don't
	// need to match remote candidates with local ones.
	ice_candidate_pair_t pair;
	bool is_controlling = agent->mode == AGENT_MODE_CONTROLLING;
	if (ice_create_candidate_pair(NULL, remote, is_controlling, &pair)) {
		JLOG_ERROR("Failed to create candidate pair");
		return -1;
	}

	if (agent->candidate_pairs_count >= MAX_CANDIDATE_PAIRS_COUNT)
		return -1;

	JLOG_VERBOSE("Adding new candidate pair, priority=%" PRIu64, pair.priority);

	// Add pair
	ice_candidate_pair_t *pos = agent->candidate_pairs + agent->candidate_pairs_count;
	*pos = pair;
	++agent->candidate_pairs_count;

	agent_update_ordered_pairs(agent);

	// There is only one component, therefore we can unfreeze the pair and schedule it when possible
	pos->state = ICE_CANDIDATE_PAIR_STATE_WAITING;

	JLOG_VERBOSE("Registering STUN entry %d for candidate pair checking", agent->entries_count);
	agent_stun_entry_t *entry = agent->entries + agent->entries_count;
	entry->type = AGENT_STUN_ENTRY_TYPE_CHECK;
	entry->pair = pos;
	entry->record = pos->remote->resolved;
	entry->next_transmission = current_timestamp();
	entry->retransmissions = MAX_STUN_RETRANSMISSION_COUNT;
	juice_random(entry->transaction_id, STUN_TRANSACTION_ID_SIZE);

	// Find a STUN transmission time slot
	agent_stun_entry_t *other = agent->entries;
	while (other != agent->entries + agent->entries_count) {
		timestamp_t other_transmission = other->next_transmission;
		timediff_t timediff = entry->next_transmission - other_transmission;
		if (other_transmission && abs((int)timediff) < STUN_PACING_TIME) {
			entry->next_transmission = other_transmission + STUN_PACING_TIME;
			other = agent->entries;
		} else {
			++other;
		}
	}
	++agent->entries_count;
	return 0;
}

void agent_update_gathering_done(juice_agent_t *agent) {
	JLOG_VERBOSE("Updating gathering status");
	for (int i = 0; i < agent->entries_count; ++i) {
		if (agent->entries[i].type == AGENT_STUN_ENTRY_TYPE_SERVER && !agent->entries[i].finished) {
			JLOG_VERBOSE("STUN server entry %d is not finished", i);
			return;
		}
	}
	if (!agent->gathering_done) {
		JLOG_INFO("Candidate gathering done");
		agent->gathering_done = true;
		if (agent->config.cb_gathering_done)
			agent->config.cb_gathering_done(agent, agent->config.user_ptr);
	}
}

void agent_update_candidate_pairs(juice_agent_t *agent) {
	bool is_controlling = agent->mode == AGENT_MODE_CONTROLLING;
	for (int i = 0; i < agent->candidate_pairs_count; ++i)
		ice_update_candidate_pair(is_controlling, agent->candidate_pairs + i);
	agent_update_ordered_pairs(agent);
}

void agent_update_ordered_pairs(juice_agent_t *agent) {
	JLOG_VERBOSE("Updated ordered candidate pairs");
	for (int i = 0; i < agent->candidate_pairs_count; ++i) {
		ice_candidate_pair_t **begin = agent->ordered_pairs;
		ice_candidate_pair_t **end = begin + i;
		ice_candidate_pair_t **prev = end;
		uint32_t priority = agent->candidate_pairs[i].priority;
		while (--prev >= begin && (*prev)->priority < priority)
			*(prev + 1) = *prev;
		*(prev + 1) = agent->candidate_pairs + i;
	}
}

agent_stun_entry_t *agent_find_entry_from_record(juice_agent_t *agent,
                                                 const addr_record_t *record) {
	for (int i = 0; i < agent->entries_count; ++i) {
		if (record->len == agent->entries[i].record.len &&
		    memcmp(&record->addr, &agent->entries[i].record.addr, record->len) == 0) {
			JLOG_DEBUG("STUN entry %d matching incoming candidate", i);
			return agent->entries + i;
		}
	}
	return NULL;
}
