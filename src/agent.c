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
#include "addr.h"
#include "ice.h"
#include "juice.h"
#include "log.h"
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

const char *state_to_string(juice_state_t state) {
	switch (state) {
	case JUICE_STATE_DISCONNECTED:
		return "disconnected";
	case JUICE_STATE_GATHERING:
		return "gathering";
	case JUICE_STATE_CONNECTING:
		return "connecting";
	case JUICE_STATE_CONNECTED:
		return "connected";
	case JUICE_STATE_COMPLETED:
		return "completed";
	case JUICE_STATE_FAILED:
		return "failed";
	default:
		return "unknown";
	}
}

void agent_destroy(juice_agent_t *agent) {
	JLOG_VERBOSE("Destroying agent");
	close(agent->sock);
	pthread_mutex_destroy(&agent->mutex);
	free(agent);
}

void agent_change_state(juice_agent_t *agent, juice_state_t state) {
	if (state != agent->state) {
		JLOG_INFO("Changing state to %s", state_to_string(state));
		agent->state = state;
	}
}

int agent_add_candidate_pair(juice_agent_t *agent, ice_candidate_t *remote) {
	// Here is the trick: local candidates are undifferentiated for sending.
	// Therefore, we don't need to match remote candidates with local ones.
	ice_candidate_pair_t pair;
	if (ice_create_candidate_pair(NULL, remote, agent->config.is_controlling,
	                              &pair)) {
		JLOG_ERROR("Failed to create candidate pair");
		return -1;
	}

	if (agent->candidate_pairs_count >= MAX_CANDIDATE_PAIRS_COUNT)
		return -1;

	JLOG_VERBOSE("Adding new candidate pair, priority=%" PRIu64, pair.priority);

	// Add pair
	ice_candidate_pair_t *pos =
	    agent->candidate_pairs + agent->candidate_pairs_count;
	*pos = pair;

	// Insert pair in ordered pairs
	ice_candidate_pair_t **begin = agent->ordered_pairs;
	ice_candidate_pair_t **end = begin + agent->candidate_pairs_count;
	ice_candidate_pair_t **prev = end;
	while (--prev >= begin && (*prev)->priority < pair.priority)
		*(prev + 1) = *prev;
	*(prev + 1) = pos;

	++agent->candidate_pairs_count;

	// There is only one component, therefore we can unfreeze the pair
	// and schedule it when possible !
	pos->state = ICE_CANDIDATE_PAIR_STATE_WAITING;

	JLOG_VERBOSE("Registering STUN entry %d for candidate pair checking",
	             agent->entries_count);
	agent_stun_entry_t *entry = agent->entries + agent->entries_count;
	entry->type = AGENT_STUN_ENTRY_TYPE_CHECK;
	entry->pair = pos;
	entry->record = pos->remote->resolved;
	entry->next_transmission = current_timestamp();
	entry->retransmissions = MAX_STUN_RETRANSMISSION_COUNT;

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

int agent_add_local_reflexive_candidate(juice_agent_t *agent,
                                        ice_candidate_type_t type,
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

int agent_add_remote_reflexive_candidate(juice_agent_t *agent,
                                         ice_candidate_type_t type,
                                         uint32_t priority,
                                         const addr_record_t *record) {
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
	JLOG_DEBUG("Obtained a new remote reflexive candidate, priority=%lu",
	           (unsigned long)priority);
	ice_candidate_t *remote =
	    agent->remote.candidates + agent->remote.candidates_count - 1;
	remote->priority = priority;
	return agent_add_candidate_pair(agent, remote);
}

int agent_send_stun_binding(juice_agent_t *agent, agent_stun_entry_t *entry,
                            stun_class_t class, addr_record_t *mapped) {
	--entry->retransmissions;
	entry->next_transmission =
	    current_timestamp() + MIN_STUN_RETRANSMISSION_TIMEOUT;

	// Send STUN binding request
	JLOG_DEBUG("Sending STUN binding %s",
	           class == STUN_CLASS_REQUEST ? "request" : "response");

	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_class = class;
	msg.msg_method = STUN_METHOD_BINDING;

	// Local candidates are undifferentiated, always set the maximum priority
	uint32_t local_priority = 0;
	for (int i = 0; i < agent->local.candidates_count; ++i) {
		ice_candidate_t *candidate = agent->local.candidates + i;
		if (local_priority < candidate->priority)
			local_priority = candidate->priority;
	}

	const size_t username_size = 256 * 2 + 2;
	char username[username_size];
	if (entry->type == AGENT_STUN_ENTRY_TYPE_CHECK) {
		// RFC 8445: A connectivity-check Binding request MUST utilize the STUN
		// short-term credential mechanism. The username for the credential is
		// formed by concatenating the username fragment provided by the peer
		// with the username fragment of the ICE agent sending the request,
		// separated by a colon (":"). The password is equal to the password
		// provided by the peer.
		snprintf(username, username_size, "%s:%s", agent->remote.ice_ufrag,
		         agent->local.ice_ufrag);

		msg.has_integrity = true;
		msg.has_fingerprint = true;
		msg.username = username;
		msg.password = agent->remote.ice_pwd;
		msg.priority = local_priority;
		msg.use_candidate = false; // TODO
		msg.ice_controlling = agent->config.is_controlling;
		msg.ice_controlled = !agent->config.is_controlling;
		if (mapped)
			msg.mapped = *mapped;
	}

	char buffer[BUFFER_SIZE];
	int size = stun_write(buffer, BUFFER_SIZE, &msg);
	if (size <= 0) {
		JLOG_ERROR("STUN message write failed");
		return -1;
	}

	if (sendto(agent->sock, buffer, size, 0,
	           (struct sockaddr *)&entry->record.addr,
	           entry->record.len) <= 0) {
		JLOG_ERROR("STUN message send failed");
		return -1;
	}

	return 0;
}

int agent_process_stun_binding(juice_agent_t *agent, const stun_message_t *msg,
                               agent_stun_entry_t *entry,
                               addr_record_t *source) {
	switch (msg->msg_class) {
	case STUN_CLASS_REQUEST: {
		JLOG_DEBUG("Got STUN binding request");
		if (agent_send_stun_binding(agent, entry, STUN_CLASS_RESP_SUCCESS,
		                            source)) {
			JLOG_ERROR("Failed to send STUN binding response");
			return -1;
		}
		break;
	}
	case STUN_CLASS_RESP_SUCCESS: {
		JLOG_DEBUG("Got STUN binding success response");
		if (msg->mapped.len) {
			ice_candidate_type_t type =
			    (entry->type == AGENT_STUN_ENTRY_TYPE_SERVER)
			        ? ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE
			        : ICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
			if (agent_add_local_reflexive_candidate(agent, type,
			                                        &msg->mapped)) {
				JLOG_WARN("Failed to add local peer reflexive candidate from "
				          "STUN mapped address");
			}
		}
		if (entry->pair) {
			ice_candidate_pair_t *pair = entry->pair;
			if (!pair->local)
				pair->local =
				    ice_find_candidate_from_addr(&agent->local, source);
			if (entry->type == AGENT_STUN_ENTRY_TYPE_CHECK) {
				if (pair->state == ICE_CANDIDATE_PAIR_STATE_INPROGRESS) {
					JLOG_DEBUG("Got a working pair");
					pair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
				}
			}
		} else {
			if (entry->type == AGENT_STUN_ENTRY_TYPE_SERVER)
				JLOG_VERBOSE("Server entry has no pair");
			else
				JLOG_WARN("Candidate pair check entry has no pair");
		}
		// Cancel next retransmissions
		entry->next_transmission = 0;
		entry->retransmissions = 0;
		break;
	}
	case STUN_CLASS_RESP_ERROR: {
		JLOG_WARN("Got STUN error binding response, code=%u",
		          (unsigned int)msg->error_code);
		// TODO: handle it
		break;
	}
	default: {
		JLOG_WARN("Got STUN unexpected binding message, class=%u",
		          (unsigned int)msg->msg_class);
		return -1;
	}
	}
	return 0;
}


int agent_bookkeeping(juice_agent_t *agent, timestamp_t *next_timestamp) {
	timestamp_t now = current_timestamp();
	*next_timestamp = now + 1000;

	if (agent->state == JUICE_STATE_DISCONNECTED)
		return 0;

	for (int i = 0; i < agent->entries_count; ++i) {
		agent_stun_entry_t *entry = agent->entries + i;

		if (entry->pair &&
		    (entry->pair->state == ICE_CANDIDATE_PAIR_STATE_FROZEN ||
		     entry->pair->state == ICE_CANDIDATE_PAIR_STATE_FAILED ||
		     entry->pair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED))
			continue;

		if (entry->next_transmission && entry->next_transmission <= now) {
			JLOG_VERBOSE("STUN entry %d: Transmission time reached", i);

			if (entry->retransmissions > 0) {
				if (entry->pair)
					entry->pair->state = ICE_CANDIDATE_PAIR_STATE_INPROGRESS;

				JLOG_DEBUG("STUN entry %d: Sending request", i);
				agent_send_stun_binding(agent, entry, STUN_CLASS_REQUEST, NULL);
			} else {
				JLOG_DEBUG("STUN entry %d: Failed", i);
				entry->next_transmission = 0;
				if (entry->pair)
					entry->pair->state = ICE_CANDIDATE_PAIR_STATE_FAILED;
			}
		}

		if (entry->next_transmission &&
		    *next_timestamp > entry->next_transmission)
			*next_timestamp = entry->next_transmission;
	}

	if (agent->candidate_pairs_count == 0)
		return 0;

	ice_candidate_pair_t *pending = NULL;
	ice_candidate_pair_t *selected = NULL;
	for (int i = 0; i < agent->candidate_pairs_count; ++i) {
		ice_candidate_pair_t *pair = *(agent->ordered_pairs + i);
		if (selected) {
			// A higher-priority pair succeeded, we can stop checking this one
			if (pair->state == ICE_CANDIDATE_PAIR_STATE_WAITING ||
			    pair->state == ICE_CANDIDATE_PAIR_STATE_INPROGRESS) {
				JLOG_DEBUG("Cancelling checks for lower-priority pair");
				pair->state = ICE_CANDIDATE_PAIR_STATE_FROZEN;
			}
		} else {
			if (pair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED)
				selected = pair;
			else if (pair->state == ICE_CANDIDATE_PAIR_STATE_WAITING ||
			         pair->state == ICE_CANDIDATE_PAIR_STATE_INPROGRESS) {
				pending = pair;
			}
		}
	}

	if (selected) {
		if (pending)
			agent_change_state(agent, JUICE_STATE_CONNECTED);
		else
			agent_change_state(agent, JUICE_STATE_COMPLETED);
	} else {
		if (!pending)
			agent_change_state(agent, JUICE_STATE_FAILED);
	}
	return 0;
}

void agent_run(juice_agent_t *agent) {
	pthread_mutex_lock(&agent->mutex);

	// TODO
	const char *stun_hostname = "stun.l.google.com";
	const char *stun_service = "19302";

	agent_change_state(agent, JUICE_STATE_CONNECTING);

	addr_record_t records[MAX_STUN_SERVER_RECORDS_COUNT];
	int records_count = addr_resolve(stun_hostname, stun_service, records,
	                                 MAX_STUN_SERVER_RECORDS_COUNT);
	if (records_count <= 0) {
		JLOG_ERROR("STUN address resolution failed");
		return;
	}

	JLOG_VERBOSE("Sending STUN binding request to %zu server addresses",
	             records_count);

	for (int i = 0; i < records_count; ++i) {
		if (agent->entries_count >= MAX_STUN_ENTRIES_COUNT)
			break;
		JLOG_VERBOSE("Registering STUN entry %d for server request",
		             agent->entries_count);
		agent_stun_entry_t *entry = agent->entries + agent->entries_count;
		entry->type = AGENT_STUN_ENTRY_TYPE_SERVER;
		entry->pair = NULL;
		entry->record = records[i];
		entry->next_transmission =
		    current_timestamp() + STUN_PACING_TIME * agent->entries_count;
		entry->retransmissions = MAX_STUN_RETRANSMISSION_COUNT;
		++agent->entries_count;
	}

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
			int ret = recvfrom(agent->sock, buffer, BUFFER_SIZE, 0,
			                   (struct sockaddr *)&record.addr, &record.len);
			if (ret < 0) {
				JLOG_ERROR("recvfrom failed, errno=%d", errno);
				break;
			}

			if (record.addr.ss_family == AF_INET6)
				addr_unmap_inet6_v4mapped((struct sockaddr *)&record.addr,
				                          &record.len);

			// See agent_send_stun_binding(() for username format
			const size_t username_size = 256 * 2 + 2;
			char username[username_size];
			snprintf(username, username_size, "%s:%s", agent->local.ice_ufrag,
			         agent->remote.ice_ufrag);

			stun_message_t msg;
			msg.username = username;
			msg.password = agent->local.ice_pwd;
			if (stun_read(buffer, ret, &msg) <= 0) {
				JLOG_WARN("STUN message read failed");
				continue;
			}
			if (msg.msg_method != STUN_METHOD_BINDING) {
				JLOG_WARN("Unknown STUN method %X", msg.msg_method);
				continue;
			}

			if (msg.has_integrity) { // this is a check from the remote peer
				if (agent_add_remote_reflexive_candidate(
				        agent, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE, msg.priority,
				        &record)) {
					JLOG_WARN(
					    "Failed to add remote peer reflexive candidate from "
					    "STUN message");
				}
			}

			agent_stun_entry_t *entry = NULL;
			for (int i = 0; i < agent->entries_count; ++i) {
				if (record.len == agent->entries[i].record.len &&
				    memcmp(&record.addr, &agent->entries[i].record.addr,
				           record.len) == 0) {
					entry = &agent->entries[i];
					JLOG_DEBUG("STUN entry %d: Processing incoming message", i);
					break;
				}
			}
			if (!entry) {
				JLOG_ERROR("STUN entry for message processing not found");
				continue;
			}
			if (agent_process_stun_binding(agent, &msg, entry, &record) < 0) {
				JLOG_ERROR("STUN message processing failed");
				continue;
			}
		}
	}

	JLOG_DEBUG("Leaving agent thread");
	agent_change_state(agent, JUICE_STATE_DISCONNECTED);
	agent_destroy(agent);
}

void *agent_thread_entry(void *arg) {
	agent_run((juice_agent_t *)arg);
	return NULL;
}

juice_agent_t *juice_agent_create(const juice_config_t *config) {
	JLOG_VERBOSE("Creating agent");
	juice_agent_t *agent = malloc(sizeof(juice_agent_t));
	if (!agent) {
		JLOG_FATAL("malloc for agent failed");
		return NULL;
	}
	memset(agent, 0, sizeof(*agent));
	agent->config = *config;
	agent->state = JUICE_STATE_DISCONNECTED;
	agent->sock = INVALID_SOCKET;
	agent->thread_started = false;
	agent->thread_destroyed = false;
	pthread_mutex_init(&agent->mutex, NULL);
	ice_create_local_description(&agent->local);
	return agent;
}

void juice_agent_destroy(juice_agent_t *agent) {
	if (!agent->thread_started) {
		agent_destroy(agent);
	} else {
		JLOG_VERBOSE("Requesting agent destruction");
		agent->thread_destroyed = true;
	}
}

int juice_agent_gather_candidates(juice_agent_t *agent) {
	if (agent->sock != INVALID_SOCKET) {
		JLOG_ERROR("Started candidates gathering twice");
		return -1;
	}
	// No need to lock the mutex, the thread is not started yet
	agent->sock = udp_create_socket();
	if (agent->sock == INVALID_SOCKET) {
		JLOG_FATAL("UDP socket creation for agent failed");
		return -1;
	}
	agent_change_state(agent, JUICE_STATE_GATHERING);

	addr_record_t records[ICE_MAX_CANDIDATES_COUNT - 1];
	int records_count =
	    udp_get_addrs(agent->sock, records, ICE_MAX_CANDIDATES_COUNT - 1);
	if (records_count < 0) {
		JLOG_ERROR("Failed to gather local host candidates");
		records_count = 0;
	} else if (records_count == 0) {
		JLOG_WARN("No local host candidates gathered");
	}

	JLOG_VERBOSE("Adding %d local host candidates", records_count);

	for (int i = 0; i < records_count; ++i) {
		ice_candidate_t candidate;
		if (ice_create_local_candidate(ICE_CANDIDATE_TYPE_HOST, 1, records + i,
		                               &candidate)) {
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

	int ret = pthread_create(&agent->thread, NULL, agent_thread_entry, agent);
	if (ret) {
		JLOG_FATAL("pthread_create for agent failed, error=%d", ret);
		return -1;
	}
	pthread_detach(agent->thread);
	agent->thread_started = true;
	return 0;
}

int juice_agent_get_local_description(juice_agent_t *agent, char *buffer,
                                      size_t size) {
	pthread_mutex_lock(&agent->mutex);
	int ret = ice_generate_sdp(&agent->local, buffer, size);
	pthread_mutex_unlock(&agent->mutex);
	return ret;
}

int juice_agent_set_remote_description(juice_agent_t *agent, const char *sdp) {
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
	pthread_mutex_unlock(&agent->mutex);
	return 0;
}

int juice_agent_add_remote_candidate(juice_agent_t *agent, const char *sdp) {
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
	ice_candidate_t *remote =
	    agent->remote.candidates + agent->remote.candidates_count - 1;
	int ret = agent_add_candidate_pair(agent, remote);
	pthread_mutex_unlock(&agent->mutex);
	return ret;
}

int juice_agent_send(juice_agent_t *agent, const char *data, size_t size) {
	pthread_mutex_lock(&agent->mutex);
	if (agent->state == JUICE_STATE_CONNECTED ||
	    agent->state == JUICE_STATE_COMPLETED) {
		// TODO: send on selected pair
		pthread_mutex_unlock(&agent->mutex);
		return 0;
	}
	pthread_mutex_unlock(&agent->mutex);
	return -1;
}
