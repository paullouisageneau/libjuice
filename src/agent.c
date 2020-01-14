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

	JLOG_VERBOSE("Adding a new candidate pair, priority=" PRIu64,
	             pair.priority);

	// Insert pair in order
	ice_candidate_pair_t *begin = agent->candidate_pairs;
	ice_candidate_pair_t *end = begin + agent->remote.candidates_count;
	ice_candidate_pair_t *prev = end;
	while (--prev >= begin && prev->priority < pair.priority)
		*(prev + 1) = *prev;
	ice_candidate_pair_t *pos = prev + 1;
	*pos = pair;
	++agent->candidate_pairs_count;

	// There is only one component, therefore we can unfreeze the pair
	// and schedule it when possible !
	pos->state = ICE_CANDIDATE_PAIR_STATE_WAITING;

	JLOG_VERBOSE("Adding a new entry for candidate pair checking");

	agent_stun_entry_t *entry = agent->entries + agent->entries_count;
	entry->type = AGENT_STUN_ENTRY_TYPE_CHECK;
	entry->pair = pos;
	entry->record = pos->remote->resolved;
	entry->next_transmission =
	    entry != agent->entries && (entry - 1)->next_transmission
	        ? (entry - 1)->next_transmission + STUN_PACING_TIME
	        : current_timestamp();
	entry->retransmissions = MAX_STUN_RETRANSMISSION_COUNT;
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
		JLOG_DEBUG("A local candidate already exists for the mapped address, "
		           "ignoring");
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
                                         const addr_record_t *record) {
	if (type == ICE_CANDIDATE_TYPE_HOST) {
		JLOG_ERROR("Invalid type for reflexive candidate");
		return -1;
	}
	if (ice_find_candidate_from_addr(&agent->remote, record)) {
		JLOG_DEBUG("A local candidate already exists for the mapped address, "
		           "ignoring");
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
	JLOG_DEBUG("Obtained a new remote reflexive candidate");
	ice_candidate_t *remote =
	    agent->remote.candidates + agent->remote.candidates_count - 1;
	return agent_add_candidate_pair(agent, remote);
}

int agent_send_stun_binding(juice_agent_t *agent, agent_stun_entry_t *entry,
                            stun_class_t class, addr_record_t *mapped) {
	--entry->retransmissions;
	entry->next_transmission =
	    current_timestamp() + MIN_STUN_RETRANSMISSION_TIMEOUT;

	// Send STUN binding request
	JLOG_DEBUG("Sending STUN binding request");

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
			if (agent_add_local_reflexive_candidate(agent, type, &msg->mapped) <
			    0) {
				JLOG_ERROR(
				    "Failed to add reflexive candidate from STUN message");
				return -1;
			}
		}
		if (entry->type == AGENT_STUN_ENTRY_TYPE_CHECK && entry->pair &&
		    entry->pair->state == ICE_CANDIDATE_PAIR_STATE_INPROGRESS) {
			JLOG_DEBUG("Got a working pair");
			entry->pair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
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
	*next_timestamp = now + 10000;

	for (int i = 0; i < agent->entries_count; ++i) {
		agent_stun_entry_t *entry = agent->entries + i;

		if (entry->pair &&
		    (entry->pair->state == ICE_CANDIDATE_PAIR_STATE_FROZEN ||
		     entry->pair->state == ICE_CANDIDATE_PAIR_STATE_FAILED ||
		     entry->pair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED))
			continue;

		if (!entry->next_transmission || entry->next_transmission > now)
			continue;

		if (entry->retransmissions > 0) {
			if (entry->pair)
				entry->pair->state = ICE_CANDIDATE_PAIR_STATE_INPROGRESS;

			agent_send_stun_binding(agent, entry, STUN_CLASS_REQUEST, NULL);

			if (entry->next_transmission &&
			    *next_timestamp > entry->next_transmission)
				*next_timestamp = entry->next_transmission;
		} else {
			// Failed
			entry->next_transmission = 0;
			if (entry->pair)
				entry->pair->state = ICE_CANDIDATE_PAIR_STATE_FAILED;
	    }
	}
	return 0;
}

void agent_run(juice_agent_t *agent) {
	memset(agent->entries, 0,
	       MAX_STUN_ENTRIES_COUNT * sizeof(agent_stun_entry_t));

	const char *stun_hostname = "stun.l.google.com";
	const char *stun_service = "19302";

	addr_record_t records[MAX_STUN_SERVER_RECORDS_COUNT];
	int records_count = addr_resolve(stun_hostname, stun_service, records,
	                                 MAX_STUN_SERVER_RECORDS_COUNT);
	if (records_count <= 0) {
		JLOG_ERROR("STUN address resolution failed");
		return;
	}

	JLOG_VERBOSE("Send STUN binding request to %zu server addresses",
	             records_count);

	const timestamp_t now = current_timestamp();
	for (int i = 0; i < records_count; ++i) {
		if (agent->entries_count >= MAX_STUN_ENTRIES_COUNT)
			break;
		agent_stun_entry_t *entry = agent->entries + agent->entries_count;
		entry->type = AGENT_STUN_ENTRY_TYPE_SERVER;
		entry->pair = NULL;
		entry->record = records[i];
		entry->next_transmission = now;
		entry->retransmissions = MAX_STUN_RETRANSMISSION_COUNT;
		++agent->entries_count;
	}

	timestamp_t next_timestamp;
	while (agent_bookkeeping(agent, &next_timestamp) == 0) {
		timediff_t timediff = next_timestamp - current_timestamp();
		if (timediff < 0)
			timediff = 0;
		struct timeval timeout;
		timeout.tv_sec = timediff / 1000;
		timeout.tv_usec = timediff * 1000;

		fd_set set;
		FD_ZERO(&set);
		FD_SET(agent->sock, &set);

		int n = SOCKET_TO_INT(agent->sock) + 1;
		int ret = select(n, &set, NULL, NULL, &timeout);
		if (ret < 0) {
			JLOG_ERROR("select failed, errno=%d", errno);
			return;
		}

		if (FD_ISSET(agent->sock, &set)) {
			char buffer[BUFFER_SIZE];
			addr_record_t record;
			record.len = sizeof(record.addr);
			int ret = recvfrom(agent->sock, buffer, BUFFER_SIZE, 0,
			                   (struct sockaddr *)&record.addr, &record.len);
			if (ret < 0) {
				JLOG_ERROR("recvfrom failed, errno=%d", errno);
				return;
			}

			if (record.addr.ss_family == AF_INET6)
				addr_unmap_inet6_v4mapped((struct sockaddr *)&record.addr,
				                          &record.len);

			agent_stun_entry_t *entry = NULL;
			for (int i = 0; i < agent->entries_count; ++i) {
				if (record.len == agent->entries[i].record.len &&
				    memcmp(&record.addr, &agent->entries[i].record.addr,
				           record.len) == 0) {
					entry = &agent->entries[i];
					break;
				}
			}

			stun_message_t msg;
			if (stun_read(buffer, ret, &msg) <= 0) {
				JLOG_WARN("STUN message read failed");
				continue;
			}

			if (msg.msg_method != STUN_METHOD_BINDING) {
				JLOG_WARN("Unknown STUN method %X", msg.msg_method);
				continue;
			}

			if (agent_process_stun_binding(agent, &msg, entry, &record) < 0) {
				JLOG_ERROR("STUN message processing failed");
				continue;
			}
		}
	}

	JLOG_DEBUG("Agent thread finished");
}

void *agent_thread_entry(void *arg) {
	agent_run((juice_agent_t *)arg);
	return NULL;
}

juice_agent_t *juice_agent_create(const juice_config_t *config) {
	juice_agent_t *agent = malloc(sizeof(juice_agent_t));
	if (!agent) {
		JLOG_FATAL("malloc for agent failed");
		return NULL;
	}

	memset(agent, 0, sizeof(*agent));
	agent->config = *config;
	ice_create_local_description(&agent->local);

	agent->sock = udp_create_socket();
	if (agent->sock == INVALID_SOCKET) {
		JLOG_FATAL("UDP socket creation for agent failed");
		goto error;
	}

	JLOG_VERBOSE("Agent created");
	return agent;

error:
	if (agent->sock != INVALID_SOCKET)
		close(agent->sock);
	free(agent);
	return NULL;
}

void juice_agent_destroy(juice_agent_t *agent) { free(agent); }

int juice_agent_gather_candidates(juice_agent_t *agent) {
	JLOG_DEBUG("Gathering candidates");

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
	return 0;
}

int juice_agent_get_local_description(juice_agent_t *agent, char *buffer,
                                      size_t size) {
	return ice_generate_sdp(&agent->local, buffer, size);
}

int juice_agent_set_remote_description(juice_agent_t *agent, const char *sdp) {
	if (ice_parse_sdp(sdp, &agent->remote) < 0) {
		JLOG_ERROR("Failed to parse remote SDP description");
		return -1;
	}
	for (size_t i = 0; i < agent->remote.candidates_count; ++i)
		if (agent_add_candidate_pair(agent, agent->remote.candidates + i))
			return -1;
	return 0;
}

int juice_agent_add_remote_candidate(juice_agent_t *agent, const char *sdp) {
	ice_candidate_t candidate;
	if (ice_parse_candidate_sdp(sdp, &candidate) < 0) {
		JLOG_ERROR("Failed to parse remote SDP candidate");
		return -1;
	}
	if (ice_add_candidate(&candidate, &agent->remote)) {
		JLOG_ERROR("Failed to add candidate to remote description");
		return -1;
	}
	ice_candidate_t *remote =
	    agent->remote.candidates + agent->remote.candidates_count - 1;
	return agent_add_candidate_pair(agent, remote);
}

int juice_agent_send(juice_agent_t *agent, const char *data, size_t size) {
	return -1;
}
