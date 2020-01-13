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
#include <stdlib.h>

#define BUFFER_SIZE 4096

typedef int64_t timestamp_t;
typedef timestamp_t timediff_t;

static timestamp_t current_timestamp() {
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts))
		return 0;
	return (timestamp_t)ts.tv_sec * 1000 + (timestamp_t)ts.tv_nsec / 1000000;
}

int agent_add_reflexive_candidate(juice_agent_t *agent,
                                  ice_candidate_type_t type,
                                  const struct sockaddr_record *record) {
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

int agent_add_candidate_pair(juice_agent_t *agent, ice_candidate_t *remote) {
	// Here is the trick: local candidates are undifferenciated for sending.
	// Therefore, we don't need to match remote candidates with local ones.
	ice_candidate_pair_t pair;
	if (ice_create_candidate_pair(NULL, remote, agent->config.is_controlling,
	                              &pair)) {
		JLOG_ERROR("Failed to create candidate pair");
		return -1;
	}

	if (agent->candidate_pairs_count >= MAX_CANDIDATE_PAIRS_COUNT)
		return -1;

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
	// immediately!
	pos->state = ICE_CANDIDATE_PAIR_STATE_WAITING;

	// TODO: force checks scheduling
	return 0;
}

int agent_process_stun_message(juice_agent_t *agent, const stun_message_t *msg,
                               bool is_server) {
	if (msg->mapped.len) {
		ice_candidate_type_t type = is_server
		                                ? ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE
		                                : ICE_CANDIDATE_TYPE_PEER_REFLEXIVE;
		if (agent_add_reflexive_candidate(agent, type, &msg->mapped) < 0) {
			JLOG_ERROR("Failed add reflexive candidate from STUN message");
			return -1;
		}
	}
	return 0;
}

int agent_bookkeeping(juice_agent_t *agent, timestamp_t *next_timestamp) {
	// TODO: send check/retransmission/keepalive and stuff
	*next_timestamp = current_timestamp() + 50;
	return 0;
}

void agent_run(juice_agent_t *agent) {
	const char *stun_hostname = "stun.l.google.com";
	const char *stun_service = "19302";

	struct sockaddr_record records[4];
	int records_count = addr_resolve(stun_hostname, stun_service, records, 4);
	if (records_count <= 0) {
		JLOG_ERROR("STUN address resolution failed");
		return;
	}

	// Send STUN binding request
	JLOG_DEBUG("Sending STUN binding request");

	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_class = STUN_CLASS_REQUEST;
	msg.msg_method = STUN_METHOD_BINDING;

	char buffer[BUFFER_SIZE];
	int size = stun_write(buffer, BUFFER_SIZE, &msg);
	if (size <= 0) {
		JLOG_ERROR("STUN message write failed");
		return;
	}

	for (int i = 0; i < records_count; ++i) {
		if (sendto(agent->sock, buffer, size, 0,
		           (struct sockaddr *)&records[i].addr, records[i].len) <= 0)
			JLOG_ERROR("STUN message send failed");
	}

	// Send STUN binding request
	JLOG_VERBOSE("STUN binding request sent to %zu addresses", records_count);

	timestamp_t next_timestamp = current_timestamp() + 10000;
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
			struct sockaddr_record record;
			record.len = sizeof(record.addr);
			int ret = recvfrom(agent->sock, buffer, BUFFER_SIZE, 0,
			                   (struct sockaddr *)&record.addr, &record.len);
			if (ret < 0) {
				JLOG_ERROR("recvfrom failed");
				return;
			}

			if (record.addr.ss_family == AF_INET6)
				addr_unmap_inet6_v4mapped((struct sockaddr *)&record.addr,
				                          &record.len);

			bool is_server = false;
			for (int i = 0; i < records_count; ++i) {
				if (record.len == records[i].len &&
				    memcmp(&record.addr, &records[i].addr, record.len) == 0) {
					is_server = true;
					break;
				}
			}

			if (stun_read(buffer, ret, &msg) <= 0) {
				JLOG_WARN("STUN message read failed");
				continue;
			}

			if (agent_process_stun_message(agent, &msg, is_server) < 0) {
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

	struct sockaddr_record records[ICE_MAX_CANDIDATES_COUNT - 1];
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
