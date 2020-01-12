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
#include "stun.h"
#include "udp.h"

#include <assert.h>
#include <stdlib.h>

#define BUFFER_SIZE 1024

int resolve_addr(const char *hostname, const char *service,
                 struct sockaddr_record *records, size_t count) {
	struct sockaddr_record *end = records + count;

	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG;
	struct addrinfo *ai_list = NULL;
	if (getaddrinfo(hostname, service, &hints, &ai_list))
		return -1;

	int ret = 0;
	for (struct addrinfo *ai = ai_list; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
			++ret;
			if (records != end) {
				memcpy(&records->addr, ai->ai_addr, ai->ai_addrlen);
				records->len = ai->ai_addrlen;
				++records;
			}
		}
	}

	freeaddrinfo(ai_list);
	return ret;
}

void agent_run(juice_agent_t *agent) {
	const char *stun_hostname = "stun.l.google.com";
	const char *stun_service = "19302";

	struct sockaddr_record records[4];
	int records_count = resolve_addr(stun_hostname, stun_service, records, 4);
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

	struct timeval timeout;
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	while (true) {
		fd_set set;
		FD_ZERO(&set);
		FD_SET(agent->sock, &set);

		int n = SOCKET_TO_INT(agent->sock) + 1;
		int ret = select(n, &set, NULL, NULL, &timeout);
		if (ret < 0) {
			JLOG_ERROR("select failed");
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

			if (stun_read(buffer, ret, &msg) <= 0) {
				JLOG_ERROR("STUN message read failed");
				return;
			}

			ice_candidate_t candidate;
			if (ice_create_local_candidate(ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
			                               1, &msg.mapped, &candidate)) {
				JLOG_WARN("Failed to create server reflexive candidate");
				return;
			}

			if (ice_add_candidate(&candidate, &agent->local)) {
				JLOG_WARN("Failed to add candidate to local description");
				return;
			}

			if (ice_generate_candidate_sdp(&candidate, buffer, BUFFER_SIZE) <
			    0) {
				JLOG_WARN("Failed to generate SDP for local candidate");
				return;
			}
			JLOG_DEBUG("Gathered server reflexive candidate: %s", buffer);

			// TODO: Trigger callback
		}
	}

	return;
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
	ice_create_local_description(&agent->local);

	agent->sock = juice_udp_create();
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
	    juice_udp_get_addrs(agent->sock, records, ICE_MAX_CANDIDATES_COUNT - 1);
	if (records_count < 0) {
		JLOG_WARN("Failed to gather local host candidates");
		records_count = 0;
	}

	JLOG_VERBOSE("Adding %d local host candidates", records_count);

	for (int i = 0; i < records_count; ++i) {
		ice_candidate_t candidate;
		if (ice_create_local_candidate(ICE_CANDIDATE_TYPE_HOST, 1, records + i,
		                               &candidate)) {
			JLOG_WARN("Failed to create host candidate");
			continue;
		}
		if (ice_add_candidate(&candidate, &agent->local)) {
			JLOG_WARN("Failed to add candidate to local description");
			continue;
		}
	}

	char buffer[BUFFER_SIZE];
	for (int i = 0; i < agent->local.candidates_count; ++i) {
		ice_candidate_t *candidate = agent->local.candidates + i;
		if (ice_generate_candidate_sdp(candidate, buffer, BUFFER_SIZE) < 0) {
			JLOG_WARN("Failed to generate SDP for local candidate");
			continue;
		}
		JLOG_DEBUG("Gathered host candidate: %s", buffer);

		// TODO: Trigger callback
	}

	int ret = pthread_create(&agent->thread, NULL, agent_thread_entry, agent);
	if (ret) {
		JLOG_FATAL("pthread_create for agent failed, error=%d", ret);
		return -1;
	}
	return 0;
}

const char *juice_agent_get_local_description(juice_agent_t *agent) {
	return NULL;
}

int juice_agent_set_remote_description(juice_agent_t *agent, const char *sdp) {
	return -1;
}

int juice_agent_add_remote_candidate(juice_agent_t *agent, const char *sdp) {
	return -1;
}

int juice_agent_send(juice_agent_t *agent, const char *data, size_t size) {
	return -1;
}
