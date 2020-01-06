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
#include "juice.h"
#include "log.h"
#include "stun.h"
#include "udp.h"

#include <assert.h>
#include <stdlib.h>

int resolve_addr(const char *hostname, const char *service,
                 struct sockaddr_record *records, size_t *count) {
	struct sockaddr_record *end = records + *count;
	*count = 0;

	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET; // TODO
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG;
	struct addrinfo *aiList = NULL;
	if (getaddrinfo(hostname, service, &hints, &aiList))
		return -1;

	int ret = 0;
	for (struct addrinfo *ai = aiList; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
			++ret;
			if (records != end) {
				memcpy(&records->addr, ai->ai_addr, ai->ai_addrlen);
				records->len = ai->ai_addrlen;
				++records;
				++*count;
			}
		}
	}

	freeaddrinfo(aiList);
	return ret;
}

void agent_run(juice_agent_t *agent) {
	const char *stun_hostname = "stun.l.google.com";
	const char *stun_service = "19302";

	struct sockaddr_record records[4];
	size_t count = 4;
	if (resolve_addr(stun_hostname, stun_service, records, &count) <= 0) {
		JLOG_ERROR("STUN address resolution failed");
		return;
	}

	// Send STUN binding request
	JLOG_DEBUG("Sending STUN binding request");

	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_class = STUN_CLASS_REQUEST;
	msg.msg_method = STUN_METHOD_BINDING;

	char buffer[1280];
	int size = stun_write(buffer, 1280, &msg);
	if (size <= 0) {
		JLOG_ERROR("STUN message write failed");
		return;
	}

	if (sendto(agent->sock, buffer, size, 0,
	           (struct sockaddr *)&records[0].addr, records[0].len) <= 0)
		JLOG_ERROR("STUN message send failed");

	fd_set set;
	FD_ZERO(&set);
	FD_SET(agent->sock, &set);

	struct timeval timeout;
	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	int n = SOCKET_TO_INT(agent->sock) + 1;
	int ret = select(n, &set, NULL, NULL, &timeout);
	if (ret < 0) {
		JLOG_ERROR("select failed");
		return;
	}

	if (FD_ISSET(agent->sock, &set)) {
		struct sockaddr_storage addr;
		socklen_t addrlen = sizeof(addr);
		int ret = recvfrom(agent->sock, buffer, 1280, 0,
		                   (struct sockaddr *)&addr, &addrlen);
		if (ret < 0) {
			JLOG_ERROR("recvfrom failed");
			return;
		}

		if (stun_read(buffer, ret, &msg) < 0) {
			JLOG_ERROR("STUN message read failed");
			return;
		}

		char host[256];
		char service[16];
		if (getnameinfo((struct sockaddr *)&msg.mapped_addr, msg.mapped_addrlen,
		                host, 256, service, 16,
		                NI_NUMERICHOST | NI_NUMERICSERV | NI_DGRAM)) {
			JLOG_ERROR("getnameinfo failed");
			return;
		}

		JLOG_INFO("Mapped address: %s:%s\n", host, service);
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

	memset(agent, 0, sizeof(juice_agent_t));

	agent->sock = juice_udp_create();
	if (agent->sock == INVALID_SOCKET) {
		JLOG_FATAL("UDP socket creation for agent failed");
		goto error;
	}

	int ret = pthread_create(&agent->thread, NULL, agent_thread_entry, agent);
	if (ret) {
		JLOG_FATAL("pthread_create for agent failed, error=%d", ret);
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

int juice_agent_gather_candidates(juice_agent_t *agent) { return -1; }

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
