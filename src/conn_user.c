/**
 * Copyright (c) 2023 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "conn_user.h"
#include "agent.h"
#include "log.h"
#include "socket.h"
#include "udp.h"

#include <stdint.h>

typedef enum conn_state { CONN_STATE_NEW = 0, CONN_STATE_READY, CONN_STATE_FINISHED } conn_state_t;

typedef struct conn_impl {
	conn_state_t state;
	socket_t sock;
	mutex_t mutex;
	mutex_t send_mutex;
	int send_ds;
	timestamp_t next_timestamp;
} conn_impl_t;

static inline int conn_user_recv(socket_t sock, char *buffer, size_t size, addr_record_t *src);

JUICE_EXPORT int juice_user_poll(juice_agent_t *agent, char *buffer, size_t size) {
	if (!agent || !buffer)
		return JUICE_ERR_INVALID;
	
	conn_impl_t *conn_impl = agent->conn_impl;

	if (!conn_impl)
		return JUICE_ERR_INVALID;

	mutex_lock(&conn_impl->mutex);

	if (conn_impl->state == CONN_STATE_FINISHED) {
		mutex_unlock(&conn_impl->mutex);
		return JUICE_ERR_FAILED;
	}

	if (agent->config.concurrency_mode != JUICE_CONCURRENCY_MODE_USER) {
		JLOG_ERROR("agent->config.concurrency_mode=%d Only JUICE_CONCURRENCY_MODE_USER (%d) is supported", 
		            agent->config.concurrency_mode, JUICE_CONCURRENCY_MODE_USER);
		mutex_unlock(&conn_impl->mutex);
		return JUICE_ERR_INVALID;
	}

	addr_record_t src;
	int ret = conn_user_recv(conn_impl->sock, buffer, size, &src);

	if (ret < 0) {
		agent_conn_fail(agent);
		conn_impl->state = CONN_STATE_FINISHED;
		mutex_unlock(&conn_impl->mutex);
		return JUICE_ERR_FAILED;
	} else if (ret > 0) {
		if (agent_conn_recv(agent, buffer, (size_t)ret, &src) != 0) {
			JLOG_WARN("Agent receive failed");
			conn_impl->state = CONN_STATE_FINISHED;
			mutex_unlock(&conn_impl->mutex);
			return JUICE_ERR_FAILED;
		}
	}

	if (   ret > 0 // We just received a datagram
	    || conn_impl->next_timestamp <= current_timestamp()
	    || agent->state != JUICE_STATE_COMPLETED) {
		if (agent_conn_update(agent, &conn_impl->next_timestamp) != 0) {
			JLOG_WARN("Agent update failed");
			conn_impl->state = CONN_STATE_FINISHED;
			mutex_unlock(&conn_impl->mutex);
			return JUICE_ERR_FAILED;
		}
	}

	mutex_unlock(&conn_impl->mutex);
	return ret;
}

static inline int conn_user_recv(socket_t sock, char *buffer, size_t size, addr_record_t *src) {
	JLOG_VERBOSE("Receiving datagram");
	int len;
	while ((len = udp_recvfrom(sock, buffer, size, src)) == 0) {
		// Empty datagram, ignore
	}

	if (len < 0) {
		if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK) {
			JLOG_VERBOSE("No more datagrams to receive");
			return 0;
		}
		JLOG_ERROR("recvfrom failed, errno=%d", sockerrno);
		return -1;
	}

	addr_unmap_inet6_v4mapped((struct sockaddr *)&src->addr, &src->len);
	return len; // len > 0
}

int conn_user_init(juice_agent_t *agent, conn_registry_t *registry, udp_socket_config_t *config) {
	(void)registry;

	conn_impl_t *conn_impl = calloc(1, sizeof(conn_impl_t));
	if (!conn_impl) {
		JLOG_FATAL("Memory allocation failed for connection impl");
		return -1;
	}

	conn_impl->sock = udp_create_socket(config);
	if (conn_impl->sock == INVALID_SOCKET) {
		JLOG_ERROR("UDP socket creation failed");
		free(conn_impl);
		return -1;
	}

	mutex_init(&conn_impl->mutex, 0);
	mutex_init(&conn_impl->send_mutex, 0);

	agent->conn_impl = conn_impl;

	return JUICE_ERR_SUCCESS;
}

void conn_user_cleanup(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;

	closesocket(conn_impl->sock);
	mutex_destroy(&conn_impl->mutex);
	mutex_destroy(&conn_impl->send_mutex);
	free(agent->conn_impl);
	agent->conn_impl = NULL;
}

void conn_user_lock(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	mutex_lock(&conn_impl->mutex);
}

void conn_user_unlock(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	mutex_unlock(&conn_impl->mutex);
}

int conn_user_interrupt(juice_agent_t *agent) {
	// juice_user_poll does not block when polling, so there's nothing to interrupt
	return JUICE_ERR_SUCCESS;
}

int conn_user_send(juice_agent_t *agent, const addr_record_t *dst, const char *data, size_t size,
                   int ds) {
	conn_impl_t *conn_impl = agent->conn_impl;

	mutex_lock(&conn_impl->send_mutex);

	if (conn_impl->send_ds >= 0 && conn_impl->send_ds != ds) {
		JLOG_VERBOSE("Setting Differentiated Services field to 0x%X", ds);
		if (udp_set_diffserv(conn_impl->sock, ds) == 0)
			conn_impl->send_ds = ds;
		else
			conn_impl->send_ds = -1; // disable for next time
	}

	JLOG_VERBOSE("Sending datagram, size=%d", size);

	int ret = udp_sendto(conn_impl->sock, data, size, dst);
	if (ret < 0) {
		if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)
			JLOG_INFO("Send failed, buffer is full");
		else if (sockerrno == SEMSGSIZE)
			JLOG_WARN("Send failed, datagram is too large");
		else
			JLOG_WARN("Send failed, errno=%d", sockerrno);
	}

	mutex_unlock(&conn_impl->send_mutex);
	return ret;
}

int conn_user_get_addrs(juice_agent_t *agent, addr_record_t *records, size_t size) {
	conn_impl_t *conn_impl = agent->conn_impl;

	return udp_get_addrs(conn_impl->sock, records, size);
}
