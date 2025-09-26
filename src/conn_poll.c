/**
 * Copyright (c) 2022 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "conn_poll.h"
#include "agent.h"
#include "log.h"
#include "socket.h"
#include "tcp.h"
#include "thread.h"
#include "udp.h"

#include <assert.h>
#include <string.h>

#define BUFFER_SIZE 4096

typedef struct registry_impl {
	thread_t thread;
#ifdef _WIN32
	socket_t interrupt_sock;
#else
	int interrupt_pipe_out;
	int interrupt_pipe_in;
#endif
} registry_impl_t;

typedef enum conn_state { CONN_STATE_NEW = 0, CONN_STATE_READY, CONN_STATE_FINISHED } conn_state_t;

typedef struct conn_impl {
	conn_registry_t *registry;
	conn_state_t state;
	socket_t udp_sock;
	socket_t tcp_sock;
	tcp_ice_write_context_t tcp_ice_write_context;
	tcp_ice_read_context_t tcp_ice_read_context;
	addr_record_t tcp_dst;
	tcp_state_t tcp_state;
	uint16_t ice_tcp_len;
	mutex_t send_mutex;
	int send_ds;
	timestamp_t next_timestamp;
} conn_impl_t;

typedef struct pfds_record {
	struct pollfd *pfds;
	nfds_t size;
} pfds_record_t;

int conn_poll_prepare(conn_registry_t *registry, pfds_record_t *pfds, timestamp_t *next_timestamp);
int conn_poll_process(conn_registry_t *registry, pfds_record_t *pfds);
void conn_poll_process_udp(juice_agent_t *agent, struct pollfd *pfd);
int conn_poll_recv_udp(socket_t sock, char *buffer, size_t size, addr_record_t *src);
void conn_poll_process_tcp(juice_agent_t *agent, struct pollfd *pfd);
void conn_poll_change_tcp_fail(juice_agent_t *agent);
void conn_poll_change_tcp_state(juice_agent_t *agent, tcp_state_t state);
int conn_poll_run(conn_registry_t *registry);

static thread_return_t THREAD_CALL conn_thread_entry(void *arg) {
	thread_set_name_self("juice poll");
	conn_registry_t *registry = (conn_registry_t *)arg;
	conn_poll_run(registry);
	return (thread_return_t)0;
}

int conn_poll_registry_init(conn_registry_t *registry, udp_socket_config_t *config) {
	(void)config;
	registry_impl_t *registry_impl = calloc(1, sizeof(registry_impl_t));
	if (!registry_impl) {
		JLOG_FATAL("Memory allocation failed for connections registry impl");
		return -1;
	}

#ifdef _WIN32
	udp_socket_config_t interrupt_config;
	memset(&interrupt_config, 0, sizeof(interrupt_config));
	interrupt_config.bind_address = "localhost";
	registry_impl->interrupt_sock = udp_create_socket(&interrupt_config);
	if (registry_impl->interrupt_sock == INVALID_SOCKET) {
		JLOG_FATAL("Dummy socket creation failed");
		free(registry_impl);
		return -1;
	}
#else
	int pipefds[2];
	if (pipe(pipefds)) {
		JLOG_FATAL("Pipe creation failed");
		free(registry_impl);
		return -1;
	}

	fcntl(pipefds[0], F_SETFL, O_NONBLOCK);
	fcntl(pipefds[1], F_SETFL, O_NONBLOCK);
	registry_impl->interrupt_pipe_out = pipefds[1]; // read
	registry_impl->interrupt_pipe_in = pipefds[0];  // write
#endif

	registry->impl = registry_impl;

	JLOG_DEBUG("Starting connections thread");
	int ret = thread_init(&registry_impl->thread, conn_thread_entry, registry);
	if (ret) {
		JLOG_FATAL("Thread creation failed, error=%d", ret);
		goto error;
	}

	return 0;

error:
#ifndef _WIN32
	close(registry_impl->interrupt_pipe_out);
	close(registry_impl->interrupt_pipe_in);
#endif
	free(registry_impl);
	registry->impl = NULL;
	return -1;
}

void conn_poll_registry_cleanup(conn_registry_t *registry) {
	registry_impl_t *registry_impl = registry->impl;

	JLOG_VERBOSE("Waiting for connections thread");
	thread_join(registry_impl->thread, NULL);

#ifdef _WIN32
	closesocket(registry_impl->interrupt_sock);
#else
	close(registry_impl->interrupt_pipe_out);
	close(registry_impl->interrupt_pipe_in);
#endif
	free(registry->impl);
	registry->impl = NULL;
}

int conn_poll_prepare(conn_registry_t *registry, pfds_record_t *pfds, timestamp_t *next_timestamp) {
	timestamp_t now = current_timestamp();
	*next_timestamp = now + 60000;

	mutex_lock(&registry->mutex);
	nfds_t size = 1;
	for (int i = 0; i < registry->agents_size; ++i) {
		juice_agent_t *agent = registry->agents[i];
		if (!agent) {
			continue;
		}

		conn_impl_t *conn_impl = agent->conn_impl;
		if (!conn_impl ||
		    (conn_impl->state != CONN_STATE_NEW && conn_impl->state != CONN_STATE_READY)) {
			continue;
		}

		size++;
		if (conn_impl->tcp_sock != INVALID_SOCKET) {
			size++;
		}
	}

	if (pfds->size != size) {
		struct pollfd *new_pfds = realloc(pfds->pfds, sizeof(struct pollfd) * size);
		if (!new_pfds) {
			JLOG_FATAL("Memory allocation for poll file descriptors failed");
			goto error;
		}
		pfds->pfds = new_pfds;
		pfds->size = size;
	}

	registry_impl_t *registry_impl = registry->impl;
	struct pollfd *interrupt_pfd = pfds->pfds;
	assert(interrupt_pfd);
#ifdef _WIN32
	interrupt_pfd->fd = registry_impl->interrupt_sock;
#else
	interrupt_pfd->fd = registry_impl->interrupt_pipe_in;
#endif
	interrupt_pfd->events = POLLIN;

	nfds_t i = 1;
	for (int j = 0; j < registry->agents_size; ++j) {
		juice_agent_t *agent = registry->agents[j];
		if (!agent)
			continue;

		conn_impl_t *conn_impl = agent->conn_impl;
		if (!conn_impl ||
		    (conn_impl->state != CONN_STATE_NEW && conn_impl->state != CONN_STATE_READY))
			continue;

		if (conn_impl->state == CONN_STATE_NEW)
			conn_impl->state = CONN_STATE_READY;

		if (*next_timestamp > conn_impl->next_timestamp)
			*next_timestamp = conn_impl->next_timestamp;

		assert(i < pfds->size);

		struct pollfd *udp_pfd = pfds->pfds + i;
		udp_pfd->fd = conn_impl->udp_sock;
		udp_pfd->events = POLLIN;
		i++;

		if (conn_impl->tcp_sock != INVALID_SOCKET) {
			struct pollfd *tcp_pfd = pfds->pfds + i;
			tcp_pfd->fd = conn_impl->tcp_sock;
			if (conn_impl->tcp_state == TCP_STATE_CONNECTING) {
				tcp_pfd->events = POLLOUT;
			} else {
				tcp_pfd->events = POLLIN;
				if(conn_impl->tcp_ice_write_context.pending)
					tcp_pfd->events |= POLLOUT;
			}

			i++;
		}
	}

	mutex_unlock(&registry->mutex);
	return size - 1;

error:
	mutex_unlock(&registry->mutex);
	return -1;
}

void conn_poll_process_udp(juice_agent_t *agent, struct pollfd *pfd) {
	conn_impl_t *conn_impl = agent->conn_impl;

	if (pfd->revents & POLLNVAL) {
		JLOG_WARN("Invalid socket");
		return;
	}

	if (pfd->revents & POLLERR) {
		JLOG_WARN("UDP socket error");
		agent_conn_fail(agent);
		conn_impl->state = CONN_STATE_FINISHED;
	}

	if (pfd->revents & POLLIN) {
		char buffer[BUFFER_SIZE];
		addr_record_t src;
		int ret = 0;
		int left = 1000; // limit for fairness between sockets
		while (left--) {
			if ((ret = conn_poll_recv_udp(conn_impl->udp_sock, buffer, BUFFER_SIZE,
							&src)) <= 0) {
				break;
			}

			if (agent_conn_recv(agent, buffer, (size_t)ret, &src) != 0) {
				JLOG_WARN("Agent receive failed");
				conn_impl->state = CONN_STATE_FINISHED;
				break;
			}
		}

		if (conn_impl->state == CONN_STATE_FINISHED)
			return;

		if (ret == -SEAGAIN || ret == -SEWOULDBLOCK) {
			JLOG_VERBOSE("No more datagrams to receive");
		} else {
			agent_conn_fail(agent);
			conn_impl->state = CONN_STATE_FINISHED;
			return;
		}

		if (agent_conn_update(agent, &conn_impl->next_timestamp) != 0) {
			JLOG_WARN("Agent update failed");
			conn_impl->state = CONN_STATE_FINISHED;
			return;
		}

	} else if (conn_impl->next_timestamp <= current_timestamp()) {
		if (agent_conn_update(agent, &conn_impl->next_timestamp) != 0) {
			JLOG_WARN("Agent update failed");
			conn_impl->state = CONN_STATE_FINISHED;
			return;
		}
	}

}

int conn_poll_recv_udp(socket_t sock, char *buffer, size_t size, addr_record_t *src) {
	JLOG_VERBOSE("Receiving datagram");
	int len;
	while ((len = udp_recvfrom(sock, buffer, size, src)) == 0) {
		// Empty datagram, ignore
	}

	if (len < 0) {
		if (sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK)
			JLOG_ERROR("recvfrom failed, errno=%d", sockerrno);

		return -sockerrno;
	}

	addr_unmap_inet6_v4mapped((struct sockaddr *)&src->addr, &src->len);
	return len; // len > 0
}

void conn_poll_process_tcp(juice_agent_t *agent, struct pollfd *pfd) {
	conn_impl_t *conn_impl = agent->conn_impl;

	if (pfd->revents & POLLNVAL) {
		JLOG_WARN("Invalid socket");
		return;
	}

	if (pfd->revents & POLLERR || (pfd->revents & POLLHUP && !(pfd->revents & POLLIN))) {
		JLOG_DEBUG("TCP connection failed");
		conn_poll_change_tcp_fail(agent);
		return;
	}

	if (pfd->revents & POLLOUT) {
		if (conn_impl->tcp_state == TCP_STATE_CONNECTING) {
			int err = 0;
			socklen_t errlen = sizeof(err);
			if (getsockopt(conn_impl->tcp_sock, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen) != 0) {
				JLOG_DEBUG("Failed to get socket error code");
				conn_poll_change_tcp_fail(agent);
				return;
			}

			if (err != 0) {
				JLOG_DEBUG("TCP connection failed, errno=%d", err);
				conn_poll_change_tcp_fail(agent);
				return;
			}

			conn_poll_change_tcp_state(agent, TCP_STATE_CONNECTED);
		} else {
			tcp_ice_write_context_t *context = &conn_impl->tcp_ice_write_context;
			if(context->pending) {
				int ret = tcp_ice_write(conn_impl->tcp_sock, NULL, 0, context);
				if (ret >= 0) {
					JLOG_DEBUG("Finished sending ICE-TCP datagram");
				} else if (ret == -SEAGAIN || ret == -SEWOULDBLOCK) {
					JLOG_WARN("TCP send failed, errno=%d", -ret);
					conn_poll_change_tcp_fail(agent);
					return;
				}
			}
		}
	}

	if (pfd->revents & POLLIN) {
		int ret = 0;
		int left = 1000; // limit for fairness between sockets
		while (left--) {
			tcp_ice_read_context_t *context = &conn_impl->tcp_ice_read_context;
			if ((ret = tcp_ice_read(conn_impl->tcp_sock, context)) < 0) {
				break;
			}

			if (agent_conn_recv(agent, context->buffer, (size_t)ret, &conn_impl->tcp_dst) != 0) {
				JLOG_WARN("Agent receive failed");
				conn_impl->state = CONN_STATE_FINISHED;
				break;
			}
		}

		if (conn_impl->state == CONN_STATE_FINISHED)
			return;

		if (ret == -SEAGAIN || ret == -SEWOULDBLOCK) {
			JLOG_VERBOSE("No more ICE-TCP datagrams to receive");
		} else if (ret <= 0) {
			if (ret == 0) JLOG_DEBUG("TCP connection closed");
			else JLOG_DEBUG("TCP connection failed");
			conn_poll_change_tcp_fail(agent);
			return;
		}

		if (agent_conn_update(agent, &conn_impl->next_timestamp) != 0) {
			JLOG_WARN("Agent update failed");
			conn_impl->state = CONN_STATE_FINISHED;
			return;
		}

	} else if (conn_impl->next_timestamp <= current_timestamp()) {
		if (agent_conn_update(agent, &conn_impl->next_timestamp) != 0) {
			JLOG_WARN("Agent update failed");
			conn_impl->state = CONN_STATE_FINISHED;
			return;
		}
	}
}

void conn_poll_change_tcp_fail(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	if (conn_impl->tcp_sock != INVALID_SOCKET) {
		closesocket(conn_impl->tcp_sock);
		conn_impl->tcp_sock = INVALID_SOCKET;
	}
	memset(&conn_impl->tcp_ice_write_context, 0, sizeof(tcp_ice_write_context_t));
	memset(&conn_impl->tcp_ice_read_context, 0, sizeof(tcp_ice_read_context_t));
	conn_poll_change_tcp_state(agent, TCP_STATE_FAILED);
}

void conn_poll_change_tcp_state(juice_agent_t *agent, tcp_state_t state) {
	conn_impl_t *conn_impl = agent->conn_impl;
	if(conn_impl->tcp_state != state) {
		switch(state) {
			case TCP_STATE_DISCONNECTED:
				JLOG_DEBUG("TCP state changed to disconnected");
				break;
			case TCP_STATE_CONNECTING:
				JLOG_DEBUG("TCP state changed to connecting");
				break;
			case TCP_STATE_CONNECTED:
				JLOG_DEBUG("TCP state changed to connected");
				break;
			case TCP_STATE_FAILED:
				JLOG_DEBUG("TCP state changed to failed");
				break;
			default:
				break;
		}
		conn_impl->tcp_state = state;
		if (agent_conn_tcp_state(agent, &conn_impl->tcp_dst, state) != 0) {
			if (conn_impl->tcp_sock != INVALID_SOCKET) {
				closesocket(conn_impl->tcp_sock);
				conn_impl->tcp_sock = INVALID_SOCKET;
			}
			conn_impl->tcp_state = TCP_STATE_DISCONNECTED;
		}
	}
}

int conn_poll_process(conn_registry_t *registry, pfds_record_t *pfds) {
	struct pollfd *interrupt_pfd = pfds->pfds;
	if (interrupt_pfd->revents & POLLIN) {
#ifdef _WIN32
		char dummy;
		addr_record_t src;
		while (udp_recvfrom(interrupt_pfd->fd, &dummy, 1, &src) >= 0) {
			// Ignore
		}
#else
		char dummy;
		while (read(interrupt_pfd->fd, &dummy, 1) > 0) {
			// Ignore
		}
#endif
	}

	mutex_lock(&registry->mutex);

	nfds_t i = 1;
	for (int j = 0; j < registry->agents_size; ++j) {
		juice_agent_t *agent = registry->agents[j];
		if (!agent)
			continue;

		conn_impl_t *conn_impl = agent->conn_impl;
		if (!conn_impl || (conn_impl->state != CONN_STATE_NEW && conn_impl->state != CONN_STATE_READY))
			continue;

		if (i >= pfds->size)
			break;

		struct pollfd *udp_pfd = pfds->pfds + i;
		if (udp_pfd->fd != conn_impl->udp_sock)
			break;

		conn_poll_process_udp(agent, udp_pfd);
		i++;

		if (conn_impl->tcp_sock == INVALID_SOCKET)
			continue;

		struct pollfd *tcp_pfd = pfds->pfds + i;
		if (tcp_pfd->fd != conn_impl->tcp_sock)
			break;

		conn_poll_process_tcp(agent, tcp_pfd);
		i++;
	}

	mutex_unlock(&registry->mutex);
	return 0;
}

int conn_poll_run(conn_registry_t *registry) {
	pfds_record_t pfds;
	pfds.pfds = NULL;
	pfds.size = 0;
	timestamp_t next_timestamp = 0;
	int count;
	while ((count = conn_poll_prepare(registry, &pfds, &next_timestamp)) > 0) {
		timediff_t timediff = next_timestamp - current_timestamp();
		if (timediff < 0)
			timediff = 0;

		JLOG_VERBOSE("Entering poll on %d sockets for %d ms", count, (int)timediff);
		int ret = poll(pfds.pfds, pfds.size, (int)timediff);
		JLOG_VERBOSE("Leaving poll");
		if (ret < 0) {
#ifdef _WIN32
			if (sockerrno == WSAENOTSOCK)
				continue; // prepare again as the fd has been removed
#endif
			if (sockerrno == SEINTR || sockerrno == SEAGAIN) {
				JLOG_VERBOSE("poll interrupted");
				continue;
			} else {
				JLOG_FATAL("poll failed, errno=%d", sockerrno);
				break;
			}
		}

		if (conn_poll_process(registry, &pfds) < 0)
			break;
	}

	JLOG_DEBUG("Leaving connections thread");
	free(pfds.pfds);
	return 0;
}

int conn_poll_init(juice_agent_t *agent, conn_registry_t *registry, udp_socket_config_t *config) {
	conn_impl_t *conn_impl = calloc(1, sizeof(conn_impl_t));
	if (!conn_impl) {
		JLOG_FATAL("Memory allocation failed for connection impl");
		return -1;
	}

	conn_impl->udp_sock = udp_create_socket(config);
	if (conn_impl->udp_sock == INVALID_SOCKET) {
		JLOG_ERROR("UDP socket creation failed");
		free(conn_impl);
		return -1;
	}

	mutex_init(&conn_impl->send_mutex, 0);
	conn_impl->registry = registry;
	conn_impl->tcp_sock = INVALID_SOCKET;
	conn_impl->tcp_state = TCP_STATE_DISCONNECTED;
	memset(&conn_impl->tcp_ice_write_context, 0, sizeof(tcp_ice_write_context_t));
	memset(&conn_impl->tcp_ice_read_context, 0, sizeof(tcp_ice_read_context_t));

	agent->conn_impl = conn_impl;
	return 0;
}

void conn_poll_cleanup(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;

	conn_poll_interrupt(agent);

	mutex_destroy(&conn_impl->send_mutex);
	closesocket(conn_impl->udp_sock);
	closesocket(conn_impl->tcp_sock);
	free(agent->conn_impl);
	agent->conn_impl = NULL;
}

void conn_poll_lock(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	conn_registry_t *registry = conn_impl->registry;
	mutex_lock(&registry->mutex);
}

void conn_poll_unlock(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	conn_registry_t *registry = conn_impl->registry;
	mutex_unlock(&registry->mutex);
}

int conn_poll_interrupt(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	conn_registry_t *registry = conn_impl->registry;
	registry_impl_t *registry_impl = registry->impl;

	mutex_lock(&registry->mutex);
	conn_impl->next_timestamp = current_timestamp();
	mutex_unlock(&registry->mutex);

	JLOG_VERBOSE("Interrupting connections thread");

	char dummy = 0;
#ifdef _WIN32
	if (udp_sendto_self(registry_impl->interrupt_sock, &dummy, 0) < 0) {
		if (sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK) {
			JLOG_WARN("Failed to interrupt poll by triggering socket, errno=%d", sockerrno);
		}
		return -1;
	}
#else
	if (write(registry_impl->interrupt_pipe_out, &dummy, 1) < 0 && errno != EAGAIN &&
	    errno != EWOULDBLOCK) {
		JLOG_WARN("Failed to interrupt poll by writing to pipe, errno=%d", errno);
	}
#endif
	return 0;
}

int conn_poll_send(juice_agent_t *agent, const addr_record_t *dst, const char *data, size_t size,
                   int ds) {
	conn_impl_t *conn_impl = agent->conn_impl;

	mutex_lock(&conn_impl->send_mutex);

	JLOG_VERBOSE("Sending datagram, size=%d", size);

	int ret;
	if (dst->socktype == SOCK_STREAM) {
		tcp_ice_write_context_t *context = &conn_impl->tcp_ice_write_context;
		if (!context->pending) {
			ret = tcp_ice_write(conn_impl->tcp_sock, data, size, context);
			if (context->pending && (ret == SEAGAIN || ret == SEWOULDBLOCK))
				ret = (int)size; // datagram is buffered, consider it sent
		} else {
			// another datagram is buffered, drop
			ret = -SEAGAIN;
		}
	} else {
		if (conn_impl->send_ds >= 0 && conn_impl->send_ds != ds) {
			JLOG_VERBOSE("Setting Differentiated Services field to 0x%X", ds);
			if (udp_set_diffserv(conn_impl->udp_sock, ds) == 0)
				conn_impl->send_ds = ds;
			else
				conn_impl->send_ds = -1; // disable for next time
		}

		ret = udp_sendto(conn_impl->udp_sock, data, size, dst);
		if (ret < 0)
			ret = -sockerrno;
	}

	if (ret < 0) {
		if (ret == -SEAGAIN || ret == -SEWOULDBLOCK)
			JLOG_INFO("Send failed, buffer is full");
		else if (ret == -SEMSGSIZE)
			JLOG_WARN("Send failed, datagram is too large");
		else
			JLOG_WARN("Send failed, errno=%d", -ret);
	}

	mutex_unlock(&conn_impl->send_mutex);
	return ret;
}

void conn_poll_tcp_connect(juice_agent_t *agent, const addr_record_t *dst) {
	conn_impl_t *conn_impl = agent->conn_impl;

	mutex_lock(&conn_impl->registry->mutex);
	mutex_lock(&conn_impl->send_mutex);
	if (conn_impl->tcp_sock == INVALID_SOCKET) {
		if (JLOG_DEBUG_ENABLED) {
			char dst_str[ADDR_MAX_STRING_LEN];
			addr_record_to_string(dst, dst_str, ADDR_MAX_STRING_LEN);
			JLOG_DEBUG("Attempting ICE-TCP connection to %s", dst_str);
		}
		conn_impl->tcp_sock = tcp_create_socket(dst);
		memcpy(&conn_impl->tcp_dst, dst, sizeof(conn_impl->tcp_dst));
		conn_poll_change_tcp_state(agent, TCP_STATE_CONNECTING);
	}
	mutex_unlock(&conn_impl->send_mutex);
	mutex_unlock(&conn_impl->registry->mutex);
}

int conn_poll_get_addrs(juice_agent_t *agent, addr_record_t *records, size_t size) {
	conn_impl_t *conn_impl = agent->conn_impl;

	return udp_get_addrs(conn_impl->udp_sock, records, size);
}
