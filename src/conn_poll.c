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
	tcp_conn_t *ice_tcp;
	tcp_conn_t *turn_tcp;
	mutex_t send_mutex;
	int send_ds;
	timestamp_t next_timestamp;
} conn_impl_t;

typedef struct pfds_record {
	struct pollfd *pfds;
	nfds_t size;
} pfds_record_t;

typedef void (*tcp_on_state_change_t)(juice_agent_t *agent, tcp_conn_t *tc, tcp_state_t state);

int conn_poll_prepare(conn_registry_t *registry, pfds_record_t *pfds, timestamp_t *next_timestamp);
int conn_poll_process(conn_registry_t *registry, pfds_record_t *pfds);
void conn_poll_process_udp(juice_agent_t *agent, struct pollfd *pfd);
int conn_poll_recv_udp(socket_t sock, char *buffer, size_t size, addr_record_t *src);
void conn_poll_change_tcp_fail(juice_agent_t *agent, tcp_conn_t *tc,
                          const char *label, tcp_on_state_change_t on_change);
void conn_poll_change_tcp_state(juice_agent_t *agent, tcp_conn_t *tc,
                                  tcp_state_t state, const char *label,
                                  tcp_on_state_change_t on_change);

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

static inline nfds_t prepare_tcp_pfd(struct pollfd *pfds, nfds_t i, tcp_conn_t *tc) {
	if (tc && tc->sock != INVALID_SOCKET) {
		struct pollfd *pfd = pfds + i;
		pfd->fd = tc->sock;
		if (tc->state == TCP_STATE_CONNECTING)
			pfd->events = POLLOUT;
		else {
			pfd->events = POLLIN;
			bool write_pending = tc->write.pending;
			if (write_pending)
				pfd->events |= POLLOUT;
		}
		return i + 1;
	}
	return i;
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
		tcp_conn_t *ice_tcp = conn_impl->ice_tcp;
		if (ice_tcp && ice_tcp->sock != INVALID_SOCKET) {
			size++;
		}
		tcp_conn_t *turn_tcp = conn_impl->turn_tcp;
		if (turn_tcp && turn_tcp->sock != INVALID_SOCKET) {
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

		i = prepare_tcp_pfd(pfds->pfds, i, conn_impl->ice_tcp);
		i = prepare_tcp_pfd(pfds->pfds, i, conn_impl->turn_tcp);
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

		if (ret > 0) {
			// There are more datagrams but we need to give other sockets a turn
			JLOG_VERBOSE("Fairness limit reached, will continue on next poll");
		} else if (ret == -SEAGAIN || ret == -SEWOULDBLOCK) {
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

void conn_poll_process_tcp_conn(juice_agent_t *agent, struct pollfd *pfd,
                                       tcp_conn_t *tc, const char *label,
                                       tcp_on_state_change_t on_change) {
	conn_impl_t *conn_impl = agent->conn_impl;
	bool stun_framing = tc->framing == TCP_FRAMING_STUN;

	if (pfd->revents & POLLNVAL) {
		JLOG_WARN("Invalid %s socket", label);
		return;
	}

	if (pfd->revents & POLLERR || (pfd->revents & POLLHUP && !(pfd->revents & POLLIN))) {
		JLOG_DEBUG("%s connection got POLLERR/POLLHUP (revents=0x%x)", label, pfd->revents);
		conn_poll_change_tcp_fail(agent, tc, label, on_change);
		return;
	}

	if (pfd->revents & POLLOUT) {
		if (tc->state == TCP_STATE_CONNECTING) {
			int err = 0;
			socklen_t errlen = sizeof(err);
			if (getsockopt(tc->sock, SOL_SOCKET, SO_ERROR, (char *)&err, &errlen) != 0) {
				JLOG_INFO("Failed to get %s socket error code, errno=%d", label, sockerrno);
				conn_poll_change_tcp_fail(agent, tc, label, on_change);
				return;
			}

			if (err != 0) {
				JLOG_INFO("%s connection failed on SO_ERROR, errno=%d", label, err);
				conn_poll_change_tcp_fail(agent, tc, label, on_change);
				return;
			}

			int nodelay = 1;
			setsockopt(tc->sock, IPPROTO_TCP, TCP_NODELAY, (char*)&nodelay, sizeof(nodelay));

			JLOG_INFO("%s connection established (POLLOUT with no error)", label);
			conn_poll_change_tcp_state(agent, tc, TCP_STATE_CONNECTED, label, on_change);
		} else {
			if (tc->write.pending) {
				int ret = stun_framing
				    ? tcp_stun_write(tc->sock, NULL, 0, &tc->write)
				    : tcp_ice_write(tc->sock, NULL, 0, &tc->write);
				if (ret >= 0) {
					JLOG_DEBUG("Finished sending %s message", label);
				} else if (ret == -SEAGAIN || ret == -SEWOULDBLOCK) {
					JLOG_WARN("%s send failed, errno=%d", label, -ret);
					conn_poll_change_tcp_fail(agent, tc, label, on_change);
					return;
				}
			}
		}
	}

	if (pfd->revents & POLLIN) {
		int ret = 0;
		int left = 1000; // limit for fairness between sockets
		while (left--) {
			if (stun_framing)
				ret = tcp_stun_read(tc->sock, &tc->read);
			else
				ret = tcp_ice_read(tc->sock, &tc->read);
			if (ret < 0)
				break;
			if (agent_conn_recv(agent, tc->read.buffer, (size_t)ret, &tc->dst) != 0) {
				JLOG_WARN("Agent receive failed");
				conn_impl->state = CONN_STATE_FINISHED;
				break;
			}
		}

		if (conn_impl->state == CONN_STATE_FINISHED)
			return;

		if (ret > 0) {
			// There are more datagrams but we need to give other sockets a turn
			JLOG_VERBOSE("Fairness limit reached, will continue on next poll");
		} else if (ret == -SEAGAIN || ret == -SEWOULDBLOCK) {
			JLOG_VERBOSE("No more ICE-TCP datagrams to receive");
		} else {
			if (ret == 0) JLOG_DEBUG("TCP connection closed");
			else JLOG_DEBUG("TCP connection failed");
			conn_poll_change_tcp_fail(agent, tc, label, on_change);
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

void conn_poll_change_tcp_fail(juice_agent_t *agent, tcp_conn_t *tc,
                          const char *label, tcp_on_state_change_t on_change) {
	JLOG_INFO("%s connection closing socket and marking failed", label);
	if (tc->sock != INVALID_SOCKET) {
		closesocket(tc->sock);
		tc->sock = INVALID_SOCKET;
	}
	tcp_conn_reset(tc);
	conn_poll_change_tcp_state(agent, tc, TCP_STATE_FAILED, label, on_change);
}

void conn_poll_change_tcp_state(juice_agent_t *agent, tcp_conn_t *tc,
                                  tcp_state_t state, const char *label,
                                  tcp_on_state_change_t on_change) {
	if (tc->state != state) {
		JLOG_INFO("%s state changed to %s", label, tcp_state_to_string(state));
		tc->state = state;
		if (on_change)
			on_change(agent, tc, state);
	}
}

static void ice_tcp_on_state_change(juice_agent_t *agent, tcp_conn_t *tc, tcp_state_t state) {
	if (agent_conn_tcp_state(agent, &tc->dst, state) != 0) {
		if (tc->sock != INVALID_SOCKET) {
			closesocket(tc->sock);
			tc->sock = INVALID_SOCKET;
		}
		tc->state = TCP_STATE_DISCONNECTED;
	}
}

static void turn_tcp_on_state_change(juice_agent_t *agent, tcp_conn_t *tc, tcp_state_t state) {
	(void)tc;
	JLOG_INFO("TURN TCP state changed: %s", tcp_state_to_string(state));
	if (state == TCP_STATE_CONNECTED || state == TCP_STATE_FAILED)
		conn_interrupt(agent);
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

		tcp_conn_t *ice_tcp = conn_impl->ice_tcp;
		if (ice_tcp && ice_tcp->sock != INVALID_SOCKET) {
			if (i >= pfds->size)
				break;

			struct pollfd *tcp_pfd = pfds->pfds + i;
			if (tcp_pfd->fd == ice_tcp->sock) {
				conn_poll_process_tcp_conn(agent, tcp_pfd, ice_tcp, "ICE-TCP", ice_tcp_on_state_change);
				i++;
			}
		}

		tcp_conn_t *turn_tcp = conn_impl->turn_tcp;
		if (turn_tcp && turn_tcp->sock != INVALID_SOCKET) {
			if (i >= pfds->size)
				break;

			struct pollfd *turn_tcp_pfd = pfds->pfds + i;
			if (turn_tcp_pfd->fd == turn_tcp->sock) {
				conn_poll_process_tcp_conn(agent, turn_tcp_pfd, turn_tcp, "TURN TCP", turn_tcp_on_state_change);
				i++;
			}
		}
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

	agent->conn_impl = conn_impl;
	return 0;
}

void conn_poll_cleanup(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;

	conn_poll_interrupt(agent);

	mutex_destroy(&conn_impl->send_mutex);
	closesocket(conn_impl->udp_sock);
	tcp_conn_t *ice_tcp = conn_impl->ice_tcp;
	if (ice_tcp) {
		if (ice_tcp->sock != INVALID_SOCKET)
			closesocket(ice_tcp->sock);
		free(ice_tcp);
	}
	tcp_conn_t *turn_tcp = conn_impl->turn_tcp;
	if (turn_tcp) {
		if (turn_tcp->sock != INVALID_SOCKET)
			closesocket(turn_tcp->sock);
		free(turn_tcp);
	}
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
                   int ds, bool use_turn_tcp) {
	conn_impl_t *conn_impl = agent->conn_impl;

	if (use_turn_tcp) {
		mutex_lock(&conn_impl->send_mutex);

		tcp_conn_t *turn_tcp = conn_impl->turn_tcp;
		if (!turn_tcp || turn_tcp->state != TCP_STATE_CONNECTED) {
			mutex_unlock(&conn_impl->send_mutex);
			return -SEAGAIN;
		}

		JLOG_VERBOSE("Sending STUN message via TURN TCP, size=%d", (int)size);

		int ret;
		tcp_write_context_t *context = &turn_tcp->write;
		if (!context->pending) {
			ret = tcp_stun_write(turn_tcp->sock, data, size, context);
			if (context->pending && (ret == -SEAGAIN || ret == -SEWOULDBLOCK))
				ret = (int)size; // message is buffered, consider it sent
		} else {
			// another message is buffered, drop
			ret = -SEAGAIN;
		}

		if (ret < 0) {
			if (ret == -SEAGAIN || ret == -SEWOULDBLOCK)
				JLOG_INFO("TURN TCP send failed, buffer is full");
			else
				JLOG_WARN("TURN TCP send failed, errno=%d", -ret);
		}

		mutex_unlock(&conn_impl->send_mutex);
		return ret;
	}

	mutex_lock(&conn_impl->send_mutex);

	JLOG_VERBOSE("Sending datagram, size=%d", size);

	int ret;
	if (dst->socktype == SOCK_STREAM) {
		tcp_conn_t *ice_tcp = conn_impl->ice_tcp;
		if (!ice_tcp) {
			mutex_unlock(&conn_impl->send_mutex);
			return -SEAGAIN;
		}
		tcp_write_context_t *context = &ice_tcp->write;
		if (!context->pending) {
			ret = tcp_ice_write(ice_tcp->sock, data, size, context);
			if (context->pending && (ret == -SEAGAIN || ret == -SEWOULDBLOCK))
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

static void tcp_conn_connect(juice_agent_t *agent, tcp_conn_t *tc,
                             const addr_record_t *dst, const char *label,
                             bool override_socktype_dgram,
                             tcp_on_state_change_t on_change) {
	if (tc->sock == INVALID_SOCKET) {
		char dst_str[ADDR_MAX_STRING_LEN];
		addr_record_to_string(dst, dst_str, ADDR_MAX_STRING_LEN);
		JLOG_INFO("Attempting %s connection to %s", label, dst_str);
		tc->sock = tcp_create_socket(dst);
		if (tc->sock == INVALID_SOCKET) {
			JLOG_WARN("%s socket creation failed for %s", label, dst_str);
			return;
		}
		memcpy(&tc->dst, dst, sizeof(tc->dst));
		if (override_socktype_dgram)
			tc->dst.socktype = SOCK_DGRAM;
		conn_poll_change_tcp_state(agent, tc, TCP_STATE_CONNECTING, label, on_change);
	}
}

void conn_poll_tcp_connect(juice_agent_t *agent, const addr_record_t *dst) {
	conn_impl_t *conn_impl = agent->conn_impl;

	mutex_lock(&conn_impl->registry->mutex);
	mutex_lock(&conn_impl->send_mutex);
	if (!conn_impl->ice_tcp) {
		conn_impl->ice_tcp = malloc(sizeof(tcp_conn_t));
		if (conn_impl->ice_tcp) {
			tcp_conn_init(conn_impl->ice_tcp, TCP_FRAMING_ICE);
		}
	}
	tcp_conn_t *ice_tcp = conn_impl->ice_tcp;
	if (ice_tcp)
		tcp_conn_connect(agent, ice_tcp, dst, "ICE-TCP", false, ice_tcp_on_state_change);
	mutex_unlock(&conn_impl->send_mutex);
	mutex_unlock(&conn_impl->registry->mutex);
}

int conn_poll_get_addrs(juice_agent_t *agent, addr_record_t *records, size_t size) {
	conn_impl_t *conn_impl = agent->conn_impl;

	return udp_get_addrs(conn_impl->udp_sock, records, size);
}

void conn_poll_turn_tcp_connect(juice_agent_t *agent, const addr_record_t *dst) {
	conn_impl_t *conn_impl = agent->conn_impl;

	mutex_lock(&conn_impl->registry->mutex);
	mutex_lock(&conn_impl->send_mutex);
	if (!conn_impl->turn_tcp) {
		conn_impl->turn_tcp = malloc(sizeof(tcp_conn_t));
		if (conn_impl->turn_tcp) {
			tcp_conn_init(conn_impl->turn_tcp, TCP_FRAMING_STUN);
		}
	}
	tcp_conn_t *turn_tcp = conn_impl->turn_tcp;
	if (turn_tcp)
		tcp_conn_connect(agent, turn_tcp, dst, "TURN TCP", true, turn_tcp_on_state_change);
	mutex_unlock(&conn_impl->send_mutex);
	mutex_unlock(&conn_impl->registry->mutex);
}

bool conn_poll_turn_tcp_connected(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	tcp_conn_t *turn_tcp = conn_impl->turn_tcp;
	return turn_tcp && turn_tcp->state == TCP_STATE_CONNECTED;
}

bool conn_poll_turn_tcp_failed(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	tcp_conn_t *turn_tcp = conn_impl->turn_tcp;
	return turn_tcp && turn_tcp->state == TCP_STATE_FAILED;
}
