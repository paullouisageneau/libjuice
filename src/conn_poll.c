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
#include "random.h"
#include "thread.h"
#include "tcp.h"
#include "udp.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 4096

#if defined(__APPLE__) || defined(_WIN32)
#define TCP_SEND_FLAGS 0
#else
#define TCP_SEND_FLAGS MSG_NOSIGNAL
#endif

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

typedef enum poll_entry_type {
	POLL_ENTRY_INTERRUPT = 0,
	POLL_ENTRY_UDP,
	POLL_ENTRY_TCP_LISTENER,
	POLL_ENTRY_TCP_CONN,
} poll_entry_type_t;

typedef struct tcp_connection {
	socket_t sock;
	addr_record_t remote;
	bool closed;
	bool connecting;
	uint16_t frame_len;
	size_t header_bytes;
	size_t payload_len;
	uint8_t *send_buffer;
	size_t send_size;
	size_t send_offset;
	size_t send_capacity;
	uint8_t recv_buffer[65535];
} tcp_connection_t;

typedef struct conn_impl {
	conn_registry_t *registry;
	conn_state_t state;
	socket_t sock;
	mutex_t send_mutex;
	int send_ds;
	timestamp_t next_timestamp;
	bool tcp_enabled;
	socket_t tcp_listener;
	tcp_connection_t *tcp_conns;
	size_t tcp_conns_count;
	size_t tcp_conns_capacity;
	addr_record_t *tcp_addrs;
	size_t tcp_addrs_count;
} conn_impl_t;

typedef struct tcp_listener_config {
	const char *bind_address;
	uint16_t port_begin;
	uint16_t port_end;
} tcp_listener_config_t;

static uint16_t conn_poll_get_next_port(uint16_t begin, uint16_t end) {
	if (begin == 0)
		begin = 1024;
	if (end == 0)
		end = 0xFFFF;
	if (begin == end)
		return begin;

	static volatile uint32_t count = 0;
	if (count == 0)
		count = juice_rand32();

	static mutex_t mutex = MUTEX_INITIALIZER;
	mutex_lock(&mutex);
	uint32_t diff = end > begin ? end - begin : 0;
	uint16_t next = begin + count++ % (diff + 1);
	mutex_unlock(&mutex);
	return next;
}

static socket_t conn_poll_create_bound_tcp_socket(const tcp_listener_config_t *config,
	                                              const struct addrinfo *ai) {
	socket_t sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock == INVALID_SOCKET) {
		JLOG_WARN("TCP socket creation failed, errno=%d", sockerrno);
		return INVALID_SOCKET;
	}

	const sockopt_t reuse = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

	if (ai->ai_family == AF_INET6) {
		const sockopt_t disabled = 0;
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&disabled, sizeof(disabled));
	}

	const sockopt_t buffer_size = 1 * 1024 * 1024;
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char *)&buffer_size, sizeof(buffer_size));
	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char *)&buffer_size, sizeof(buffer_size));

	ctl_t nbio = 1;
	if (ioctlsocket(sock, FIONBIO, &nbio)) {
		JLOG_ERROR("Setting non-blocking mode on TCP socket failed, errno=%d", sockerrno);
		closesocket(sock);
		return INVALID_SOCKET;
	}

	if (config->port_begin == 0 && config->port_end == 0) {
		if (bind(sock, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0)
			return sock;

		JLOG_WARN("TCP socket binding failed, errno=%d", sockerrno);
		closesocket(sock);
		return INVALID_SOCKET;
	}

	struct sockaddr_storage addr;
	socklen_t addrlen = (socklen_t)ai->ai_addrlen;
	memcpy(&addr, ai->ai_addr, addrlen);

	if (config->port_begin == config->port_end) {
		addr_set_port((struct sockaddr *)&addr, config->port_begin);
		if (bind(sock, (struct sockaddr *)&addr, addrlen) == 0)
			return sock;

		JLOG_WARN("TCP socket binding failed on port %hu, errno=%d", config->port_begin,
		          sockerrno);
		closesocket(sock);
		return INVALID_SOCKET;
	}

	int retries = config->port_end - config->port_begin;
	do {
		uint16_t port = conn_poll_get_next_port(config->port_begin, config->port_end);
		addr_set_port((struct sockaddr *)&addr, port);
		if (bind(sock, (struct sockaddr *)&addr, addrlen) == 0)
			return sock;
	} while ((sockerrno == SEADDRINUSE || sockerrno == SEACCES) && retries-- > 0);

	JLOG_WARN("TCP socket binding failed on port range %s:[%hu,%hu], errno=%d",
	          config->bind_address ? config->bind_address : "any", config->port_begin,
	          config->port_end, sockerrno);
	closesocket(sock);
	return INVALID_SOCKET;
}

static socket_t conn_poll_tcp_create_listener(const tcp_listener_config_t *config) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

	struct addrinfo *ai_list = NULL;
	if (getaddrinfo(config->bind_address, "0", &hints, &ai_list) != 0) {
		JLOG_ERROR("getaddrinfo for binding address failed, errno=%d", sockerrno);
		return INVALID_SOCKET;
	}

	const int families[2] = {AF_INET6, AF_INET};
	const char *names[2] = {"IPv6", "IPv4"};
	for (int i = 0; i < 2; ++i) {
		const struct addrinfo *ai = ai_list;
		while (ai && ai->ai_family != families[i])
			ai = ai->ai_next;
		if (!ai)
			continue;

		JLOG_DEBUG("Opening TCP listener for %s family", names[i]);
		socket_t sock = conn_poll_create_bound_tcp_socket(config, ai);
		if (sock != INVALID_SOCKET) {
			freeaddrinfo(ai_list);
			return sock;
		}
	}

	JLOG_ERROR("TCP listener opening failed");
	freeaddrinfo(ai_list);
	return INVALID_SOCKET;
}

static int conn_poll_tcp_get_bound_addr(socket_t sock, addr_record_t *record) {
	record->len = sizeof(record->addr);
	if (getsockname(sock, (struct sockaddr *)&record->addr, &record->len) < 0)
		return -1;
	record->socktype = SOCK_STREAM;
	addr_unmap_inet6_v4mapped((struct sockaddr *)&record->addr, &record->len);
	return 0;
}

typedef struct poll_map_entry {
	poll_entry_type_t type;
	juice_agent_t *agent;
	int index;
} poll_map_entry_t;

typedef struct pfds_record {
	struct pollfd *pfds;
	poll_map_entry_t *map;
	nfds_t size;
} pfds_record_t;

int conn_poll_prepare(conn_registry_t *registry, pfds_record_t *pfds, timestamp_t *next_timestamp);
int conn_poll_process(conn_registry_t *registry, pfds_record_t *pfds);
int conn_poll_recv(socket_t sock, char *buffer, size_t size, addr_record_t *src);
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

	nfds_t needed = 1; // interrupt entry
	for (int i = 0; i < registry->agents_size; ++i) {
		juice_agent_t *agent = registry->agents[i];
		if (!agent)
			continue;

		conn_impl_t *conn_impl = agent->conn_impl;
		if (!conn_impl)
			continue;

		if (conn_impl->state != CONN_STATE_NEW && conn_impl->state != CONN_STATE_READY)
			continue;

		if (conn_impl->state == CONN_STATE_NEW)
			conn_impl->state = CONN_STATE_READY;

		if (*next_timestamp > conn_impl->next_timestamp)
			*next_timestamp = conn_impl->next_timestamp;

		++needed; // UDP socket
		if (conn_impl->tcp_enabled) {
			if (conn_impl->tcp_listener != INVALID_SOCKET)
				++needed;
			needed += conn_impl->tcp_conns_count;
		}
	}

	if (pfds->size != needed) {
		struct pollfd *new_pfds = realloc(pfds->pfds, sizeof(struct pollfd) * needed);
		poll_map_entry_t *new_map = realloc(pfds->map, sizeof(poll_map_entry_t) * needed);
		if (!new_pfds || !new_map) {
			JLOG_FATAL("Memory allocation for poll data failed");
			free(new_pfds);
			free(new_map);
			goto error;
		}
		pfds->pfds = new_pfds;
		pfds->map = new_map;
		pfds->size = needed;
	}

	registry_impl_t *registry_impl = registry->impl;
	struct pollfd *interrupt_pfd = pfds->pfds;
	poll_map_entry_t *interrupt_map = pfds->map;
	assert(interrupt_pfd && interrupt_map);
#ifdef _WIN32
	interrupt_pfd->fd = registry_impl->interrupt_sock;
#else
	interrupt_pfd->fd = registry_impl->interrupt_pipe_in;
#endif
	interrupt_pfd->events = POLLIN;
	interrupt_map->type = POLL_ENTRY_INTERRUPT;
	interrupt_map->agent = NULL;
	interrupt_map->index = -1;

	nfds_t index = 1;
	for (int i = 0; i < registry->agents_size; ++i) {
		juice_agent_t *agent = registry->agents[i];
		if (!agent)
			continue;

		conn_impl_t *conn_impl = agent->conn_impl;
		if (!conn_impl || conn_impl->state != CONN_STATE_READY)
			continue;

		struct pollfd *pfd = pfds->pfds + index;
		poll_map_entry_t *map = pfds->map + index;
		pfd->fd = conn_impl->sock;
		pfd->events = POLLIN;
		map->type = POLL_ENTRY_UDP;
		map->agent = agent;
		map->index = -1;
		++index;

		if (!conn_impl->tcp_enabled)
			continue;

		if (conn_impl->tcp_listener != INVALID_SOCKET) {
			struct pollfd *listener_pfd = pfds->pfds + index;
			poll_map_entry_t *listener_map = pfds->map + index;
			listener_pfd->fd = conn_impl->tcp_listener;
			listener_pfd->events = POLLIN;
			listener_map->type = POLL_ENTRY_TCP_LISTENER;
			listener_map->agent = agent;
			listener_map->index = -1;
			++index;
		}

		for (size_t j = 0; j < conn_impl->tcp_conns_count; ++j) {
			tcp_connection_t *connection = conn_impl->tcp_conns + j;
			struct pollfd *conn_pfd = pfds->pfds + index;
			poll_map_entry_t *conn_map = pfds->map + index;
			conn_pfd->fd = connection->sock;
			short events = POLLIN;
			if (connection->connecting)
				events |= POLLOUT;
			if (connection->send_size > connection->send_offset)
				events |= POLLOUT;
			conn_pfd->events = events;
			conn_map->type = POLL_ENTRY_TCP_CONN;
			conn_map->agent = agent;
			conn_map->index = (int)j;
			++index;
		}
	}

	assert(index == needed);

	int count = registry->agents_count;
	mutex_unlock(&registry->mutex);
	return count;

error:
	mutex_unlock(&registry->mutex);
	return -1;
}

int conn_poll_recv(socket_t sock, char *buffer, size_t size, addr_record_t *src) {
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

static void conn_poll_free_tcp_connection(tcp_connection_t *connection) {
	if (!connection)
		return;
	if (connection->sock != INVALID_SOCKET) {
		closesocket(connection->sock);
		connection->sock = INVALID_SOCKET;
	}
	free(connection->send_buffer);
	connection->send_buffer = NULL;
	connection->send_size = 0;
	connection->send_offset = 0;
	connection->send_capacity = 0;
	connection->closed = true;
}

static void conn_poll_sweep_tcp_connections(conn_impl_t *conn_impl) {
	if (!conn_impl->tcp_conns || conn_impl->tcp_conns_count == 0)
		return;

	size_t write_index = 0;
	for (size_t read_index = 0; read_index < conn_impl->tcp_conns_count; ++read_index) {
		tcp_connection_t *connection = conn_impl->tcp_conns + read_index;
		if (connection->closed) {
			conn_poll_free_tcp_connection(connection);
			continue;
		}
		if (write_index != read_index)
			conn_impl->tcp_conns[write_index] = conn_impl->tcp_conns[read_index];
		++write_index;
	}

	conn_impl->tcp_conns_count = write_index;
}

static int conn_poll_tcp_reserve(conn_impl_t *conn_impl, size_t count) {
	if (conn_impl->tcp_conns_capacity >= count)
		return 0;

	size_t new_capacity = conn_impl->tcp_conns_capacity ? conn_impl->tcp_conns_capacity : 4;
	while (new_capacity < count)
		new_capacity *= 2;

	tcp_connection_t *new_conns = realloc(conn_impl->tcp_conns,
	                                    new_capacity * sizeof(tcp_connection_t));
	if (!new_conns) {
		JLOG_FATAL("Memory allocation failed for TCP connections");
		return -1;
	}

	conn_impl->tcp_conns = new_conns;
	conn_impl->tcp_conns_capacity = new_capacity;
	return 0;
}

static bool conn_poll_mark_tcp_connection_closed(juice_agent_t *agent, conn_impl_t *conn_impl,
	                                              size_t index) {
	if (index >= conn_impl->tcp_conns_count)
		return false;

	addr_record_t remote = conn_impl->tcp_conns[index].remote;
	conn_poll_free_tcp_connection(conn_impl->tcp_conns + index);
	return agent_conn_tcp_state(agent, &remote, TCP_STATE_DISCONNECTED) == 0;
}

static int conn_poll_tcp_flush(tcp_connection_t *connection) {
	if (connection->connecting)
		return 0;
	while (connection->send_offset < connection->send_size) {
		int ret = (int)send(connection->sock,
		                  (const char *)connection->send_buffer + connection->send_offset,
		                  (int)(connection->send_size - connection->send_offset), TCP_SEND_FLAGS);
		if (ret < 0) {
			if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)
				return 0;
			JLOG_WARN("TCP send failed, errno=%d", sockerrno);
			return -1;
		}
		if (ret == 0)
			return -1;
		connection->send_offset += (size_t)ret;
	}

	connection->send_offset = 0;
	connection->send_size = 0;
	return 0;
}

static int conn_poll_tcp_queue_send(tcp_connection_t *connection, const char *data, size_t size) {
	if (size > 65535) {
		JLOG_WARN("Trying to send TCP frame larger than 65535 bytes");
		return -1;
	}
	if (connection->closed)
		return -1;

	size_t pending = connection->send_size - connection->send_offset;
	if (pending > 0 && connection->send_offset > 0) {
		memmove(connection->send_buffer, connection->send_buffer + connection->send_offset, pending);
		connection->send_size = pending;
		connection->send_offset = 0;
	} else if (pending == 0) {
		connection->send_size = 0;
		connection->send_offset = 0;
	}

	size_t frame_size = size + 2;
	size_t required = connection->send_size + frame_size;
	if (required > connection->send_capacity) {
		size_t new_capacity = connection->send_capacity ? connection->send_capacity : 512;
		while (new_capacity < required)
			new_capacity *= 2;
		uint8_t *new_buffer = realloc(connection->send_buffer, new_capacity);
		if (!new_buffer) {
			JLOG_FATAL("Memory allocation failed for TCP send buffer");
			return -1;
		}
		connection->send_buffer = new_buffer;
		connection->send_capacity = new_capacity;
	}

	uint8_t *dst = connection->send_buffer + connection->send_size;
	dst[0] = (uint8_t)((size >> 8) & 0xFF);
	dst[1] = (uint8_t)(size & 0xFF);
	memcpy(dst + 2, data, size);
	connection->send_size += frame_size;

	return conn_poll_tcp_flush(connection);
}

static int conn_poll_accept_tcp_connections(juice_agent_t *agent, conn_impl_t *conn_impl) {
	if (conn_impl->tcp_listener == INVALID_SOCKET)
		return 0;

	for (;;) {
		addr_record_t client;
		client.len = sizeof(client.addr);
		socket_t client_sock = accept(conn_impl->tcp_listener, (struct sockaddr *)&client.addr,
		                            &client.len);
		if (client_sock == INVALID_SOCKET) {
			if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)
				return 0;
			if (sockerrno == SEINTR)
				continue;
			JLOG_WARN("TCP accept failed, errno=%d", sockerrno);
			return -1;
		}
		client.socktype = SOCK_STREAM;
		addr_unmap_inet6_v4mapped((struct sockaddr *)&client.addr, &client.len);

		mutex_lock(&conn_impl->send_mutex);
		int reserve_err = conn_poll_tcp_reserve(conn_impl, conn_impl->tcp_conns_count + 1);
		if (reserve_err) {
			mutex_unlock(&conn_impl->send_mutex);
			closesocket(client_sock);
			return -1;
		}

		tcp_connection_t *connection = conn_impl->tcp_conns + conn_impl->tcp_conns_count;
		memset(connection, 0, sizeof(*connection));
		connection->sock = client_sock;
		connection->remote = client;
		connection->remote.socktype = SOCK_STREAM;
		connection->closed = false;
		connection->connecting = false;

		if (JLOG_INFO_ENABLED) {
			char addr_str[ADDR_MAX_STRING_LEN];
			addr_record_to_string(&connection->remote, addr_str, sizeof(addr_str));
			JLOG_INFO("Accepted ICE-TCP connection from %s", addr_str);
		}

		if (agent_conn_tcp_state(agent, &connection->remote, TCP_STATE_CONNECTED) != 0) {
			conn_poll_free_tcp_connection(connection);
			mutex_unlock(&conn_impl->send_mutex);
			closesocket(client_sock);
			return -1;
		}

		++conn_impl->tcp_conns_count;
		mutex_unlock(&conn_impl->send_mutex);
	}
}

static int conn_poll_tcp_finish_connect(juice_agent_t *agent, tcp_connection_t *connection) {
	int error = 0;
	socklen_t len = sizeof(error);
	if (getsockopt(connection->sock, SOL_SOCKET, SO_ERROR, (void *)&error, &len) < 0) {
		JLOG_WARN("getsockopt(SO_ERROR) failed, errno=%d", sockerrno);
		return -1;
	}
	if (error != 0) {
		JLOG_WARN("ICE-TCP connect failed, error=%d", error);
		return -1;
	}
	connection->connecting = false;
	if (agent_conn_tcp_state(agent, &connection->remote, TCP_STATE_CONNECTED) != 0)
		return -1;
	return 0;
}

static tcp_connection_t *conn_poll_tcp_create_active(juice_agent_t *agent, conn_impl_t *conn_impl,
                                                    const addr_record_t *dst) {
	if (conn_poll_tcp_reserve(conn_impl, conn_impl->tcp_conns_count + 1))
		return NULL;

	socket_t sock = socket(dst->addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		JLOG_WARN("ICE-TCP socket creation failed, errno=%d", sockerrno);
		return NULL;
	}

	const sockopt_t buffer_size = 1 * 1024 * 1024;
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char *)&buffer_size, sizeof(buffer_size));
	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char *)&buffer_size, sizeof(buffer_size));

	ctl_t nbio = 1;
	if (ioctlsocket(sock, FIONBIO, &nbio)) {
		JLOG_WARN("ICE-TCP set non-blocking failed, errno=%d", sockerrno);
		closesocket(sock);
		return NULL;
	}

	int ret = connect(sock, (const struct sockaddr *)&dst->addr, dst->len);
	bool connecting = false;
	if (ret < 0) {
		if (sockerrno == SEINPROGRESS || sockerrno == SEWOULDBLOCK) {
			connecting = true;
		} else {
			JLOG_WARN("ICE-TCP connect failed immediately, errno=%d", sockerrno);
			closesocket(sock);
			return NULL;
		}
	}

	tcp_connection_t *connection = conn_impl->tcp_conns + conn_impl->tcp_conns_count;
	memset(connection, 0, sizeof(*connection));
	connection->sock = sock;
	connection->remote = *dst;
	connection->remote.socktype = SOCK_STREAM;
	connection->closed = false;
	connection->connecting = connecting;
	connection->send_buffer = NULL;
	connection->send_capacity = 0;
	connection->send_size = 0;
	connection->send_offset = 0;
	connection->header_bytes = 0;
	connection->frame_len = 0;
	connection->payload_len = 0;

	addr_unmap_inet6_v4mapped((struct sockaddr *)&connection->remote.addr, &connection->remote.len);

	if (!connecting)
		JLOG_DEBUG("ICE-TCP active connection established");
	else
		JLOG_DEBUG("ICE-TCP active connection in progress");

	if (agent_conn_tcp_state(agent, &connection->remote,
	                        connecting ? TCP_STATE_CONNECTING : TCP_STATE_CONNECTED) != 0) {
		conn_poll_free_tcp_connection(connection);
		closesocket(sock);
		return NULL;
	}

	++conn_impl->tcp_conns_count;
	return connection;
}

static int conn_poll_tcp_handle_read(juice_agent_t *agent, tcp_connection_t *connection) {
	uint8_t buffer[BUFFER_SIZE];
	for (;;) {
        int ret = (int)recv(connection->sock, (char *)buffer, sizeof(buffer), 0);
		if (ret < 0) {
			if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)
				return 0;
			JLOG_WARN("TCP recv failed, errno=%d", sockerrno);
			return -1;
		}
		if (ret == 0)
			return -1; // closed

		size_t offset = 0;
		while (offset < (size_t)ret) {
			if (connection->header_bytes < 2) {
				connection->frame_len = (uint16_t)((connection->frame_len << 8) | buffer[offset]);
				++connection->header_bytes;
				++offset;
				if (connection->header_bytes == 2) {
					if (connection->frame_len == 0) {
						JLOG_WARN("Invalid zero-length TCP frame");
						return -1;
					}
					if (connection->frame_len >= sizeof(connection->recv_buffer)) {
						JLOG_WARN("TCP frame too large: %u bytes", connection->frame_len);
						return -1;
					}
					connection->payload_len = 0;
				}
				continue;
			}

			size_t remaining = connection->frame_len - connection->payload_len;
			size_t copy = remaining < ((size_t)ret - offset) ? remaining : ((size_t)ret - offset);
			memcpy(connection->recv_buffer + connection->payload_len, buffer + offset, copy);
			connection->payload_len += copy;
			offset += copy;

			if (connection->payload_len == connection->frame_len) {
				if (agent_conn_recv(agent, (char *)connection->recv_buffer, connection->frame_len,
				                 &connection->remote) != 0) {
					JLOG_WARN("Agent receive failed for TCP frame");
					return -1;
				}
				connection->header_bytes = 0;
				connection->frame_len = 0;
				connection->payload_len = 0;
			}
		}
	}
}

static ssize_t conn_poll_find_tcp_connection(conn_impl_t *conn_impl, const addr_record_t *dst) {
	for (size_t i = 0; i < conn_impl->tcp_conns_count; ++i) {
		tcp_connection_t *connection = conn_impl->tcp_conns + i;
		if (connection->closed)
			continue;
		if (addr_record_is_equal(&connection->remote, dst, true))
			return (ssize_t)i;
		if (addr_record_is_equal(&connection->remote, dst, false))
			return (ssize_t)i;
	}
	return -1;
}

static int conn_poll_update_agent(juice_agent_t *agent, conn_impl_t *conn_impl) {
	if (agent_conn_update(agent, &conn_impl->next_timestamp) != 0) {
		JLOG_WARN("Agent update failed");
		conn_impl->state = CONN_STATE_FINISHED;
		agent_conn_fail(agent);
		return -1;
	}
	return 0;
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
	for (nfds_t i = 1; i < pfds->size; ++i) {
		struct pollfd *pfd = pfds->pfds + i;
		poll_map_entry_t *map = pfds->map + i;
		if (!map->agent)
			continue;

		juice_agent_t *agent = map->agent;
		conn_impl_t *conn_impl = agent->conn_impl;
		if (!conn_impl || conn_impl->state != CONN_STATE_READY) {
			map->agent = NULL;
			continue;
		}

		short revents = pfd->revents;
		if (revents & (POLLNVAL | POLLERR)) {
			JLOG_WARN("Polling error on connection socket");
			agent_conn_fail(agent);
			conn_impl->state = CONN_STATE_FINISHED;
			map->agent = NULL;
			continue;
		}

		timestamp_t now = current_timestamp();
		bool need_update = false;

		switch (map->type) {
		case POLL_ENTRY_UDP: {
			if (revents & POLLIN) {
				char buffer[BUFFER_SIZE];
				addr_record_t src;
				int ret = 0;
				int left = 1000;
				while (left-- &&
				       (ret = conn_poll_recv(conn_impl->sock, buffer, BUFFER_SIZE, &src)) > 0) {
					if (agent_conn_recv(agent, buffer, (size_t)ret, &src) != 0) {
						JLOG_WARN("Agent receive failed");
						agent_conn_fail(agent);
						conn_impl->state = CONN_STATE_FINISHED;
						break;
					}
					need_update = true;
				}
				if (conn_impl->state != CONN_STATE_READY)
					break;
				if (ret < 0) {
					agent_conn_fail(agent);
					conn_impl->state = CONN_STATE_FINISHED;
					break;
				}
			}
			break;
		}
	case POLL_ENTRY_TCP_LISTENER: {
		if (revents & POLLIN) {
			if (conn_poll_accept_tcp_connections(agent, conn_impl) < 0) {
				agent_conn_fail(agent);
				conn_impl->state = CONN_STATE_FINISHED;
			}
		}
		break;
		}
	case POLL_ENTRY_TCP_CONN: {
		if (map->index < 0 || (size_t)map->index >= conn_impl->tcp_conns_count) {
			map->agent = NULL;
			break;
		}
		tcp_connection_t *connection = conn_impl->tcp_conns + map->index;
		bool connection_failed = false;
		bool connection_established = !connection->connecting;
		if (connection->connecting && (revents & (POLLOUT | POLLIN))) {
			if (conn_poll_tcp_finish_connect(agent, connection) < 0)
				connection_failed = true;
			else {
				connection_established = true;
				need_update = true;
			}
		}
		if (!connection_failed && (revents & POLLIN)) {
			if (conn_poll_tcp_handle_read(agent, connection) < 0)
				connection_failed = true;
			else
				need_update = true;
		}
		if (!connection_failed && connection_established && (revents & POLLOUT)) {
			mutex_lock(&conn_impl->send_mutex);
			if (conn_poll_tcp_flush(connection) < 0)
				connection_failed = true;
			mutex_unlock(&conn_impl->send_mutex);
		}
		if (!connection_failed && (revents & POLLHUP))
			connection_failed = true;
		if (connection_failed) {
			JLOG_WARN("ICE-TCP connection failed or closed");
			bool entry_notified = false;
			mutex_lock(&conn_impl->send_mutex);
			entry_notified =
			    conn_poll_mark_tcp_connection_closed(agent, conn_impl, (size_t)map->index);
			mutex_unlock(&conn_impl->send_mutex);
			map->agent = NULL;
			if (!entry_notified) {
				agent_conn_fail(agent);
				conn_impl->state = CONN_STATE_FINISHED;
				continue;
			}
			need_update = true;
			continue;
		}
		break;
	}
		default:
			break;
		}

		if (conn_impl->state != CONN_STATE_READY) {
			map->agent = NULL;
			continue;
		}

		if (need_update || conn_impl->next_timestamp <= now) {
			if (conn_poll_update_agent(agent, conn_impl) < 0) {
				map->agent = NULL;
				continue;
			}
		}
	}

	for (int i = 0; i < registry->agents_size; ++i) {
		juice_agent_t *agent = registry->agents[i];
		if (!agent)
			continue;
		conn_impl_t *conn_impl = agent->conn_impl;
		if (!conn_impl)
			continue;
		mutex_lock(&conn_impl->send_mutex);
		conn_poll_sweep_tcp_connections(conn_impl);
		mutex_unlock(&conn_impl->send_mutex);
	}

	mutex_unlock(&registry->mutex);
	return 0;
}

int conn_poll_run(conn_registry_t *registry) {
	pfds_record_t pfds;
	pfds.pfds = NULL;
	pfds.map = NULL;
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
	free(pfds.map);
	return 0;
}

int conn_poll_init(juice_agent_t *agent, conn_registry_t *registry, udp_socket_config_t *config) {
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

	mutex_init(&conn_impl->send_mutex, 0);
	conn_impl->send_ds = -1;
	conn_impl->registry = registry;
	conn_impl->tcp_listener = INVALID_SOCKET;
	conn_impl->tcp_enabled = agent->ice_tcp_mode != JUICE_ICE_TCP_MODE_NONE;

	if (conn_impl->tcp_enabled) {
		tcp_listener_config_t tcp_config;
		memset(&tcp_config, 0, sizeof(tcp_config));
		tcp_config.bind_address = config->bind_address;
		tcp_config.port_begin = config->port_begin;
		tcp_config.port_end = config->port_end;

		conn_impl->tcp_listener = conn_poll_tcp_create_listener(&tcp_config);
		if (conn_impl->tcp_listener == INVALID_SOCKET) {
			JLOG_WARN("ICE-TCP listener creation failed, disabling ICE-TCP");
			conn_impl->tcp_enabled = false;
		} else if (listen(conn_impl->tcp_listener, SOMAXCONN) < 0) {
			JLOG_WARN("ICE-TCP listen failed, errno=%d", sockerrno);
			closesocket(conn_impl->tcp_listener);
			conn_impl->tcp_listener = INVALID_SOCKET;
			conn_impl->tcp_enabled = false;
		} else {
			addr_record_t listener_addr;
			if (conn_poll_tcp_get_bound_addr(conn_impl->tcp_listener, &listener_addr) < 0) {
				JLOG_WARN("Failed to obtain TCP listener address, disabling ICE-TCP");
				closesocket(conn_impl->tcp_listener);
				conn_impl->tcp_listener = INVALID_SOCKET;
				conn_impl->tcp_enabled = false;
			} else {
				uint16_t tcp_port = addr_get_port((const struct sockaddr *)&listener_addr.addr);
				addr_record_t tmp[ICE_MAX_CANDIDATES_COUNT];
				int count = udp_get_addrs(conn_impl->sock, tmp, ICE_MAX_CANDIDATES_COUNT);
			if (count > 0) {
				conn_impl->tcp_addrs = malloc((size_t)count * sizeof(addr_record_t));
				if (!conn_impl->tcp_addrs) {
					JLOG_FATAL("Memory allocation failed for TCP addresses");
					closesocket(conn_impl->tcp_listener);
					conn_impl->tcp_listener = INVALID_SOCKET;
					conn_impl->tcp_enabled = false;
				} else {
					for (int i = 0; i < count; ++i) {
						tmp[i].socktype = SOCK_STREAM;
						addr_set_port((struct sockaddr *)&tmp[i].addr, tcp_port);
					}
					memcpy(conn_impl->tcp_addrs, tmp, (size_t)count * sizeof(addr_record_t));
					conn_impl->tcp_addrs_count = (size_t)count;
				}
			} else {
				if (count < 0)
					JLOG_ERROR("Failed to enumerate ICE-TCP addresses");
				else
					JLOG_WARN("No ICE-TCP addresses available");
			}
			}
		}
	}

	agent->conn_impl = conn_impl;
	return 0;
}

void conn_poll_cleanup(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;

	conn_poll_interrupt(agent);

	mutex_destroy(&conn_impl->send_mutex);
	if (conn_impl->tcp_conns) {
		for (size_t i = 0; i < conn_impl->tcp_conns_count; ++i)
			conn_poll_free_tcp_connection(conn_impl->tcp_conns + i);
		free(conn_impl->tcp_conns);
	}
	if (conn_impl->tcp_listener != INVALID_SOCKET)
		closesocket(conn_impl->tcp_listener);
	free(conn_impl->tcp_addrs);
	closesocket(conn_impl->sock);
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
	bool use_tcp = conn_impl->tcp_enabled && agent_address_uses_tcp(agent, dst);

	if (use_tcp) {
		conn_registry_t *registry = conn_impl->registry;
		if (!registry)
			return -1;

		mutex_lock(&registry->mutex);
		mutex_lock(&conn_impl->send_mutex);

		int queue_ret = -1;
		ssize_t index = conn_poll_find_tcp_connection(conn_impl, dst);
		if (index >= 0) {
			tcp_connection_t *connection = conn_impl->tcp_conns + index;
			queue_ret = conn_poll_tcp_queue_send(connection, data, size);
		} else {
			tcp_connection_t *connection = conn_poll_tcp_create_active(agent, conn_impl, dst);
			if (connection)
				queue_ret = conn_poll_tcp_queue_send(connection, data, size);
		}

		mutex_unlock(&conn_impl->send_mutex);
		mutex_unlock(&registry->mutex);

		if (queue_ret < 0)
			return queue_ret;

		conn_poll_interrupt(agent);
		return (int)size;
	}

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
		ret = -sockerrno;
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

int conn_poll_get_addrs(juice_agent_t *agent, addr_record_t *records, size_t size) {
	conn_impl_t *conn_impl = agent->conn_impl;

	return udp_get_addrs(conn_impl->sock, records, size);
}

int conn_poll_get_tcp_addrs(juice_agent_t *agent, addr_record_t *records, size_t size) {
	conn_impl_t *conn_impl = agent->conn_impl;
	if (!conn_impl->tcp_enabled || conn_impl->tcp_addrs_count == 0)
		return 0;

	size_t available = conn_impl->tcp_addrs_count;
	if (records && size > 0) {
		size_t copy = available;
		if (copy > size)
			copy = size;
		memcpy(records, conn_impl->tcp_addrs, copy * sizeof(addr_record_t));
	}

	return (int)available;
}

void conn_poll_tcp_connect(juice_agent_t *agent, const addr_record_t *dst) {
	conn_impl_t *conn_impl = agent->conn_impl;
	if (!conn_impl->tcp_enabled)
		return;

	conn_registry_t *registry = conn_impl->registry;
	mutex_lock(&registry->mutex);
	mutex_lock(&conn_impl->send_mutex);
	if (conn_poll_find_tcp_connection(conn_impl, dst) < 0)
		conn_poll_tcp_create_active(agent, conn_impl, dst);
	mutex_unlock(&conn_impl->send_mutex);
	mutex_unlock(&registry->mutex);
}
