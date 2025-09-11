/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef JUICE_TCP_H
#define JUICE_TCP_H

#include "addr.h"
#include "juice.h"
#include "socket.h"

typedef enum tcp_state {
	TCP_STATE_DISCONNECTED,
	TCP_STATE_CONNECTING,
	TCP_STATE_CONNECTED,
	TCP_STATE_FAILED
} tcp_state_t;

socket_t tcp_create_socket(const addr_record_t *dst);

#define TCP_ICE_BUFFER_SIZE 2048

typedef struct tcp_ice_write_context {
	char buffer[TCP_ICE_BUFFER_SIZE];
	uint16_t length;
	uint16_t bytes_written;
	bool pending;
} tcp_ice_write_context_t;

typedef struct tcp_ice_read_context {
	char buffer[TCP_ICE_BUFFER_SIZE];
	uint16_t length;
	uint16_t bytes_read; // 0 if finished
	uint16_t header;
	bool pending;
} tcp_ice_read_context_t;

int tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_ice_write_context_t *context);
int tcp_ice_read(socket_t sock, tcp_ice_read_context_t *context);

// Export for tests
JUICE_EXPORT int _juice_tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_ice_write_context_t *context);
JUICE_EXPORT int _juice_tcp_ice_read(socket_t sock, tcp_ice_read_context_t *context);

#endif
