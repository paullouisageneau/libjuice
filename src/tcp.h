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

#define TCP_BUFFER_SIZE 2048

// STUN messages: 20-byte header, length at bytes 2-3 (payload only, total = 20 + length)
// ChannelData:    4-byte header, length at bytes 2-3 (payload only, total = 4 + length)
// Disambiguated by first byte: 0x00-0x3F = STUN, 0x40-0x4F = ChannelData
#define STUN_HEADER_SIZE 20
#define CHANNEL_DATA_HEADER_SIZE 4

typedef struct tcp_write_context {
	char buffer[TCP_BUFFER_SIZE];
	uint16_t length;
	uint16_t bytes_written;
	bool pending;
} tcp_write_context_t;

typedef struct tcp_read_context {
	char buffer[TCP_BUFFER_SIZE];
	uint16_t length;
	uint16_t bytes_read;
	uint16_t header; // RFC 4571: 2-byte length prefix (ICE framing only)
	bool pending;
} tcp_read_context_t;

// RFC 4571 framing (2-byte length prefix) — used for ICE-TCP
int tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context);
int tcp_ice_read(socket_t sock, tcp_read_context_t *context);

// Self-delimiting STUN/ChannelData framing — used for TURN-TCP
int tcp_stun_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context);
int tcp_stun_read(socket_t sock, tcp_read_context_t *context);

typedef enum tcp_framing {
	TCP_FRAMING_ICE,  // RFC 4571: 2-byte length prefix (ICE-TCP)
	TCP_FRAMING_STUN, // self-delimiting STUN/ChannelData (TURN-TCP)
} tcp_framing_t;

typedef struct tcp_conn {
	socket_t sock;
	tcp_framing_t framing;
	tcp_write_context_t write;
	tcp_read_context_t read;
	addr_record_t dst;
	tcp_state_t state;
} tcp_conn_t;

const char *tcp_state_to_string(tcp_state_t state);
void tcp_conn_init(tcp_conn_t *tc, tcp_framing_t framing);
void tcp_conn_reset(tcp_conn_t *tc);

// Export for tests
JUICE_EXPORT tcp_conn_t* _tcp_conn_init(tcp_framing_t);
JUICE_EXPORT int _juice_tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context);
JUICE_EXPORT int _juice_tcp_ice_read(socket_t sock, tcp_read_context_t *context);
JUICE_EXPORT int _juice_tcp_stun_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context);
JUICE_EXPORT int _juice_tcp_stun_read(socket_t sock, tcp_read_context_t *context);

#endif
