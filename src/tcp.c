/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "tcp.h"
#include "log.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 1024

socket_t tcp_create_socket(const addr_record_t *dst) {
	socket_t sock = socket(dst->addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		JLOG_WARN("TCP socket creation failed, errno=%d", sockerrno);
		return INVALID_SOCKET;
	}

	int nodelay = 1;
	if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&nodelay, sizeof(nodelay))) {
		JLOG_WARN("Setting TCP_NODELAY on TCP socket failed, errno=%d", sockerrno);
	}

	ctl_t nbio = 1;
	if (ioctlsocket(sock, FIONBIO, &nbio)) {
		JLOG_ERROR("Setting non-blocking mode on TCP socket failed, errno=%d", sockerrno);
		goto error;
	}

	int ret = connect(sock, (const struct sockaddr *)&dst->addr, dst->len);
	if (ret != 0 && sockerrno != SEINPROGRESS && sockerrno != SEWOULDBLOCK) {
		JLOG_WARN("TCP connection failed, errno=%d", sockerrno);
		goto error;
	}

	JLOG_DEBUG("TCP socket created, non-blocking connect initiated (ret=%d)", ret);
	return sock;

error:
	if (sock != INVALID_SOCKET)
		closesocket(sock);

	return INVALID_SOCKET;
}

// Write datagram to TCP socket with RFC4571 framing
int tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context) {
#if defined(__APPLE__) || defined(_WIN32)
	int flags = 0;
#else
	int flags = MSG_NOSIGNAL;
#endif

	if (data) {
		if (context->pending)
			return -SEAGAIN;

		if (size > TCP_BUFFER_SIZE)
			return -SEMSGSIZE;

		memcpy(context->buffer, data, size);
		context->length = (uint16_t)size;
		context->bytes_written = 0;
		context->pending = true;
	}

	while(context->pending && context->bytes_written < 2 + context->length) {
		int len;
		if (context->bytes_written < 2) {
			uint16_t header = htons(context->length);
			len = send(sock, (const char *)&header + context->bytes_written, 2 - context->bytes_written, flags);
		} else { // bytes_written >= 2
			len = send(sock, context->buffer + (context->bytes_written - 2), context->length - (context->bytes_written - 2), flags);
		}

		if (len < 0)
			return len;

		context->bytes_written += len;
	}

	context->pending = false;
	return (int)context->length;
}

// Read datagram from TCP socket with RFC4571 framing (discard empty datagrams)
int tcp_ice_read(socket_t sock, tcp_read_context_t *context) {
#if defined(__APPLE__) || defined(_WIN32)
	int flags = 0;
#else
	int flags = MSG_NOSIGNAL;
#endif

	if (!context->pending) {
		context->length = 0;
		context->bytes_read = 0;
		context->pending = true;
	}

	int len;
	while (context->bytes_read < 2 + context->length) {
		if (context->bytes_read < 2) {
			len = recv(sock, (char *)&context->header + context->bytes_read, 2 - context->bytes_read, flags);
		} else { // bytes_read >= 2
			len = recv(sock, context->buffer + (context->bytes_read - 2),
			           context->length - (context->bytes_read - 2), flags);
		}

		if (len < 0) {
			if (sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK)
				JLOG_DEBUG("TCP recv failed, errno=%d", sockerrno);
			return -sockerrno;
		}

		if (len == 0)
			return 0; // closed

		context->bytes_read += len;

		if (context->bytes_read == 2) {
			context->length = ntohs(context->header);
			if (context->length == 0)
				context->bytes_read = 0; // discard empty datagram
			else if (context->length > TCP_BUFFER_SIZE)
				return -SEMSGSIZE;
		}
	}

	context->pending = false;
	assert(context->length > 0);
	return (int)context->length;
}

// Write raw STUN or ChannelData message to TCP socket (no RFC 4571 framing).
// ChannelData is padded to 4-byte boundary per RFC 8656 Section 12.5.
int tcp_stun_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context) {
#if defined(__APPLE__) || defined(_WIN32)
	int flags = 0;
#else
	int flags = MSG_NOSIGNAL;
#endif

	if (data) {
		if (context->pending)
			return -SEAGAIN;

		if (size > TCP_BUFFER_SIZE)
			return -SEMSGSIZE;

		memcpy(context->buffer, data, size);
		uint16_t wire_size = (uint16_t)size;

		// Pad ChannelData to 4-byte boundary for TCP (RFC 8656 Section 12.5)
		uint8_t first_byte = (uint8_t)context->buffer[0];
		if (first_byte >= 64 && first_byte <= 79) {
			uint16_t padded = (wire_size + 3) & ~3u;
			if (padded > TCP_BUFFER_SIZE)
				return -SEMSGSIZE;
			// Zero-fill padding bytes
			while (wire_size < padded)
				context->buffer[wire_size++] = 0;
		}

		context->length = wire_size;
		context->bytes_written = 0;
		context->pending = true;
	}

	while (context->pending && context->bytes_written < context->length) {
		int len = send(sock, context->buffer + context->bytes_written,
		               context->length - context->bytes_written, flags);
		if (len < 0) {
			if (sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK)
				JLOG_DEBUG("TCP send failed, errno=%d", sockerrno);
			return -sockerrno;
		}

		context->bytes_written += (uint16_t)len;
	}

	context->pending = false;
	return (int)context->length;
}

// Read raw STUN or ChannelData message from TCP socket (self-delimiting).
// STUN: first byte 0x00-0x3F, 20-byte header, payload length at bytes 2-3.
// ChannelData: first byte 0x40-0x4F, 4-byte header, payload length at bytes 2-3.
int tcp_stun_read(socket_t sock, tcp_read_context_t *context) {
#if defined(__APPLE__) || defined(_WIN32)
	int flags = 0;
#else
	int flags = MSG_NOSIGNAL;
#endif

	if (!context->pending) {
		context->length = CHANNEL_DATA_HEADER_SIZE; // read min header (4 bytes) to disambiguate
		context->bytes_read = 0;
		context->pending = true;
	}

	while (context->bytes_read < context->length) {
		int remaining = context->length - context->bytes_read;

		int len = recv(sock, context->buffer + context->bytes_read, remaining, flags);
		if (len < 0) {
			if (sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK)
				JLOG_DEBUG("TCP recv failed, errno=%d", sockerrno);
			return -sockerrno;
		}
		if (len == 0)
			return 0; // closed

		context->bytes_read += (uint16_t)len;

		// Once we have the minimum header (4 bytes), determine the full message length
		if (context->bytes_read >= CHANNEL_DATA_HEADER_SIZE &&
		    context->length == CHANNEL_DATA_HEADER_SIZE) {
			uint8_t first_byte = (uint8_t)context->buffer[0];
			uint16_t payload_len;
			memcpy(&payload_len, context->buffer + 2, sizeof(uint16_t));
			payload_len = ntohs(payload_len);

			uint16_t msg_len;
			if (first_byte < 64) {
				// STUN message: 20-byte header + payload
				msg_len = STUN_HEADER_SIZE + payload_len;
			} else {
				// ChannelData: 4-byte header + payload (padded to 4-byte boundary on TCP)
				msg_len = CHANNEL_DATA_HEADER_SIZE + ((payload_len + 3) & ~3u);
			}
			if (msg_len > TCP_BUFFER_SIZE)
				return -SEMSGSIZE;
			context->length = msg_len;
		}
	}

	context->pending = false;
	return (int)context->length;
}

const char *tcp_state_to_string(tcp_state_t state) {
	switch (state) {
	case TCP_STATE_DISCONNECTED: return "disconnected";
	case TCP_STATE_CONNECTING:   return "connecting";
	case TCP_STATE_CONNECTED:    return "connected";
	case TCP_STATE_FAILED:       return "failed";
	default:                     return "unknown";
	}
}

void tcp_conn_init(tcp_conn_t *tc, tcp_framing_t framing) {
	tc->sock = INVALID_SOCKET;
	tc->state = TCP_STATE_DISCONNECTED;
	tc->framing = framing;
	memset(&tc->write, 0, sizeof(tc->write));
	memset(&tc->read,  0, sizeof(tc->read));
}

void tcp_conn_reset(tcp_conn_t *tc) {
	memset(&tc->write, 0, sizeof(tc->write));
	memset(&tc->read,  0, sizeof(tc->read));
}

JUICE_EXPORT int _juice_tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context) {
	return tcp_ice_write(sock, data, size, context);
}

JUICE_EXPORT int _juice_tcp_ice_read(socket_t sock, tcp_read_context_t *context) {
	return tcp_ice_read(sock, context);
}

JUICE_EXPORT int _juice_tcp_stun_write(socket_t sock, const char *data, size_t size, tcp_write_context_t *context) {
	return tcp_stun_write(sock, data, size, context);
}

JUICE_EXPORT int _juice_tcp_stun_read(socket_t sock, tcp_read_context_t *context) {
	return tcp_stun_read(sock, context);
}

JUICE_EXPORT tcp_conn_t* _tcp_conn_init(tcp_framing_t f) {
	tcp_conn_t *tc = malloc(sizeof(tcp_conn_t));
	tcp_conn_init(tc, f);
	return tc;
}
