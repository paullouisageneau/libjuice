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
#include <string.h>

#define BUFFER_SIZE 1024

socket_t tcp_create_socket(const addr_record_t *dst) {
	socket_t sock = socket(dst->addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) {
		JLOG_WARN("TCP socket creation failed, errno=%d", sockerrno);
		return INVALID_SOCKET;
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

	return sock;

error:
	if (sock != INVALID_SOCKET)
		closesocket(sock);

	return INVALID_SOCKET;
}

// Write datagram to TCP socket with RFC4571 framing
int tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_ice_write_context_t *context) {
#if defined(__APPLE__) || defined(_WIN32)
	int flags = 0;
#else
	int flags = MSG_NOSIGNAL;
#endif

	if (data) {
		if (context->pending)
			return -SEAGAIN;

		if (size > TCP_ICE_BUFFER_SIZE)
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
int tcp_ice_read(socket_t sock, tcp_ice_read_context_t *context) {
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
			if (context->bytes_read < 2 + TCP_ICE_BUFFER_SIZE) {
				uint16_t length = context->length;
				if (length > TCP_ICE_BUFFER_SIZE)
					length = TCP_ICE_BUFFER_SIZE;

				len = recv(sock, context->buffer + (context->bytes_read - 2), length - (context->bytes_read - 2), flags);
			} else {
				char buffer[BUFFER_SIZE];
				size_t size = context->length - (context->bytes_read - 2);
				if (size > BUFFER_SIZE)
					size = BUFFER_SIZE;

				len = recv(sock, buffer, (socklen_t)size, flags);
			}
		}

		if (len < 0) {
			if (sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK)
				JLOG_DEBUG("TCP recv failed, errno=%d", sockerrno);

			return -sockerrno;
		}

		if (len == 0)
			return len; // closed

		context->bytes_read += len;

		if(context->bytes_read == 2)
			context->length = ntohs(context->header);

		if (context->length == 0)
			context->bytes_read = 0; // discard empty datagram
	}

	context->pending = false;
	assert(context->length > 0);
	return (int)context->length;
}

JUICE_EXPORT int _juice_tcp_ice_write(socket_t sock, const char *data, size_t size, tcp_ice_write_context_t *context) {
	return tcp_ice_write(sock, data, size, context);
}

JUICE_EXPORT int _juice_tcp_ice_read(socket_t sock, tcp_ice_read_context_t *context) {
	return tcp_ice_read(sock, context);
}

