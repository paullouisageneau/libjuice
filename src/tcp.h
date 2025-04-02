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
#include "socket.h"

#include <stdbool.h>
#include <stdint.h>

socket_t tcp_create_socket(const addr_record_t *dst) {
	socket_t tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp_socket == -1) {
		return INVALID_SOCKET;
	}

	ctl_t nbio = 1;
	if (ioctlsocket(tcp_socket, FIONBIO, &nbio)) {
		closesocket(tcp_socket);
		return SECONNREFUSED;
	}

	int ret = connect(tcp_socket, (const struct sockaddr *)&dst->addr, dst->len);
	if (ret != 0 && sockerrno != SEINPROGRESS && sockerrno != SEWOULDBLOCK) {
		closesocket(tcp_socket);
		return SECONNREFUSED;
	}

	return tcp_socket;
}

int tcp_ice_write(socket_t sock, const char *data, size_t size) {
	if (size >= USHRT_MAX) {
		return SEMSGSIZE;
	}

	uint16_t header = htons((uint16_t) size);
	int ret = (int)send(sock, (const char *) &header, sizeof(uint16_t), 0);
	if (ret < 0) {
		return ret;
	}

	return send(sock, data, (int)size, 0);
}

int tcp_ice_read(socket_t sock, char *buffer, size_t size, uint16_t *ice_tcp_len) {
	int ret = 0;

	if (*ice_tcp_len == 0) {
		if ((ret = recv(sock, (char *)ice_tcp_len, sizeof(uint16_t), 0)) != 2) {
			goto __exit;
		}

		*ice_tcp_len = ntohs(*ice_tcp_len);
		if (size < *ice_tcp_len) {
			return -1;
		}
	}

	if ((ret = recv(sock, buffer, *ice_tcp_len, 0)) == *ice_tcp_len) {
		*ice_tcp_len = 0;
	}

	__exit:
		if (ret < 0 && (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)) {
			return 0;
		}

		return ret;
}

#endif
