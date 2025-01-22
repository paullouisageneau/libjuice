/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef JUICE_TCP_H
#define JUICE_TCP_H

#include "socket.h"

#include <stdbool.h>
#include <stdint.h>

socket_t tcp_create_socket(const addr_record_t *dst) {
	socket_t tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp_socket == -1) {
		return INVALID_SOCKET;
	}

	if (fcntl(tcp_socket, F_SETFL, O_NONBLOCK) != 0) {
		close(tcp_socket);
		return SECONNREFUSED;
	}

	int ret = connect(tcp_socket, (const struct sockaddr *)&dst->addr, dst->len);
	if (ret != 0 && sockerrno != SEINPROGRESS) {
		close(tcp_socket);
		return SECONNREFUSED;
	}

	return tcp_socket;
}

int tcp_send(socket_t sock, const char *data, size_t size) {
	if (size >= USHRT_MAX) {
		return SEMSGSIZE;
	}

	uint16_t header = htons((uint16_t) size);
	int ret = send(sock, &header, sizeof(uint16_t), 0);
	if (ret < 0) {
		return ret;
	}

	return send(sock, data, size, 0);
}

int tcp_ice_read(socket_t sock, char *buffer, size_t size) {
	uint16_t header = 0;
	int n = 0;

	if ((n = read(sock, &header, sizeof(uint16_t))) != 2) {
		return -1;
	}

	header = ntohs(header);
	if (size < header) {
		JLOG_ERROR("tcp_ice_read ice-tcp packet larger then buffer");
		return -1;
	}

	return read(sock, buffer, header);
}

#endif
