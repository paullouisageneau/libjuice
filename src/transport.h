/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef JUICE_TCP_H
#define JUICE_TCP_H

#include "addr.h"
#include "socket.h"

#include <stdint.h>

typedef enum socket_type {
	SOCKET_NONE,
	SOCKET_UDP,
	SOCKET_TCP,
	SOCKET_TLS
} socke_type_t;

typedef struct tcp_socket_config {
	const char *bind_address;
	uint16_t port_begin;
	uint16_t port_end;

	socke_type_t type;
	int family;
} transport_socket_config_t;

socket_t transport_create_socket(const transport_socket_config_t *config);
int transport_getpeername(socket_t sock, addr_record_t *dst);
int transport_recv(socket_t sock, char *buffer, size_t size);
int transport_recvfrom(socket_t sock, char *buffer, size_t size, addr_record_t *src);
int transport_connect(socket_t sock, const addr_record_t *dst);
int transport_wait_for_connected(socket_t sock, struct timeval *timeout);
int transport_send(socket_t sock, const char *data, size_t size);
int transport_sendto(socket_t sock, const char *data, size_t size, const addr_record_t *dst);
int transport_set_diffserv(socket_t sock, int ds);
uint16_t transport_get_port(socket_t sock);
int transport_get_bound_addr(socket_t sock, addr_record_t *record);
int transport_get_local_addr(socket_t sock, int family, addr_record_t *record); // family may be AF_UNSPEC
int transport_get_addrs(socket_t sock, addr_record_t *records, size_t count);

#endif // JUICE_TCP_H
