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

#ifndef JUICE_UDP_H
#define JUICE_UDP_H

#include "addr.h"
#include "socket.h"

#include <stdint.h>

typedef struct udp_socket_config {
	const char *bind_address;
	uint16_t port_begin;
	uint16_t port_end;
} udp_socket_config_t;

socket_t udp_create_socket(const udp_socket_config_t *config);
int udp_recvfrom(socket_t sock, char *buffer, size_t size, addr_record_t *src);
int udp_sendto(socket_t sock, const char *data, size_t size, const addr_record_t *dst);
int udp_sendto_self(socket_t sock, const char *data, size_t size);
int udp_set_diffserv(socket_t sock, int ds);
uint16_t udp_get_port(socket_t sock);
int udp_get_bound_addr(socket_t sock, addr_record_t *record);
int udp_get_local_addr(socket_t sock, int family, addr_record_t *record); // family may be AF_UNSPEC
int udp_get_addrs(socket_t sock, addr_record_t *records, size_t count);

#endif // JUICE_UDP_H
