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

#ifndef JUICE_ADDR_H
#define JUICE_ADDR_H

#include "socket.h"

#include <stdbool.h>
#include <stdint.h>

socklen_t addr_get_len(const struct sockaddr *sa);
uint16_t addr_get_port(const struct sockaddr *sa);
int addr_set_port(struct sockaddr *sa, uint16_t port);
bool addr_is_local(struct sockaddr *sa);
bool addr_is_temp_inet6(struct sockaddr *sa);
bool addr_unmap_inet6_v4mapped(struct sockaddr *sa, socklen_t *len);
bool addr_map_inet6_v4mapped(struct sockaddr_storage *ss, socklen_t *len);
bool addr_is_equal(const struct sockaddr *a, const struct sockaddr *b, bool compare_ports);
unsigned long addr_hash(const struct sockaddr *sa, bool with_port);

typedef struct addr_record {
	struct sockaddr_storage addr;
	socklen_t len;
} addr_record_t;

int addr_resolve(const char *hostname, const char *service, addr_record_t *records, size_t count);

bool addr_record_is_equal(const addr_record_t *a, const addr_record_t *b, bool compare_ports);
unsigned long addr_record_hash(const addr_record_t *record, bool with_port);

#endif // JUICE_ADDR_H
