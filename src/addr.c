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

#include "addr.h"
#include "log.h"

socklen_t addr_get_len(const struct sockaddr *sa) {
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(struct sockaddr_in);
	case AF_INET6:
		return sizeof(struct sockaddr_in6);
	default:
		JLOG_WARN("Unknown address family %hu", sa->sa_family);
		return 0;
	}
}

uint16_t addr_get_port(const struct sockaddr *sa) {
	switch (sa->sa_family) {
	case AF_INET:
		return ntohs(((struct sockaddr_in *)sa)->sin_port);
	case AF_INET6:
		return ntohs(((struct sockaddr_in6 *)sa)->sin6_port);
	default:
		JLOG_WARN("Unknown address family %hu", sa->sa_family);
		return 0;
	}
}

int addr_set_port(struct sockaddr *sa, uint16_t port) {
	switch (sa->sa_family) {
	case AF_INET:
		((struct sockaddr_in *)sa)->sin_port = htons(port);
		return 0;
	case AF_INET6:
		((struct sockaddr_in6 *)sa)->sin6_port = htons(port);
		return 0;
	default:
		JLOG_WARN("Unknown address family %hu", sa->sa_family);
		return -1;
	}
}

bool addr_is_local(struct sockaddr *sa) {
	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
		const uint8_t *b = (const uint8_t *)&sin->sin_addr.s_addr;
		if (b[0] == 127) // localhost
			return true;
		if (b[0] == 169 && b[1] == 254) // link-local
			return true;
		return false;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
		const uint8_t *b = sin6->sin6_addr.s6_addr;
		if (b[0] == 0xFE && b[1] == 0x80) // link-local
			return true;
		for (int i = 0; i < 9; ++i)
			if (b[i] != 0)
				return false;
		if (b[10] == 0xFF && b[11] == 0xFF) { // IPv4-mapped
			if (b[12] == 127)                 // localhost
				return true;
			if (b[12] == 169 && b[13] == 254) // link-local
				return true;
		}
		for (int i = 10; i < 15; ++i)
			if (b[i] != 0)
				return false;
		if (b[15] == 1) // localhost
			return true;
		return false;
	}
	default:
		return false;
	}
}

bool addr_is_temp_inet6(struct sockaddr *sa) {
	if (sa->sa_family != AF_INET6)
		return false;
	if (addr_is_local(sa))
		return false;
	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
	const uint8_t *b = sin6->sin6_addr.s6_addr;
	return (b[8] & 0x02) ? false : true;
}

bool addr_unmap_inet6_v4mapped(struct sockaddr *sa, socklen_t *len) {
	if (sa->sa_family != AF_INET6)
		return false;

	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
	if (!IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
		return false;

	struct sockaddr_in6 copy = *sin6;
	sin6 = &copy;

	struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	sin->sin_family = AF_INET;
	sin->sin_port = sin6->sin6_port;
	sin->sin_addr.s_addr = *((uint32_t *)(sin6->sin6_addr.s6_addr + 12));
	*len = sizeof(*sin);
	return true;
}
