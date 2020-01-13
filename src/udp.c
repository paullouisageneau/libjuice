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

#include "udp.h"
#include "log.h"

#include <stdio.h>

static struct addrinfo *find_family(struct addrinfo *ai_list,
                                    unsigned int family) {
	struct addrinfo *ai = ai_list;
	while (ai && ai->ai_family != family)
		ai = ai->ai_next;
	return ai;
}

static socklen_t get_addr_len(const struct sockaddr *sa) {
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

static uint16_t get_addr_port(const struct sockaddr *sa) {
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

static int set_addr_port(struct sockaddr *sa, uint16_t port) {
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

static bool is_local_addr(struct sockaddr *sa) {
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

static bool is_temp_inet6_addr(struct sockaddr *sa) {
	if (sa->sa_family != AF_INET6)
		return false;
	if (is_local_addr(sa))
		return false;
	const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
	const uint8_t *b = sin6->sin6_addr.s6_addr;
	return (b[8] & 0x02) ? false : true;
}

bool inet6_addr_unmapv4(struct sockaddr *sa, socklen_t *len) {
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

socket_t juice_udp_create(void) {
	// Obtain local Address
	struct addrinfo *ai_list = NULL;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	if (getaddrinfo(NULL, "0", &hints, &ai_list) != 0) {
		JLOG_ERROR("getaddrinfo for binding address failed, errno=%d", errno);
		return INVALID_SOCKET;
	}

	// Prefer IPv6
	struct addrinfo *ai;
	if ((ai = find_family(ai_list, AF_INET6)) == NULL &&
	    (ai = find_family(ai_list, AF_INET)) == NULL) {
		JLOG_ERROR("getaddrinfo for binding address failed: no suitable "
		           "address family");
		goto error;
	}

	// Create socket
	socket_t sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock == INVALID_SOCKET) {
		JLOG_ERROR("UDP socket creation failed, errno=%d", errno);
		goto error;
	}

	// Set options
	int enabled = 1;
	int disabled = 0;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
	if (ai->ai_family == AF_INET6)
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &disabled,
		           sizeof(disabled));

#ifndef NO_PMTUDISC
	int val = IP_PMTUDISC_DO;
	setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
#else
	setsockopt(sock, IPPROTO_IP, IP_DONTFRAG, &enabled, sizeof(enabled));
#endif

	// Bind it
	if (bind(sock, ai->ai_addr, ai->ai_addrlen)) {
		JLOG_ERROR("bind for UDP socket failed, errno=%d", errno);
		goto error;
	}

	ctl_t b = 1;
	if (ioctl(sock, FIONBIO, &b)) {
		JLOG_ERROR("Setting non-blocking mode for UDP socket failed, errno=%d",
		           errno);
		goto error;
	}

	freeaddrinfo(ai_list);
	return sock;

error:
	freeaddrinfo(ai_list);
	return INVALID_SOCKET;
}

uint16_t juice_udp_get_port(socket_t sock) {
	struct sockaddr_storage sa;
	socklen_t sl = sizeof(sa);
	if (getsockname(sock, (struct sockaddr *)&sa, &sl)) {
		JLOG_WARN("getsockname failed, errno=%d", errno);
		return 0;
	}

	return get_addr_port((struct sockaddr *)&sa);
}

int juice_udp_get_addrs(socket_t sock, struct sockaddr_record *records,
                        size_t count) {
	uint16_t port = juice_udp_get_port(sock);
	if (port == 0) {
		JLOG_ERROR("Getting UDP port failed");
		return -1;
	}

	struct sockaddr_record *end = records + count;
	int ret = 0;

#ifndef NO_IFADDRS
	struct ifaddrs *ifas;
	if (getifaddrs(&ifas)) {
		JLOG_ERROR("getifaddrs failed, errno=%d", errno);
		return -1;
	}

	// RFC 8445: If gathering one or more host candidates that correspond to an
	// IPv6 address that was generated using a mechanism that prevents location
	// tracking [RFC7721], host candidates that correspond to IPv6 addresses
	// that do allow location tracking, are configured on the same interface,
	// and are part of the same network prefix MUST NOT be gathered.  Similarly,
	// when host candidates corresponding to an IPv6 address generated using a
	// mechanism that prevents location tracking are gathered, then host
	// candidates corresponding to IPv6 link-local addresses [RFC4291] MUST NOT
	// be gathered. The IPv6 default address selection specification [RFC6724]
	// specifies that temporary addresses [RFC4941] are to be preferred over
	// permanent addresses.

	// Here, we will prevent gathering permanent IPv6 addresses if a temporary
	// one is found. This is more restrictive but fully compliant.
	bool has_temp_inet6 = false;
	for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
		if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK))
			continue;
		if (ifa->ifa_addr && is_temp_inet6_addr(ifa->ifa_addr)) {
			has_temp_inet6 = true;
		}
	}

	for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
		// RFC 8445: Addresses from a loopback interface MUST NOT be included in
		// the candidate addresses.
		if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK))
			continue;

		struct sockaddr *sa = ifa->ifa_addr;
		socklen_t len;
		if (sa && (sa->sa_family == AF_INET || sa->sa_family == AF_INET6) &&
		    !is_local_addr(sa) && (len = get_addr_len(sa))) {

			// Do not gather permanent addresses if a temporary one was found
			if (sa->sa_family == AF_INET6 && has_temp_inet6 &&
			    !is_temp_inet6_addr(sa))
				continue;

			++ret;
			if (records != end) {
				memcpy(&records->addr, sa, len);
				set_addr_port((struct sockaddr *)&records->addr, port);
				records->len = len;
				++records;
			}
		}
	}

	freeifaddrs(ifas);

#else // NO_IFADDRS defined
	char hostname[HOST_NAME_MAX];
	if (gethostname(hostname, HOST_NAME_MAX)) {
		JLOG_ERROR("gethostname failed, errno=%d", errno);
		return -1;
	}

	char service[8];
	snprintf(service, 8, "%hu", port);

	struct addrinfo *ai_list = NULL;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
	if (getaddrinfo(hostname, service, &hints, &ai_list)) {
		JLOG_WARN("getaddrinfo failed: hostname \"%s\" is not resolvable",
		          hostname);
		if (getaddrinfo("localhost", service, &hints, &ai_list)) {
			JLOG_ERROR(
			    "getaddrinfo failed: hostname \"localhost\" is not resolvable");
			return -1;
		}
	}

	for (struct addrinfo *ai = ai_list; ai; ai = ai->ai_next) {
		if ((ai->ai_family == AF_INET || ai->ai_family == AF_INET6) &&
		    !is_local_addr(sa)) {
			++ret;
			if (records != end) {
				memcpy(&records->addr, ai->ai_addr, ai->ai_addrlen);
				records->len = ai->ai_addrlen;
				++records;
			}
		}
	}

	freeaddrinfo(ai_list);
#endif

	return ret;
}
