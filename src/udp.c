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

static struct addrinfo *find_family(struct addrinfo *aiList,
                                    unsigned int family) {
	struct addrinfo *ai = aiList;
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

socket_t juice_udp_create(void) {
	// Obtain local Address
	struct addrinfo *aiList = NULL;
	struct addrinfo aiHints;
	memset(&aiHints, 0, sizeof(aiHints));
	aiHints.ai_family = AF_UNSPEC;
	aiHints.ai_socktype = SOCK_DGRAM;
	aiHints.ai_protocol = IPPROTO_UDP;
	aiHints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	if (getaddrinfo(NULL, "0", &aiHints, &aiList) != 0) {
		JLOG_ERROR("getaddrinfo for binding address failed, errno=%d", errno);
		return INVALID_SOCKET;
	}

	// Prefer IPv6
	struct addrinfo *ai;
	if ((ai = find_family(aiList, AF_INET6)) == NULL &&
	    (ai = find_family(aiList, AF_INET)) == NULL) {
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

	freeaddrinfo(aiList);
	return sock;

error:
	freeaddrinfo(aiList);
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

int juice_udp_get_addrs(socket_t sock, sockaddr_record_t *records,
                        size_t count) {
	uint16_t port = juice_udp_get_port(sock);
	if (port == 0) {
		JLOG_ERROR("Getting UDP port failed");
		return -1;
	}

#ifndef NO_IFADDRS
	struct ifaddrs *ifas;
	if (getifaddrs(&ifas)) {
		JLOG_ERROR("getifaddrs failed, errno=%d", errno);
		return -1;
	}

	int ret = 0;
	struct ifaddrs *ifa = ifas;
	while (ifa) {
		struct sockaddr *sa = ifa->ifa_addr;
		socklen_t len = sa ? get_addr_len(sa) : 0;
		if (len) {
			++ret;
			if (count) {
				memcpy(&records->addr, sa, len);
				records->len = len;
				sa = (struct sockaddr *)&records->addr;
				if (set_addr_port(sa, port) == 0) {
					++records;
					--count;
				}
			}
		}
		ifa = ifa->ifa_next;
	}

	freeifaddrs(ifas);
    return ret;

#else // NO_IFADDRS
	char hostname[HOST_NAME_MAX];
	if (gethostname(hostname, HOST_NAME_MAX)) {
		JLOG_ERROR("gethostname failed, errno=%d", errno);
		return -1;
	}

	char service[8];
	snprintf(service, 8, "%hu", port);

	addrinfo *aiList = NULL;
	addrinfo aiHints;
	memset(&aiHints, 0, sizeof(aiHints));
	aiHints.ai_family = AF_UNSPEC;
	aiHints.ai_socktype = SOCK_DGRAM;
	aiHints.ai_protocol = 0;
	aiHints.ai_flags = AI_NUMERICSERV;
	if (getaddrinfo(hostname, service, &aiHints, &aiList)) {
		JLOG_WARN("getaddrinfo failed: hostname \"%s\" is not resolvable",
		          hostname);
		if (getaddrinfo("localhost", service, &aiHints, &aiList)) {
			JLOG_ERROR(
			    "getaddrinfo failed: hostname \"localhost\" is not resolvable");
			return -1;
		}
	}

	int ret = 0;
	addrinfo *ai = aiList;
	while (ai) {
		if (count && (ai->ai_family == AF_INET || ai->ai_family == AF_INET6)) {
			memcpy(&records->addr, sa, len);
			records->len = len;
			++records;
			--count;
		}
		ai = ai->ai_next;
		++ret;
	}

	freeaddrinfo(aiList);
	return ret;
#endif
}
