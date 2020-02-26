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
#include "addr.h"
#include "log.h"

#include <stdio.h>
#include <string.h>

static struct addrinfo *find_family(struct addrinfo *ai_list, unsigned int family) {
	struct addrinfo *ai = ai_list;
	while (ai && ai->ai_family != family)
		ai = ai->ai_next;
	return ai;
}

socket_t udp_create_socket(void) {
	// Obtain local Address
	struct addrinfo *ai_list = NULL;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	if (getaddrinfo(NULL, "0", &hints, &ai_list) != 0) {
		JLOG_ERROR("getaddrinfo for binding address failed, errno=%d", sockerrno);
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
		JLOG_ERROR("UDP socket creation failed, errno=%d", sockerrno);
		goto error;
	}

	// Set options
	int enabled = 1;
	int disabled = 0;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&enabled, sizeof(enabled));
	if (ai->ai_family == AF_INET6)
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&disabled, sizeof(disabled));

#ifndef NO_PMTUDISC
	int val = IP_PMTUDISC_DO;
	setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, (char *)&val, sizeof(val));
#else
// It seems Mac OS lacks a way to set the DF flag...
#ifndef __APPLE__
	setsockopt(sock, IPPROTO_IP, IP_DONTFRAG, (char *)&enabled, sizeof(enabled));
#endif
#endif

	// Bind it
	if (bind(sock, ai->ai_addr, ai->ai_addrlen)) {
		JLOG_ERROR("bind for UDP socket failed, errno=%d", sockerrno);
		goto error;
	}

	ctl_t b = 1;
	if (ioctl(sock, FIONBIO, &b)) {
		JLOG_ERROR("Setting non-blocking mode for UDP socket failed, errno=%d", sockerrno);
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
		JLOG_WARN("getsockname failed, errno=%d", sockerrno);
		return 0;
	}

	return addr_get_port((struct sockaddr *)&sa);
}

// Helper function to check if a similar address already exists in records
static int has_duplicate_addr(struct sockaddr *addr, const addr_record_t *records, size_t count) {
	for (size_t i = 0; i < count; ++i) {
		const addr_record_t *record = records + i;
		if (record->addr.ss_family == addr->sa_family) {
			switch (addr->sa_family) {
			case AF_INET: {
				// For IPv4, compare the whole address
				if (memcmp(&record->addr, addr, record->len) == 0)
					return true;
				break;
			}
			case AF_INET6: {
				// For IPv6, compare the network part only
				const struct sockaddr_in6 *rsin6 = (const struct sockaddr_in6 *)&record->addr;
				const struct sockaddr_in6 *asin6 = (const struct sockaddr_in6 *)addr;
				if (memcmp(&rsin6->sin6_addr, &asin6->sin6_addr, 8) == 0) // compare first 64 bits
					return true;
				break;
			}
			}
		}
	}
	return false;
}

int udp_get_addrs(socket_t sock, addr_record_t *records, size_t count) {
	uint16_t port = juice_udp_get_port(sock);
	if (port == 0) {
		JLOG_ERROR("Getting UDP port failed");
		return -1;
	}

	// RFC 8445 5.1.1.1. Host Candidates:
	// Addresses from a loopback interface MUST NOT be included in the candidate addresses.
	// [...]
	// If gathering one or more host candidates that correspond to an IPv6 address that was
	// generated using a mechanism that prevents location tracking [RFC7721], host candidates that
	// correspond to IPv6 addresses that do allow location tracking, are configured on the same
	// interface, and are part of the same network prefix MUST NOT be gathered. Similarly, when host
	// candidates corresponding to an IPv6 address generated using a mechanism that prevents
	// location tracking are gathered, then host candidates corresponding to IPv6 link-local
	// addresses [RFC4291] MUST NOT be gathered. The IPv6 default address selection specification
	// [RFC6724] specifies that temporary addresses [RFC4941] are to be preferred over permanent
	// addresses.

	// Here, we will prevent gathering permanent IPv6 addresses if a temporary one is found.
	// This is more restrictive but fully compliant.

	addr_record_t *current = records;
	addr_record_t *end = records + count;
	int ret = 0;

#ifdef _WIN32
	char buf[4096];
	DWORD len = 0;
	if (WSAIoctl(sock, SIO_ADDRESS_LIST_QUERY, NULL, 0, buf, sizeof(buf), &len, NULL, NULL)) {
		JLOG_ERROR("WSAIoctl with SIO_ADDRESS_LIST_QUERY failed, errno=%d", WSAGetLastError());
		return -1;
	}

	SOCKET_ADDRESS_LIST *list = (SOCKET_ADDRESS_LIST *)buf;

	bool has_temp_inet6 = false;
	for (int i = 0; i < list->iAddressCount; ++i) {
		struct sockaddr *sa = list->Address[i].lpSockaddr;
		if (addr_is_temp_inet6(sa)) {
			has_temp_inet6 = true;
			break;
		}
	}

	for (int i = 0; i < list->iAddressCount; ++i) {
		struct sockaddr *sa = list->Address[i].lpSockaddr;
		socklen_t len = list->Address[i].iSockaddrLength;
		if ((sa->sa_family == AF_INET || sa->sa_family == AF_INET6) && !addr_is_local(sa) &&
		    !(has_temp_inet6 && sa->sa_family == AF_INET6 && !addr_is_temp_inet6(sa))) {
			if (!has_duplicate_addr(sa, records, current - records)) {
				++ret;
				if (current != end) {
					memcpy(&current->addr, sa, len);
					current->len = len;
					addr_unmap_inet6_v4mapped((struct sockaddr *)&current->addr, &current->len);
					addr_set_port((struct sockaddr *)&current->addr, port);
					++current;
				}
			}
		}
	}
#else // POSIX
#ifndef NO_IFADDRS
	struct ifaddrs *ifas;
	if (getifaddrs(&ifas)) {
		JLOG_ERROR("getifaddrs failed, errno=%d", sockerrno);
		return -1;
	}

	bool has_temp_inet6 = false;
	for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
		unsigned int flags = ifa->ifa_flags;
		if (!(flags & IFF_UP) || (flags & IFF_LOOPBACK))
			continue;
		if (ifa->ifa_addr && addr_is_temp_inet6(ifa->ifa_addr)) {
			has_temp_inet6 = true;
			break;
		}
	}

	for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
		unsigned int flags = ifa->ifa_flags;
		if (!(flags & IFF_UP) || (flags & IFF_LOOPBACK))
			continue;

		struct sockaddr *sa = ifa->ifa_addr;
		socklen_t len;
		if (sa && (sa->sa_family == AF_INET || sa->sa_family == AF_INET6) && !addr_is_local(sa) &&
		    !(has_temp_inet6 && sa->sa_family == AF_INET6 && !addr_is_temp_inet6(sa)) &&
		    (len = addr_get_len(sa)) > 0) {
			if (!has_duplicate_addr(sa, records, current - records)) {
				++ret;
				if (current != end) {
					memcpy(&current->addr, sa, len);
					current->len = len;
					addr_set_port((struct sockaddr *)&current->addr, port);
					++current;
				}
			}
		}
	}

	freeifaddrs(ifas);

#else // NO_IFADDRS defined
	char buf[4096];
	struct ifconf ifc;
	memset(&ifc, 0, sizeof(ifc));
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;

	if (ioctl(sock, SIOCGIFCONF, &ifc)) {
		JLOG_ERROR("ioctl for SIOCGIFCONF failed, errno=%d", sockerrno);
		return -1;
	}

	int n = ifc.ifc_len / sizeof(struct ifreq);
	for (int i = 0; i < n; ++i) {
		struct ifreq *ifr = ifc.ifc_req + i;
		struct sockaddr *sa = &ifr->ifr_addr;
		if (sa->sa_family == AF_INET && !addr_is_local(sa)) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&ifr->ifr_addr;
			if (!has_duplicate_addr(sa, records, current - records)) {
				++ret;
				if (current != end) {
					memcpy(&current->addr, sin, sizeof(*sin));
					current->len = sizeof(*sin);
					addr_set_port((struct sockaddr *)&current->addr, port);
					++current;
				}
			}
		}
	}

	char hostname[HOST_NAME_MAX];
	if (gethostname(hostname, HOST_NAME_MAX))
		strcpy(hostname, "localhost");

	char service[8];
	snprintf(service, 8, "%hu", port);

	struct addrinfo *ai_list = NULL;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
	if (getaddrinfo(hostname, service, &hints, &ai_list) == 0) {
		bool has_temp_inet6 = false;
		for (struct addrinfo *ai = ai_list; ai; ai = ai->ai_next) {
			if (addr_is_temp_inet6(ai->ai_addr)) {
				has_temp_inet6 = true;
				break;
			}
		}
	    for (struct addrinfo *ai = ai_list; ai; ai = ai->ai_next) {
			if (!addr_is_local(ai->ai_addr) &&
			    !(has_temp_inet6 && !addr_is_temp_inet6(ai->ai_addr))) {
				if (!has_duplicate_addr(ai->ai_addr, records, current - records)) {
					++ret;
					if (current != end) {
						memcpy(&current->addr, ai->ai_addr, ai->ai_addrlen);
						current->len = ai->ai_addrlen;
						++current;
					}
				}
			}
		}
		freeaddrinfo(ai_list);
	}
#endif
#endif
	return ret;
}
