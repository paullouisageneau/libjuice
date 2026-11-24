/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE // for sendmmsg()
#endif

#include "udp.h"
#include "addr.h"
#include "log.h"
#include "random.h"
#include "thread.h" // for mutexes

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <mswsock.h> // for WSA_CMSG_* macros with MinGW
#ifndef UDP_SEND_MSG_SIZE
#define UDP_SEND_MSG_SIZE 2
#endif
// Maximum total size of a buffer split into datagrams by UDP Send Offload
#define UDP_USO_MAX_SIZE 65000
#endif

// HAVE_SENDMMSG may be defined by the build system
#ifndef HAVE_SENDMMSG
#if defined(__linux__) && (!defined(__ANDROID__) || __ANDROID_API__ >= 21)
#define HAVE_SENDMMSG 1
#else
#define HAVE_SENDMMSG 0
#endif
#endif

static struct addrinfo *find_family(struct addrinfo *ai_list, int family) {
	struct addrinfo *ai = ai_list;
	while (ai && ai->ai_family != family)
		ai = ai->ai_next;
	return ai;
}

static uint16_t get_next_port_in_range(uint16_t begin, uint16_t end) {
	if (begin == 0)
		begin = 1024;
	if (end == 0)
		end = 0xFFFF;
	if (begin == end)
		return begin;

	static volatile uint32_t count = 0;
	if (count == 0)
		count = juice_rand32();

	static mutex_t mutex = MUTEX_INITIALIZER;
	mutex_lock(&mutex);
	uint32_t diff = end > begin ? end - begin : 0;
	uint16_t next = begin + count++ % (diff + 1);
	mutex_unlock(&mutex);
	return next;
}

static socket_t create_socket_for_addrinfo(const udp_socket_config_t *config,
                                           const struct addrinfo *ai) {
	// Create socket
	socket_t sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
	if (sock == INVALID_SOCKET) {
		JLOG_WARN("UDP socket creation failed, errno=%d", sockerrno);
		return INVALID_SOCKET;
	}

	// Listen on both IPv6 and IPv4
	const sockopt_t disabled = 0;
	if (ai->ai_family == AF_INET6)
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&disabled, sizeof(disabled));

		// Set DF flag
#ifndef NO_PMTUDISC
	const sockopt_t val = IP_PMTUDISC_DO;
	setsockopt(sock, IPPROTO_IP, IP_MTU_DISCOVER, (const char *)&val, sizeof(val));
#ifdef IPV6_MTU_DISCOVER
	if (ai->ai_family == AF_INET6)
		setsockopt(sock, IPPROTO_IPV6, IPV6_MTU_DISCOVER, (const char *)&val, sizeof(val));
#endif
#else
	// It seems Mac OS lacks a way to set the DF flag...
	const sockopt_t enabled = 1;
#ifdef IP_DONTFRAG
	setsockopt(sock, IPPROTO_IP, IP_DONTFRAG, (const char *)&enabled, sizeof(enabled));
#endif
#ifdef IPV6_DONTFRAG
	if (ai->ai_family == AF_INET6)
		setsockopt(sock, IPPROTO_IPV6, IPV6_DONTFRAG, (const char *)&enabled, sizeof(enabled));
#endif
#endif

	// Set buffer size up to 1 MiB for performance
	const sockopt_t buffer_size = 1 * 1024 * 1024;
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char *)&buffer_size, sizeof(buffer_size));
	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char *)&buffer_size, sizeof(buffer_size));

	ctl_t nbio = 1;
	if (ioctlsocket(sock, FIONBIO, &nbio)) {
		JLOG_ERROR("Setting non-blocking mode on UDP socket failed, errno=%d", sockerrno);
		goto error;
	}

	// Bind it
	if (config->port_begin == 0 && config->port_end == 0) {
		if (bind(sock, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0) {
			JLOG_DEBUG("UDP socket bound to %s:%hu",
			           config->bind_address ? config->bind_address : "any", udp_get_port(sock));
			return sock;
		}

		JLOG_WARN("UDP socket binding failed, errno=%d", sockerrno);

	} else if (config->port_begin == config->port_end) {
		uint16_t port = config->port_begin;
		struct sockaddr_storage addr;
		socklen_t addrlen = (socklen_t)ai->ai_addrlen;
		memcpy(&addr, ai->ai_addr, addrlen);
		addr_set_port((struct sockaddr *)&addr, port);

		if (bind(sock, (struct sockaddr *)&addr, addrlen) == 0) {
			JLOG_DEBUG("UDP socket bound to %s:%hu",
			           config->bind_address ? config->bind_address : "any", port);
			return sock;
		}

		JLOG_WARN("UDP socket binding failed on port %hu, errno=%d", port, sockerrno);

	} else {
		struct sockaddr_storage addr;
		socklen_t addrlen = (socklen_t)ai->ai_addrlen;
		memcpy(&addr, ai->ai_addr, addrlen);

		int retries = config->port_end - config->port_begin;
		do {
			uint16_t port = get_next_port_in_range(config->port_begin, config->port_end);
			addr_set_port((struct sockaddr *)&addr, port);
			if (bind(sock, (struct sockaddr *)&addr, addrlen) == 0) {
				JLOG_DEBUG("UDP socket bound to %s:%hu",
				           config->bind_address ? config->bind_address : "any", port);
				return sock;
			}
		} while ((sockerrno == SEADDRINUSE || sockerrno == SEACCES) && retries-- > 0);

		JLOG_WARN("UDP socket binding failed on port range %s:[%hu,%hu], errno=%d",
		          config->bind_address ? config->bind_address : "any", config->port_begin,
		          config->port_end, sockerrno);
	}

error:
	if (sock != INVALID_SOCKET)
		closesocket(sock);

	return INVALID_SOCKET;
}

socket_t udp_create_socket(const udp_socket_config_t *config) {
	// Obtain local Address
	struct addrinfo *ai_list = NULL;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
	if (getaddrinfo(config->bind_address, "0", &hints, &ai_list) != 0) {
		JLOG_ERROR("getaddrinfo for binding address failed, errno=%d", sockerrno);
		return INVALID_SOCKET;
	}

	const int families[2] = {AF_INET6, AF_INET}; // Prefer IPv6
	const char *names[2] = {"IPv6", "IPv4"};
	for (int i = 0; i < 2; ++i) {
		const struct addrinfo *ai = find_family(ai_list, families[i]);
		if (!ai)
			continue;

		JLOG_DEBUG("Opening UDP socket for %s family", names[i]);
		socket_t sock = create_socket_for_addrinfo(config, ai);
		if (sock != INVALID_SOCKET) {
			freeaddrinfo(ai_list);
			return sock;
		}
	}

	JLOG_ERROR("UDP socket opening failed");
	freeaddrinfo(ai_list);
	return INVALID_SOCKET;
}

int udp_recvfrom(socket_t sock, char *buffer, size_t size, addr_record_t *src) {
	while (true) {
		src->len = sizeof(src->addr);
		src->socktype = SOCK_DGRAM;
		int len =
		    recvfrom(sock, buffer, (socklen_t)size, 0, (struct sockaddr *)&src->addr, &src->len);
		if (len >= 0) {
			addr_unmap_inet6_v4mapped((struct sockaddr *)&src->addr, &src->len);

		} else if (sockerrno == SECONNRESET || sockerrno == SENETRESET ||
		           sockerrno == SECONNREFUSED) {
			// On Windows, if a UDP socket receives an ICMP port unreachable response after
			// sending a datagram, this error is stored, and the next call to recvfrom() returns
			// WSAECONNRESET (port unreachable) or WSAENETRESET (TTL expired).
			// Therefore, it may be ignored.
			JLOG_DEBUG("Ignoring %s returned by recvfrom",
			           sockerrno == SECONNRESET
			               ? "ECONNRESET"
			               : (sockerrno == SENETRESET ? "ENETRESET" : "ECONNREFUSED"));
			continue;
		}
		return len;
	}
}

#ifndef __linux__
// Map an IPv4 destination to IPv4-mapped IPv6 if the socket is IPv6
static const addr_record_t *map_dst_for_socket(socket_t sock, const addr_record_t *dst,
                                               addr_record_t *tmp) {
	*tmp = *dst;
	addr_record_t name;
	name.len = sizeof(name.addr);
	name.socktype = SOCK_DGRAM;
	if (getsockname(sock, (struct sockaddr *)&name.addr, &name.len) == 0) {
		if (name.addr.ss_family == AF_INET6)
			addr_map_inet6_v4mapped(&tmp->addr, &tmp->len);
	} else {
		JLOG_WARN("getsockname failed, errno=%d", sockerrno);
	}
	return tmp;
}
#endif

int udp_sendto(socket_t sock, const char *data, size_t size, const addr_record_t *dst) {
#ifndef __linux__
	addr_record_t tmp;
	dst = map_dst_for_socket(sock, dst, &tmp);
	return sendto(sock, data, (socklen_t)size, 0, (const struct sockaddr *)&dst->addr, dst->len);
#else
	return sendto(sock, data, size, 0, (const struct sockaddr *)&dst->addr, dst->len);
#endif
}

// dst must already be mapped for the socket
static int send_single(socket_t sock, const juice_buffer_t *buffer, const addr_record_t *dst) {
#ifndef __linux__
	return sendto(sock, buffer->data, (socklen_t)buffer->size, 0,
	              (const struct sockaddr *)&dst->addr, dst->len);
#else
	return sendto(sock, buffer->data, buffer->size, 0, (const struct sockaddr *)&dst->addr,
	              dst->len);
#endif
}

#ifndef _WIN32
// Fallback with one system call per datagram
static int send_loop(socket_t sock, const juice_buffer_t *buffers, size_t count,
                     const addr_record_t *dst) {
	for (size_t i = 0; i < count; ++i)
		if (send_single(sock, buffers + i, dst) < 0)
			return i > 0 ? (int)i : -1;

	return (int)count;
}
#endif

#ifdef _WIN32

// WSASendMsg() sends a single datagram per call, so there is no direct equivalent to sendmmsg().
// However, since Windows 10 version 2004, UDP Send Offload (USO) allows sending a buffer which is
// split by the stack into datagrams of the same size, except the last one which may be shorter,
// when the UDP_SEND_MSG_SIZE control message is passed. Segmentation is performed in software when
// the network interface does not support the offload, for instance on loopback.

#ifndef NO_USO
static atomic(int) uso_state = 0; // 0 if unknown, 1 if available, -1 if unavailable
#else
static atomic(int) uso_state = -1; // disabled at build time
#endif

static bool is_uso_available(socket_t sock) {
	int state = atomic_load(&uso_state);
	if (state == 0) {
		DWORD value = 0;
		int len = sizeof(value);
		state =
		    getsockopt(sock, IPPROTO_UDP, UDP_SEND_MSG_SIZE, (char *)&value, &len) == 0 ? 1 : -1;
		JLOG_DEBUG("UDP Send Offload is %s", state > 0 ? "available" : "not available");
		atomic_store(&uso_state, state);
	}
	return state > 0;
}

// Send datagrams of size segment_size, except the last one which may be shorter, in one call
static int send_uso(socket_t sock, const juice_buffer_t *buffers, size_t count, DWORD segment_size,
                    const addr_record_t *dst) {
	assert(count <= UDP_BATCH_MAX);
	WSABUF wsabufs[UDP_BATCH_MAX];
	for (size_t i = 0; i < count; ++i) {
		wsabufs[i].buf = (CHAR *)buffers[i].data;
		wsabufs[i].len = (ULONG)buffers[i].size;
	}

	union {
		WSACMSGHDR header; // for alignment
		char buf[WSA_CMSG_SPACE(sizeof(DWORD))];
	} control;
	memset(&control, 0, sizeof(control));

	WSAMSG msg;
	memset(&msg, 0, sizeof(msg));
	msg.name = (LPSOCKADDR)&dst->addr;
	msg.namelen = dst->len;
	msg.lpBuffers = wsabufs;
	msg.dwBufferCount = (ULONG)count;
	msg.Control.buf = control.buf;
	msg.Control.len = sizeof(control.buf);

	WSACMSGHDR *cmsg = WSA_CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = IPPROTO_UDP;
	cmsg->cmsg_type = UDP_SEND_MSG_SIZE;
	cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(DWORD));
	memcpy(WSA_CMSG_DATA(cmsg), &segment_size, sizeof(segment_size));

	DWORD sent = 0;
	return WSASendMsg(sock, &msg, 0, &sent, NULL, NULL) == 0 ? 0 : -1;
}

static int send_batch_windows(socket_t sock, const juice_buffer_t *buffers, size_t count,
                              const addr_record_t *dst) {
	size_t i = 0;
	while (i < count) {
		// Find the longest run of datagrams which can be sent with USO
		size_t segment_size = buffers[i].size;
		size_t j = i + 1;
		if (segment_size > 0 && is_uso_available(sock)) {
			size_t total = segment_size;
			while (j < count && j - i < UDP_BATCH_MAX && buffers[j].size == segment_size &&
			       total + segment_size <= UDP_USO_MAX_SIZE) {
				total += segment_size;
				++j;
			}
			// The last datagram may be shorter
			if (j < count && j - i < UDP_BATCH_MAX && buffers[j].size > 0 &&
			    buffers[j].size < segment_size && total + buffers[j].size <= UDP_USO_MAX_SIZE) {
				total += buffers[j].size;
				++j;
			}
		}

		if (j - i == 1) {
			if (send_single(sock, buffers + i, dst) < 0)
				return i > 0 ? (int)i : -1;

			++i;
			continue;
		}

		if (send_uso(sock, buffers + i, j - i, (DWORD)segment_size, dst) < 0) {
			int err = sockerrno;
			if (err != WSAEINVAL && err != WSAEOPNOTSUPP && err != WSAENOPROTOOPT)
				return i > 0 ? (int)i : -1;

			// The error might be caused by USO, check if a single datagram can be sent
			if (send_single(sock, buffers + i, dst) < 0)
				return i > 0 ? (int)i : -1;

			JLOG_INFO("UDP Send Offload failed, errno=%d, disabling it", err);
			atomic_store(&uso_state, -1);
			++i;
			continue;
		}

		i = j;
	}
	return (int)count;
}

#elif HAVE_SENDMMSG

static atomic(bool) sendmmsg_unavailable = false;

static int send_batch_mmsg(socket_t sock, const juice_buffer_t *buffers, size_t count,
                           const addr_record_t *dst) {
	struct mmsghdr msgs[UDP_BATCH_MAX];
	struct iovec iovs[UDP_BATCH_MAX];
	size_t sent = 0;
	while (sent < count) {
		size_t n = count - sent < UDP_BATCH_MAX ? count - sent : UDP_BATCH_MAX;
		memset(msgs, 0, n * sizeof(*msgs));
		for (size_t i = 0; i < n; ++i) {
			iovs[i].iov_base = (void *)buffers[sent + i].data;
			iovs[i].iov_len = buffers[sent + i].size;
			msgs[i].msg_hdr.msg_name = (void *)&dst->addr;
			msgs[i].msg_hdr.msg_namelen = dst->len;
			msgs[i].msg_hdr.msg_iov = iovs + i;
			msgs[i].msg_hdr.msg_iovlen = 1;
		}

		int ret = sendmmsg(sock, msgs, (unsigned int)n, 0);
		if (ret < 0) {
			if (sent == 0 && sockerrno == ENOSYS) {
				JLOG_INFO("sendmmsg is not available, falling back to sendto");
				atomic_store(&sendmmsg_unavailable, true);
				return send_loop(sock, buffers, count, dst);
			}
			return sent > 0 ? (int)sent : -1;
		}

		sent += (size_t)ret;
		if ((size_t)ret < n) // stopped on error
			break;
	}
	return (int)sent;
}

#endif

int udp_sendto_batch(socket_t sock, const juice_buffer_t *buffers, size_t count,
                     const addr_record_t *dst) {
	if (count == 0)
		return 0;

	if (count > INT_MAX)
		count = INT_MAX;

#ifndef __linux__
	addr_record_t tmp;
	dst = map_dst_for_socket(sock, dst, &tmp);
#endif

#ifdef _WIN32
	return send_batch_windows(sock, buffers, count, dst);
#elif HAVE_SENDMMSG
	if (!atomic_load(&sendmmsg_unavailable))
		return send_batch_mmsg(sock, buffers, count, dst);

	return send_loop(sock, buffers, count, dst);
#else
	return send_loop(sock, buffers, count, dst);
#endif
}

int udp_sendto_self(socket_t sock, const char *data, size_t size) {
	addr_record_t local;
	if (udp_get_local_addr(sock, AF_UNSPEC, &local) < 0)
		return -1;

	int ret;
#ifndef __linux__
	// We know local has the same address family as sock here
	ret = sendto(sock, data, (socklen_t)size, 0, (const struct sockaddr *)&local.addr, local.len);
#else
	ret = sendto(sock, data, size, 0, (const struct sockaddr *)&local.addr, local.len);
#endif
	if (ret >= 0 || local.addr.ss_family != AF_INET6)
		return ret;

	// Fallback as IPv6 may be disabled on the loopback interface
	if (udp_get_local_addr(sock, AF_INET, &local) < 0)
		return -1;

#ifndef __linux__
	addr_map_inet6_v4mapped(&local.addr, &local.len);
	return sendto(sock, data, (socklen_t)size, 0, (const struct sockaddr *)&local.addr, local.len);
#else
	return sendto(sock, data, size, 0, (const struct sockaddr *)&local.addr, local.len);
#endif
}

int udp_set_diffserv(socket_t sock, int ds) {
#ifdef _WIN32
	// IP_TOS has been intentionally broken on Windows in favor of a convoluted proprietary
	// mechanism called qWave. Thank you Microsoft!
	// TODO: Investigate if DSCP can be still set directly without administrator flow configuration.
	(void)sock;
	(void)ds;
	JLOG_INFO("IP Differentiated Services are not supported on Windows");
	return -1;
#else
	addr_record_t name;
	name.len = sizeof(name.addr);
	name.socktype = SOCK_DGRAM;
	if (getsockname(sock, (struct sockaddr *)&name.addr, &name.len) < 0) {
		JLOG_WARN("getsockname failed, errno=%d", sockerrno);
		return -1;
	}

	switch (name.addr.ss_family) {
	case AF_INET:
#ifdef IP_TOS
		if (setsockopt(sock, IPPROTO_IP, IP_TOS, &ds, sizeof(ds)) < 0) {
			JLOG_WARN("Setting IP ToS failed, errno=%d", sockerrno);
			return -1;
		}
		return 0;
#else
		JLOG_INFO("Setting IP ToS is not supported");
		return -1;
#endif

	case AF_INET6:
#ifdef IPV6_TCLASS
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_TCLASS, &ds, sizeof(ds)) < 0) {
			JLOG_WARN("Setting IPv6 traffic class failed, errno=%d", sockerrno);
			return -1;
		}
#ifdef IP_TOS
		// Attempt to also set IP_TOS for IPv4, in case the system requires it
		setsockopt(sock, IPPROTO_IP, IP_TOS, &ds, sizeof(ds));
#endif
		return 0;
#else
		JLOG_INFO("Setting IPv6 traffic class is not supported");
		return -1;
#endif
	default:
		return -1;
	}
#endif
}

uint16_t udp_get_port(socket_t sock) {
	addr_record_t record;
	if (udp_get_bound_addr(sock, &record) < 0)
		return 0;
	return addr_get_port((struct sockaddr *)&record.addr);
}

int udp_get_bound_addr(socket_t sock, addr_record_t *record) {
	record->len = sizeof(record->addr);
	record->socktype = SOCK_DGRAM;
	if (getsockname(sock, (struct sockaddr *)&record->addr, &record->len)) {
		JLOG_WARN("getsockname failed, errno=%d", sockerrno);
		return -1;
	}
	return 0;
}

int udp_get_local_addr(socket_t sock, int family_hint, addr_record_t *record) {
	if (udp_get_bound_addr(sock, record) < 0)
		return -1;

	// If the socket is bound to a particular address, return it
	if (!addr_is_any((struct sockaddr *)&record->addr)) {
		if (record->addr.ss_family == AF_INET && family_hint == AF_INET6)
			addr_map_inet6_v4mapped(&record->addr, &record->len);

		return 0;
	}

	if (record->addr.ss_family == AF_INET6 && family_hint == AF_INET) {
		// Generate an IPv4 instead (socket is listening to any IPv4 or IPv6)

		uint16_t port = addr_get_port((struct sockaddr *)&record->addr);
		if (port == 0)
			return -1;

		struct sockaddr_in *sin = (struct sockaddr_in *)&record->addr;
		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_port = htons(port);
		record->len = sizeof(*sin);
		record->socktype = SOCK_DGRAM;
	}

	switch (record->addr.ss_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)&record->addr;
		const uint8_t localhost[4] = {127, 0, 0, 1};
		memcpy(&sin->sin_addr, localhost, 4);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&record->addr;
		uint8_t *b = (uint8_t *)&sin6->sin6_addr;
		memset(b, 0, 15);
		b[15] = 0x01; // localhost
		break;
	}
	default:
		// Ignore
		break;
	}

	if (record->addr.ss_family == AF_INET && family_hint == AF_INET6)
		addr_map_inet6_v4mapped(&record->addr, &record->len);

	return 0;
}

// Helper function to check if a similar address already exists in records
// This function ignores the port
static int has_duplicate_addr(struct sockaddr *addr, const addr_record_t *records, size_t count) {
	for (size_t i = 0; i < count; ++i) {
		const addr_record_t *record = records + i;
		if (record->addr.ss_family == addr->sa_family) {
			switch (addr->sa_family) {
			case AF_INET: {
				// For IPv4, compare the whole address
				const struct sockaddr_in *rsin = (const struct sockaddr_in *)&record->addr;
				const struct sockaddr_in *asin = (const struct sockaddr_in *)addr;
				if (memcmp(&rsin->sin_addr, &asin->sin_addr, 4) == 0)
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

#if !defined(_WIN32) && defined(NO_IFADDRS)
// Helper function to get the IPv6 address of the default interface
static int get_local_default_inet6(uint16_t port, struct sockaddr_in6 *result) {
	const char *dummy_host = "2001:db8::1"; // dummy public unreachable address
	const uint16_t dummy_port = 9;          // discard port

	struct sockaddr_in6 sin6;
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(dummy_port);
	if (inet_pton(AF_INET6, dummy_host, &sin6.sin6_addr) != 1)
		return -1;

	socket_t sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == INVALID_SOCKET)
		return -1;

	if (connect(sock, (const struct sockaddr *)&sin6, sizeof(sin6)))
		goto error;

	socklen_t result_len = sizeof(*result);
	if (getsockname(sock, (struct sockaddr *)result, &result_len))
		goto error;

	if (result_len != sizeof(*result))
		goto error;

	addr_set_port((struct sockaddr *)result, port);
	closesocket(sock);
	return 0;

error:
	closesocket(sock);
	return -1;
}
#endif

int udp_get_addrs(socket_t sock, addr_record_t *records, size_t count) {
	addr_record_t bound;
	if (udp_get_bound_addr(sock, &bound) < 0) {
		JLOG_ERROR("Getting UDP bound address failed");
		return -1;
	}

	if (!addr_is_any((struct sockaddr *)&bound.addr)) {
		if (count > 0)
			records[0] = bound;

		return 1;
	}

	uint16_t port = addr_get_port((struct sockaddr *)&bound.addr);

	// RFC 8445 5.1.1.1. Host Candidates:
	// Addresses from a loopback interface MUST NOT be included in the candidate addresses.
	// [...]
	// If gathering one or more host candidates that correspond to an IPv6 address that was
	// generated using a mechanism that prevents location tracking [RFC7721], host candidates
	// that correspond to IPv6 addresses that do allow location tracking, are configured on the
	// same interface, and are part of the same network prefix MUST NOT be gathered. Similarly,
	// when host candidates corresponding to an IPv6 address generated using a mechanism that
	// prevents location tracking are gathered, then host candidates corresponding to IPv6
	// link-local addresses [RFC4291] MUST NOT be gathered. The IPv6 default address selection
	// specification [RFC6724] specifies that temporary addresses [RFC4941] are to be preferred
	// over permanent addresses.

	// IPv6 IIDs generated by modern systems are opaque so there is no way to reliably differentiate
	// privacy-enabled IPv6 addresses here. Therefore, we hope the preferred addresses are listed
	// first, and we never list link-local addresses.

	addr_record_t *current = records;
	addr_record_t *end = records + count;
	int ret = 0;

#if defined(JUICE_ENABLE_LOCALHOST_ADDRESS) && JUICE_ENABLE_LOCALHOST_ADDRESS
	// Add localhost for test purposes
	addr_record_t local;
	if (bound.addr.ss_family == AF_INET6 && udp_get_local_addr(sock, AF_INET6, &local) == 0) {
		++ret;
		if (current != end) {
			*current = local;
			++current;
		}
	}
	if (udp_get_local_addr(sock, AF_INET, &local) == 0) {
		++ret;
		if (current != end) {
			*current = local;
			++current;
		}
	}
#endif

#ifdef _WIN32
	char buf[4096];
	DWORD len = 0;
	if (WSAIoctl(sock, SIO_ADDRESS_LIST_QUERY, NULL, 0, buf, sizeof(buf), &len, NULL, NULL)) {
		JLOG_ERROR("WSAIoctl with SIO_ADDRESS_LIST_QUERY failed, errno=%d", WSAGetLastError());
		return -1;
	}

	SOCKET_ADDRESS_LIST *list = (SOCKET_ADDRESS_LIST *)buf;
	for (int i = 0; i < list->iAddressCount; ++i) {
		struct sockaddr *sa = list->Address[i].lpSockaddr;
		socklen_t len = list->Address[i].iSockaddrLength;
		if ((sa->sa_family == AF_INET ||
		     (sa->sa_family == AF_INET6 && bound.addr.ss_family == AF_INET6)) &&
		    !addr_is_local(sa)) {
			if (!has_duplicate_addr(sa, records, current - records)) {
				++ret;
				if (current != end) {
					memcpy(&current->addr, sa, len);
					current->len = len;
					current->socktype = SOCK_DGRAM;
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

	for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
		unsigned int flags = ifa->ifa_flags;
		if (!(flags & IFF_UP) || (flags & IFF_LOOPBACK))
			continue;
		if (strcmp(ifa->ifa_name, "docker0") == 0)
			continue;

		struct sockaddr *sa = ifa->ifa_addr;
		socklen_t len;
		if (sa &&
		    (sa->sa_family == AF_INET ||
		     (sa->sa_family == AF_INET6 && bound.addr.ss_family == AF_INET6)) &&
		    !addr_is_local(sa) && (len = addr_get_len(sa)) > 0) {
			if (!has_duplicate_addr(sa, records, current - records)) {
				++ret;
				if (current != end) {
					memcpy(&current->addr, sa, len);
					current->len = len;
					current->socktype = SOCK_DGRAM;
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

	if (ioctlsocket(sock, SIOCGIFCONF, &ifc)) {
		JLOG_ERROR("ioctl for SIOCGIFCONF failed, errno=%d", sockerrno);
		return -1;
	}

	bool ifconf_has_inet6 = false;
	int n = ifc.ifc_len / sizeof(struct ifreq);
	for (int i = 0; i < n; ++i) {
		struct ifreq *ifr = ifc.ifc_req + i;
		struct sockaddr *sa = &ifr->ifr_addr;
		if (sa->sa_family == AF_INET6)
			ifconf_has_inet6 = true;

		socklen_t len;
		if ((sa->sa_family == AF_INET ||
		     (sa->sa_family == AF_INET6 && bound.addr.ss_family == AF_INET6)) &&
		    !addr_is_local(sa) && (len = addr_get_len(sa)) > 0) {
			if (!has_duplicate_addr(sa, records, current - records)) {
				++ret;
				if (current != end) {
					memcpy(&current->addr, sa, len);
					current->len = len;
					current->socktype = SOCK_DGRAM;
					addr_set_port((struct sockaddr *)&current->addr, port);
					++current;
				}
			}
		}
	}

	if (!ifconf_has_inet6 && bound.addr.ss_family == AF_INET6) {
		struct sockaddr_in6 sin6;
		if (get_local_default_inet6(port, &sin6) == 0) {
			if (!addr_is_local((const struct sockaddr *)&sin6)) {
				++ret;
				if (current != end) {
					memcpy(&current->addr, &sin6, sizeof(sin6));
					current->len = sizeof(sin6);
					current->socktype = SOCK_DGRAM;
					++current;
				}
			}
		}
	}
#endif
#endif

	return ret;
}
