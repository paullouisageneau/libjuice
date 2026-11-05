/**
 * Copyright (c) 2026 moLink contributors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "conn_external.h"
#include "agent.h"
#include "log.h"
#include "thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <ifaddrs.h>
#endif

typedef struct conn_impl {
	mutex_t mutex;
	timestamp_t next_timestamp;
} conn_impl_t;

static bool family_allowed(juice_address_family_t requested, int family) {
	switch (requested) {
	case JUICE_ADDRESS_FAMILY_IPV4:
		return family == AF_INET;
	case JUICE_ADDRESS_FAMILY_IPV6:
		return family == AF_INET6;
	case JUICE_ADDRESS_FAMILY_ANY:
	default:
		return family == AF_INET || family == AF_INET6;
	}
}

static bool has_duplicate_addr(const struct sockaddr *addr, const addr_record_t *records,
                               size_t count) {
	for (size_t i = 0; i < count; ++i) {
		const addr_record_t *record = records + i;
		if (record->addr.ss_family != addr->sa_family)
			continue;

		switch (addr->sa_family) {
		case AF_INET: {
			const struct sockaddr_in *rsin = (const struct sockaddr_in *)&record->addr;
			const struct sockaddr_in *asin = (const struct sockaddr_in *)addr;
			if (memcmp(&rsin->sin_addr, &asin->sin_addr, 4) == 0)
				return true;
			break;
		}
		case AF_INET6: {
			const struct sockaddr_in6 *rsin6 = (const struct sockaddr_in6 *)&record->addr;
			const struct sockaddr_in6 *asin6 = (const struct sockaddr_in6 *)addr;
			if (memcmp(&rsin6->sin6_addr, &asin6->sin6_addr, 8) == 0)
				return true;
			break;
		}
		default:
			break;
		}
	}
	return false;
}

static int add_record(addr_record_t *records, size_t count, size_t *used,
                      const struct sockaddr *addr, socklen_t len, uint16_t port) {
	if (*used > 0 && has_duplicate_addr(addr, records, *used))
		return 0;

	if (*used < count) {
		addr_record_t *record = records + *used;
		memcpy(&record->addr, addr, len);
		record->len = len;
		record->socktype = SOCK_DGRAM;
		addr_unmap_inet6_v4mapped((struct sockaddr *)&record->addr, &record->len);
		addr_set_port((struct sockaddr *)&record->addr, port);
	}
	++*used;
	return 0;
}

static int enumerate_addrs(const juice_external_io_t *io, addr_record_t *records, size_t count) {
	size_t used = 0;

#ifdef _WIN32
	ULONG size = 16 * 1024;
	IP_ADAPTER_ADDRESSES *addresses = (IP_ADAPTER_ADDRESSES *)malloc(size);
	if (!addresses)
		return -1;

	const ULONG flags =
	    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
	ULONG ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, addresses, &size);
	if (ret == ERROR_BUFFER_OVERFLOW) {
		IP_ADAPTER_ADDRESSES *larger = (IP_ADAPTER_ADDRESSES *)realloc(addresses, size);
		if (!larger) {
			free(addresses);
			return -1;
		}
		addresses = larger;
		ret = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, addresses, &size);
	}
	if (ret != NO_ERROR) {
		JLOG_ERROR("GetAdaptersAddresses failed, error=%lu", ret);
		free(addresses);
		return -1;
	}

	for (IP_ADAPTER_ADDRESSES *adapter = addresses; adapter; adapter = adapter->Next) {
		if (adapter->OperStatus != IfOperStatusUp)
			continue;
		for (IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress; unicast;
		     unicast = unicast->Next) {
			struct sockaddr *sa = unicast->Address.lpSockaddr;
			if (!sa || !family_allowed(io->address_family, sa->sa_family) ||
			    addr_is_local(sa))
				continue;
			socklen_t len = addr_get_len(sa);
			if (len > 0)
				add_record(records, count, &used, sa, len, io->local_port);
		}
	}

	free(addresses);
#else
	struct ifaddrs *ifas = NULL;
	if (getifaddrs(&ifas) != 0) {
		JLOG_ERROR("getifaddrs failed, errno=%d", sockerrno);
		return -1;
	}

	for (struct ifaddrs *ifa = ifas; ifa; ifa = ifa->ifa_next) {
		if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK))
			continue;
		if (ifa->ifa_name && strcmp(ifa->ifa_name, "docker0") == 0)
			continue;

		struct sockaddr *sa = ifa->ifa_addr;
		if (!sa || !family_allowed(io->address_family, sa->sa_family) || addr_is_local(sa))
			continue;
		socklen_t len = addr_get_len(sa);
		if (len > 0)
			add_record(records, count, &used, sa, len, io->local_port);
	}

	freeifaddrs(ifas);
#endif

	return (int)used;
}

int conn_external_init(juice_agent_t *agent, conn_registry_t *registry,
                       udp_socket_config_t *config) {
	(void)registry;
	(void)config;

	if (!agent->config.external.sendto) {
		JLOG_FATAL("External mode requires a sendto callback");
		return -1;
	}

	conn_impl_t *conn_impl = calloc(1, sizeof(conn_impl_t));
	if (!conn_impl) {
		JLOG_FATAL("Memory allocation for external connection failed");
		return -1;
	}

	if (mutex_init(&conn_impl->mutex, MUTEX_RECURSIVE) != 0) {
		JLOG_FATAL("Mutex initialization failed");
		free(conn_impl);
		return -1;
	}

	conn_impl->next_timestamp = current_timestamp();
	agent->conn_impl = conn_impl;
	return 0;
}

void conn_external_cleanup(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	if (!conn_impl)
		return;

	mutex_destroy(&conn_impl->mutex);
	free(conn_impl);
	agent->conn_impl = NULL;
}

void conn_external_lock(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	if (conn_impl)
		mutex_lock(&conn_impl->mutex);
}

void conn_external_unlock(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	if (conn_impl)
		mutex_unlock(&conn_impl->mutex);
}

int conn_external_interrupt(juice_agent_t *agent) {
	conn_impl_t *conn_impl = agent->conn_impl;
	if (conn_impl)
		conn_impl->next_timestamp = current_timestamp();
	return 0;
}

int conn_external_send(juice_agent_t *agent, const addr_record_t *dst, const char *data,
                       size_t size, int ds) {
	(void)ds;
	const juice_external_io_t *io = &agent->config.external;
	if (!io->sendto)
		return -1;

	int ret = io->sendto(io->user_ptr, data, size, &dst->addr, (int)dst->len);
	return ret < 0 ? ret : 0;
}

int conn_external_get_addrs(juice_agent_t *agent, addr_record_t *records, size_t size) {
	const juice_external_io_t *io = &agent->config.external;
	if (io->local_port == 0) {
		JLOG_ERROR("External mode requires local_port to build host candidates");
		return -1;
	}

	if (io->local_address && io->local_address[0] != '\0' &&
	    strcmp(io->local_address, "0.0.0.0") != 0 && strcmp(io->local_address, "::") != 0) {
		char service[8];
		snprintf(service, sizeof(service), "%hu", io->local_port);
		int count = addr_resolve(io->local_address, service, SOCK_DGRAM, records, size);
		if (count < 0) {
			JLOG_ERROR("Resolving external local address %s failed", io->local_address);
			return -1;
		}
		return count;
	}

	return enumerate_addrs(io, records, size);
}
