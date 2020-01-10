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

#include "ice.h"
#include "log.h"
#include "socket.h" // for sockaddr stuff

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 4096

const char *skip_prefix(const char *str, const char *prefix) {
	size_t len = strlen(prefix);
	return strncmp(str, prefix, len) == 0 ? str + len : str;
}

int sdp_parse_candidate(const char *line, juice_candidate_t *candidate) {
	line = skip_prefix(line, "a=");
	line = skip_prefix(line, "candidate:");

	char transport[32 + 1];
	char type[32 + 1];
	if (sscanf(line, "%32s %u %32s %u %1024s %32s typ %32s",
	           candidate->foundation, &candidate->component, transport,
	           &candidate->priority, candidate->hostname, candidate->service,
	           type) != 7) {
		JLOG_WARN("Failed to parse candidate: %s", line);
		return -1;
	}

	if (strcmp(transport, "UDP") != 0 || strcmp(transport, "udp") != 0) {
		JLOG_INFO("Ignoring candidate with transport %s", transport);
		return -1;
	}

	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICHOST | AI_NUMERICSERV;
	struct addrinfo *aiList = NULL;
	if (getaddrinfo(candidate->hostname, candidate->service, &hints, &aiList)) {
		JLOG_INFO("Failed to resolve address %s:%s", candidate->hostname,
		          candidate->service);
		return 0;
	}

	for (struct addrinfo *ai = aiList; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
			candidate->resolved.len = ai->ai_addrlen;
			memcpy(&candidate->resolved.addr, ai->ai_addr, ai->ai_addrlen);
			break;
		}
	}

	freeaddrinfo(aiList);
	return 0;
}
