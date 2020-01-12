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
#include "random.h"
#include "socket.h" // for sockaddr stuff

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 1024

static const char *skip_prefix(const char *str, const char *prefix) {
	size_t len = strlen(prefix);
	return strncmp(str, prefix, len) == 0 ? str + len : str;
}

static bool match_prefix(const char *str, const char *prefix,
                         const char **end) {
	*end = skip_prefix(str, prefix);
	return *end != str || !*prefix;
}

static int parse_sdp_line(const char *line, ice_description_t *description) {
	const char *arg;
	if (match_prefix(line, "a=ice-ufrag:", &arg)) {
		sscanf(arg, "%256s", description->ice_ufrag);
		return 0;
	}
	if (match_prefix(line, "a=ice-pwd:", &arg)) {
		sscanf(arg, "%256s", description->ice_pwd);
		return 0;
	}
	ice_candidate_t candidate;
	if (ice_parse_candidate_sdp(line, &candidate) == 0) {
		ice_add_candidate(&candidate, description);
		return 0;
	}
	return -1;
}

static int parse_sdp_candidate(const char *line, ice_candidate_t *candidate) {
	memset(candidate, 0, sizeof(*candidate));

	line = skip_prefix(line, "a=");
	line = skip_prefix(line, "candidate:");

	char transport[32 + 1];
	char type[32 + 1];
	if (sscanf(line, "%32s %u %32s %u %256s %32s typ %32s",
	           candidate->foundation, &candidate->component, transport,
	           &candidate->priority, candidate->hostname, candidate->service,
	           type) != 7) {
		JLOG_WARN("Failed to parse candidate: %s", line);
		return -1;
	}

	if (strcmp(type, "host") == 0)
		candidate->type = ICE_CANDIDATE_TYPE_HOST;
	else if (strcmp(type, "srflx") == 0)
		candidate->type = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
	else if (strcmp(type, "relay") == 0)
		candidate->type = ICE_CANDIDATE_TYPE_RELAYED;
	else {
		JLOG_WARN("Ignoring candidate with unknow type \"%s\"", type);
		return -1;
	}

	if (strcmp(transport, "UDP") != 0 || strcmp(transport, "udp") != 0) {
		JLOG_INFO("Ignoring candidate with transport \"%s\"", transport);
		return -1;
	}

	return 0;
}

static uint32_t compute_candidate_priority(ice_candidate_type_t type,
                                           int component, int addr_family) {
	uint32_t pref = 0;
	switch (type) {
	case ICE_CANDIDATE_TYPE_HOST:
		pref += ICE_CANDIDATE_PREF_HOST;
		break;
	case ICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
		pref += ICE_CANDIDATE_PREF_PEER_REFLEXIVE;
		break;
	case ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
		pref += ICE_CANDIDATE_PREF_SERVER_REFLEXIVE;
		break;
	case ICE_CANDIDATE_TYPE_RELAYED:
		pref += ICE_CANDIDATE_PREF_RELAYED;
		break;
	default:
		break;
	}

	pref <<= 16;
	// TODO: intermingling between IP families
	switch (addr_family) {
	case AF_INET6:
		pref += 65535;
		break;
	case AF_INET:
		pref += 32767;
		break;
	default:
		break;
	}

	pref <<= 8;
	if (component < 1)
		component = 1;
	if (component > 256)
		component = 256;
	pref += 256 - component;
	return pref;
}

int ice_parse_sdp(const char *sdp, ice_description_t *description) {
	memset(description, 0, sizeof(*description));

	char buffer[BUFFER_SIZE];
	size_t size = 0;
	while (*sdp) {
		if (*sdp == '\n') {
			if (size) {
				buffer[size++] = '\0';
				parse_sdp_line(buffer, description);
				size = 0;
			}
		} else if (*sdp != '\r' && size + 1 < BUFFER_SIZE) {
			buffer[size++] = *sdp;
		}
		++sdp;
	}
	if (*description->ice_ufrag && *description->ice_pwd)
		return 0;
	else
		return -1;
}

int ice_parse_candidate_sdp(const char *line, ice_candidate_t *candidate) {
	const char *arg;
	if (match_prefix(line, "a=candidate:", &arg)) {
		if (parse_sdp_candidate(line, candidate) < 0)
			return -1;
		ice_resolve_candidate(candidate, ICE_RESOLVE_MODE_SIMPLE);
		return 0;
	}
	return -1;
}

int ice_create_local_description(ice_description_t *description) {
	memset(description, 0, sizeof(*description));
	juice_random_str64(description->ice_ufrag, 4 + 1);
	juice_random_str64(description->ice_pwd, 22 + 1);
	description->candidates_count = 0;
	return 0;
}

int ice_create_local_candidate(ice_candidate_type_t type, int component,
                               const struct sockaddr_record *record,
                               ice_candidate_t *candidate) {
	memset(candidate, 0, sizeof(*candidate));
	candidate->type = type;
	candidate->component = component;
	candidate->priority =
	    compute_candidate_priority(type, component, record->addr.ss_family);
	candidate->resolved = *record;
	snprintf(candidate->foundation, 32 + 1, "%u", (unsigned int)type + 1);

	if (getnameinfo((struct sockaddr *)&record->addr, record->len,
	                candidate->hostname, 256, candidate->service, 32,
	                NI_NUMERICHOST | NI_NUMERICSERV | NI_DGRAM)) {
		JLOG_ERROR("getnameinfo failed");
		return -1;
	}
	return 0;
}

int ice_resolve_candidate(ice_candidate_t *candidate, ice_resolve_mode_t mode) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG;
	if (mode != ICE_RESOLVE_MODE_LOOKUP)
		hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
	struct addrinfo *ai_list = NULL;
	if (getaddrinfo(candidate->hostname, candidate->service, &hints,
	                &ai_list)) {
		JLOG_INFO("Failed to resolve address: %s:%s", candidate->hostname,
		          candidate->service);
		candidate->resolved.len = 0;
		return -1;
	}

	for (struct addrinfo *ai = ai_list; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6) {
			candidate->resolved.len = ai->ai_addrlen;
			memcpy(&candidate->resolved.addr, ai->ai_addr, ai->ai_addrlen);
			break;
		}
	}

	freeaddrinfo(ai_list);
	return 0;
}

int ice_add_candidate(const ice_candidate_t *candidate,
                      ice_description_t *description) {
	// TODO: sanity checks
	if (description->candidates_count < ICE_MAX_CANDIDATES_COUNT) {
		memcpy(description->candidates + description->candidates_count,
		       candidate, sizeof(*candidate));
		++description->candidates_count;
	}
	return 0;
}

int ice_generate_sdp(const ice_description_t *description, char *buffer,
                     size_t size) {
	if (!*description->ice_ufrag || !*description->ice_pwd)
		return -1;

	size_t len = 0;
	char *begin = buffer;
	char *end = begin + size;

	// Round 0 is for the description, round i with i>0 is for candidate i-1
	for (size_t i = 0; i < description->candidates_count + 1; ++i) {
		int ret;
		if (i == 0) {
			ret = snprintf(begin, end - begin,
			               "a=ice-ufrag:%s\r\na=ice-pwd:%s\r\n",
			               description->ice_ufrag, description->ice_pwd);
		} else {
			char buffer[BUFFER_SIZE];
			if (ice_generate_candidate_sdp(description->candidates + i - 1,
			                               buffer, BUFFER_SIZE) < 0)
				continue;
			ret = snprintf(begin, end - begin, "%s\r\n", buffer);
		}
		if (ret < 0)
			return -1;
		len += ret;
		begin += ret < end - begin - 1 ? ret : end - begin - 1;
	}
	return len;
}

int ice_generate_candidate_sdp(const ice_candidate_t *candidate, char *buffer,
                               size_t size) {
	const char *type;
	switch (candidate->type) {
	case ICE_CANDIDATE_TYPE_HOST:
		type = "host";
		break;
	case ICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
		type = "prflx";
		break;
	case ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
		type = "srflx";
		break;
	case ICE_CANDIDATE_TYPE_RELAYED:
		type = "relay";
		break;
	default:
		JLOG_ERROR("Unknown candidate type");
		return -1;
	}

	return snprintf(buffer, size, "%s %u UDP %u %s %s typ %s",
	                candidate->foundation, candidate->component,
	                candidate->priority, candidate->hostname,
	                candidate->service, type);
}
