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

#ifndef JUICE_ICE_H
#define JUICE_ICE_H

#include "juice.h"
#include "socket.h"

typedef enum juice_candidate_type {
	JUICE_CANDIDATE_TYPE_HOST,
	JUICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
	JUICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
	JUICE_CANDIDATE_TYPE_RELAYED,
} juice_candidate_type_t;

typedef struct juice_candidate {
	juice_candidate_type_t type;
	unsigned int priority;
	unsigned int component;
	char foundation[32 + 1]; // foundation is composed of 1 to 32 ice-chars
	char transport[32 + 1];
	char hostname[1024 + 1];
	char service[32 + 1];
	struct sockaddr_record resolved;
} juice_candidate_t;

#define JUICE_CANDIDATE_PREF_HOST 120
#define JUICE_CANDIDATE_PREF_PEER_REFLEXIVE 110
#define JUICE_CANDIDATE_PREF_SERVER_REFLEXIVE 100
#define JUICE_CANDIDATE_PREF_RELAYED 30

#endif
