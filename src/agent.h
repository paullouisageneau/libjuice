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

#ifndef JUICE_AGENT_H
#define JUICE_AGENT_H

#include "ice.h"
#include "juice.h"
#include "socket.h"

#include <pthread.h>
#include <stdbool.h>

struct juice_agent {
	juice_config_t config;
	socket_t sock;
	pthread_t thread;
	ice_description_t local;
	ice_description_t remote;
	bool is_controlling;
};

#endif
