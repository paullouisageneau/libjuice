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

#ifndef JUICE_H
#define JUICE_H

#include "log.h"

#include <stdbool.h>
#include <stddef.h>

typedef struct juice_agent juice_agent_t;

typedef enum juice_state {
	JUICE_STATE_DISCONNECTED,
	JUICE_STATE_GATHERING,
	JUICE_STATE_CONNECTING,
	JUICE_STATE_CONNECTED,
	JUICE_STATE_COMPLETED,
	JUICE_STATE_FAILED
} juice_state_t;

typedef void (*juice_cb_state_changed_t)(juice_agent_t *agent, int component,
                                         juice_state_t state, void *user_ptr);
typedef void (*juice_cb_candidate_t)(juice_agent_t *agent, int component,
                                     const char *sdp, void *user_ptr);
typedef void (*juice_cb_recv_t)(juice_agent_t *agent, int component,
                                const char *data, size_t size, void *user_ptr);

typedef struct juice_config {
	bool lite;
	juice_cb_state_changed_t cb_state_changed;
	juice_cb_candidate_t cb_candidate;
	juice_cb_recv_t cb_recv;
} juice_config_t;

juice_agent_t *juice_agent_create(const juice_config_t *config);
void juice_agent_destroy(juice_agent_t *agent);

int juice_agent_gather_candidates(juice_agent_t *agent);
const char *juice_agent_get_local_description(juice_agent_t *agent);
int juice_agent_set_remote_description(juice_agent_t *agent, const char *sdp);
int juice_agent_add_remote_candidate(juice_agent_t *agent, const char *sdp);

int juice_agent_send(juice_agent_t *agent, const char *data, size_t size);

#endif

