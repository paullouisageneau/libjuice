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

typedef void (*juice_cb_state_changed_t)(juice_agent_t *agent, juice_state_t state, void *user_ptr);
typedef void (*juice_cb_candidate_t)(juice_agent_t *agent, const char *sdp, void *user_ptr);
typedef void (*juice_cb_recv_t)(juice_agent_t *agent, const char *data, size_t size,
                                void *user_ptr);

typedef struct juice_config {
	const char *stun_server_host;
	unsigned int stun_server_port;
	bool is_controlling;
	juice_cb_state_changed_t cb_state_changed;
	juice_cb_candidate_t cb_candidate;
	juice_cb_recv_t cb_recv;
	void *user_ptr;
} juice_config_t;

juice_agent_t *juice_create(const juice_config_t *config);
void juice_destroy(juice_agent_t *agent);

int juice_gather_candidates(juice_agent_t *agent);
int juice_get_local_description(juice_agent_t *agent, char *buffer, size_t size);
int juice_set_remote_description(juice_agent_t *agent, const char *sdp);
int juice_add_remote_candidate(juice_agent_t *agent, const char *sdp);

int juice_send(juice_agent_t *agent, const char *data, size_t size);

const char *juice_state_to_string(juice_state_t state);

// Logging

typedef enum {
	JUICE_LOG_LEVEL_VERBOSE,
	JUICE_LOG_LEVEL_DEBUG,
	JUICE_LOG_LEVEL_INFO,
	JUICE_LOG_LEVEL_WARN,
	JUICE_LOG_LEVEL_ERROR,
	JUICE_LOG_LEVEL_FATAL
} juice_log_level_t;

void juice_set_log_level(juice_log_level_t level);

#endif
