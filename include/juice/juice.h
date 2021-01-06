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

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define JUICE_EXPORT __declspec(dllexport)
#else
#define JUICE_EXPORT
#endif

// ICE Agent

#define JUICE_MAX_ADDRESS_STRING_LEN 56
#define JUICE_MAX_CANDIDATE_SDP_STRING_LEN 256
#define JUICE_MAX_SDP_STRING_LEN 4096

#define JUICE_ERR_SUCCESS 0
#define JUICE_ERR_INVALID -1   // invalid argument
#define JUICE_ERR_FAILED -2    // runtime error
#define JUICE_ERR_NOT_AVAIL -3 // element not available

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
typedef bool (*juice_cb_filter_candidate_t)(juice_agent_t *agent, const char *sdp, void *user_ptr);
typedef void (*juice_cb_gathering_done_t)(juice_agent_t *agent, void *user_ptr);
typedef void (*juice_cb_recv_t)(juice_agent_t *agent, const char *data, size_t size,
                                void *user_ptr);

typedef struct juice_turn_server {
	const char *host;
	const char *username;
	const char *password;
	uint16_t port;
} juice_turn_server_t;

typedef struct juice_config {
	const char *stun_server_host;
	uint16_t stun_server_port;

	juice_turn_server_t *turn_servers;
	unsigned int turn_servers_count;

	uint16_t local_port_range_begin;
	uint16_t local_port_range_end;

	juice_cb_state_changed_t cb_state_changed;
	juice_cb_candidate_t cb_candidate;
	juice_cb_gathering_done_t cb_gathering_done;
	juice_cb_recv_t cb_recv;
	juice_cb_filter_candidate_t cb_filter_candidate;

	void *user_ptr;

} juice_config_t;

JUICE_EXPORT juice_agent_t *juice_create(const juice_config_t *config);
JUICE_EXPORT void juice_destroy(juice_agent_t *agent);

JUICE_EXPORT int juice_gather_candidates(juice_agent_t *agent);
JUICE_EXPORT int juice_get_local_description(juice_agent_t *agent, char *buffer, size_t size);
JUICE_EXPORT int juice_set_remote_description(juice_agent_t *agent, const char *sdp);
JUICE_EXPORT int juice_add_remote_candidate(juice_agent_t *agent, const char *sdp);
JUICE_EXPORT int juice_set_remote_gathering_done(juice_agent_t *agent);
JUICE_EXPORT int juice_send(juice_agent_t *agent, const char *data, size_t size);
JUICE_EXPORT int juice_send_diffserv(juice_agent_t *agent, const char *data, size_t size, int ds);
JUICE_EXPORT juice_state_t juice_get_state(juice_agent_t *agent);
JUICE_EXPORT int juice_get_selected_candidates(juice_agent_t *agent, char *local, size_t local_size,
                                               char *remote, size_t remote_size);
JUICE_EXPORT int juice_get_selected_addresses(juice_agent_t *agent, char *local, size_t local_size,
                                              char *remote, size_t remote_size);

// Utils

JUICE_EXPORT const char *juice_state_to_string(juice_state_t state);

// Logging

typedef enum {
	JUICE_LOG_LEVEL_VERBOSE,
	JUICE_LOG_LEVEL_DEBUG,
	JUICE_LOG_LEVEL_INFO,
	JUICE_LOG_LEVEL_WARN,
	JUICE_LOG_LEVEL_ERROR,
	JUICE_LOG_LEVEL_FATAL,
	JUICE_LOG_LEVEL_NONE
} juice_log_level_t;

typedef void (*juice_log_cb_t)(juice_log_level_t level, const char *message);

JUICE_EXPORT void juice_set_log_level(juice_log_level_t level);
JUICE_EXPORT void juice_set_log_handler(juice_log_cb_t cb);

#ifdef __cplusplus
}
#endif

#endif
