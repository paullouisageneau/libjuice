/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "juice/juice.h"

#include "stun.h"
#include "thread.h"
#include "tcp.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static void sleep(unsigned int secs) { Sleep(secs * 1000); }
#else
#include <unistd.h> // for sleep
#endif

#define ICE_TCP_SERVER_BUFFER_SIZE 150
#define ICE_PWD "pw01234567890123456789"

mutex_t local_gathered_ice_tcp_candidate_mutex = MUTEX_INITIALIZER;
bool local_gathered_ice_tcp_candidate = false;

static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	if (strstr(sdp, "9 typ host tcptype active")) {
		mutex_lock(&local_gathered_ice_tcp_candidate_mutex);
		local_gathered_ice_tcp_candidate = true;
		mutex_unlock(&local_gathered_ice_tcp_candidate_mutex);
	}
}

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State: %s\n", juice_state_to_string(state));
}

socket_t start_ice_tcp_server(int ice_tcp_server_port) {
	socket_t server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket == -1) {
		return INVALID_SOCKET;
	}

	struct sockaddr_in server_sockaddr;
	memset(&server_sockaddr, 0, sizeof(server_sockaddr));
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_sockaddr.sin_port = htons(ice_tcp_server_port);

	if ((bind(server_socket, (const struct sockaddr *)&server_sockaddr, sizeof(server_sockaddr))) != 0) {
		return INVALID_SOCKET;
	}

	if (listen(server_socket, 1) != 0) {
		return INVALID_SOCKET;
	}

	return server_socket;
}

void run_passive_ice_tcp(socket_t server_socket) {
	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));

	socket_t client_socket = accept(server_socket, NULL, NULL);
	uint16_t ice_tcp_len = 0;
	int n;
	char server_buffer[ICE_TCP_SERVER_BUFFER_SIZE];
	for (int i = 0; i < 2;) {
		if ((n = _juice_tcp_ice_read(client_socket, server_buffer, ICE_TCP_SERVER_BUFFER_SIZE, &ice_tcp_len)) == -1) {
			return;
		} else if (n == 0) {
			continue;
		}


		if (_juice_stun_read(server_buffer, n, &msg)  == -1) {
			return;
		}

		if (msg.msg_class != STUN_CLASS_REQUEST) {
			continue;
		}

		msg.msg_class = STUN_CLASS_RESP_SUCCESS;
		msg.msg_method = STUN_METHOD_BINDING;
		msg.priority = 0;
		msg.ice_controlling = 0;

		if ((n = _juice_stun_write(server_buffer, ICE_TCP_SERVER_BUFFER_SIZE, &msg, ICE_PWD)) == -1) {
			return;
		}

		if (_juice_tcp_ice_write(client_socket, server_buffer, n) == -1) {
			return;
		}

		i++;
	}

	closesocket(server_socket);
}

int test_tcp() {
	juice_set_log_level(JUICE_LOG_LEVEL_VERBOSE);

	juice_config_t config;
	memset(&config, 0, sizeof(config));

	config.cb_state_changed = on_state_changed;
	config.cb_candidate = on_candidate;

	juice_agent_t *agent = juice_create(&config);
	if (juice_set_local_ice_attributes(agent, "ufrag", "pw01234567890123456789")) {
		printf("Failure\n");
		return -1;
	}

	if (juice_set_ice_tcp_mode(agent, JUICE_ICE_TCP_MODE_ACTIVE)) {
		printf("Failure\n");
		return -1;
	}

	srand((unsigned int)time(NULL));
	int ice_tcp_server_port = (rand() % (6000 - 5000 + 1)) + 5000;
	socket_t server_socket = start_ice_tcp_server(ice_tcp_server_port);
	if (server_socket == INVALID_SOCKET) {
		printf("Failure\n");
		return -1;
	}

	char sdp[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent, sdp, JUICE_MAX_SDP_STRING_LEN);

	snprintf(sdp, JUICE_MAX_SDP_STRING_LEN,
	         "a=ice-ufrag:ufrag\r\n"
	         "a=ice-pwd:%s\r\n"
	         "a=candidate:1 1 TCP 2122316799 127.0.0.1 %d typ host tcptype passive\r\n"
	         "a=candidate:2 1 TCP 3122316799 127.0.0.1 %d typ host tcptype so\r\n"
	         "a=candidate:3 1 TCP 4122316799 127.0.0.1 0  typ host tcptype active\r\n",
	         ICE_PWD, ice_tcp_server_port + 2, ice_tcp_server_port);

	juice_set_remote_description(agent, sdp);
	juice_gather_candidates(agent);

	run_passive_ice_tcp(server_socket);
	sleep(2);

	mutex_lock(&local_gathered_ice_tcp_candidate_mutex);
	bool success = juice_get_state(agent) == JUICE_STATE_COMPLETED && local_gathered_ice_tcp_candidate;
	mutex_unlock(&local_gathered_ice_tcp_candidate_mutex);

	// Agent destroy
	juice_destroy(agent);

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}

