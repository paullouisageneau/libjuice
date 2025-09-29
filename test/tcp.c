/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "juice/juice.h"

#include "stun.h"
#include "tcp.h"
#include "thread.h"

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

#define STUN_WRITE_BUFFER_SIZE 150
#define ICE_PWD "pw01234567890123456789"

atomic(bool) local_gathered_ice_tcp_candidate = false;

static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	if (strstr(sdp, "9 typ host tcptype active")) {
		atomic_store(&local_gathered_ice_tcp_candidate, true);
	}
}

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State: %s\n", juice_state_to_string(state));
}

socket_t start_ice_tcp_server(int ice_tcp_server_port) {
	socket_t server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket == INVALID_SOCKET)
		return INVALID_SOCKET;

	struct sockaddr_in server_sockaddr;
	memset(&server_sockaddr, 0, sizeof(server_sockaddr));
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_sockaddr.sin_port = htons(ice_tcp_server_port);

	if ((bind(server_socket, (const struct sockaddr *)&server_sockaddr, sizeof(server_sockaddr))) !=
	    0)
		goto error;

	if (listen(server_socket, 1) != 0)
		goto error;

	return server_socket;

error:
	closesocket(server_socket);
	return INVALID_SOCKET;
}

void run_passive_ice_tcp(socket_t server_socket) {
	socket_t client_socket = accept(server_socket, NULL, NULL);
	if(client_socket == INVALID_SOCKET)
		return;

	tcp_ice_read_context_t read_context;
	memset(&read_context, 0, sizeof(read_context));

	tcp_ice_write_context_t write_context;
	memset(&write_context, 0, sizeof(write_context));

	for (int i = 0; i < 2;) {
		int len;
		if ((len = _juice_tcp_ice_read(client_socket, &read_context)) < 0)
			return;

		if (len == 0)
			continue;

		stun_message_t msg;
		memset(&msg, 0, sizeof(msg));

		if (_juice_stun_read(read_context.buffer, len, &msg) < 0)
			return;

		if (msg.msg_class != STUN_CLASS_REQUEST)
			continue;

		msg.msg_class = STUN_CLASS_RESP_SUCCESS;
		msg.msg_method = STUN_METHOD_BINDING;
		msg.priority = 0;
		msg.ice_controlling = 0;

		char buffer[STUN_WRITE_BUFFER_SIZE];
		if ((len = _juice_stun_write(buffer, STUN_WRITE_BUFFER_SIZE, &msg, ICE_PWD)) < 0)
			return;

		if (_juice_tcp_ice_write(client_socket, buffer, len, &write_context) < 0)
			return;

		i++;
	}

	closesocket(server_socket);
}

int test_tcp() {
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
	         "a=candidate:3 1 TCP 4122316799 127.0.0.1 9 typ host tcptype active\r\n",
	         ICE_PWD, ice_tcp_server_port + 2, ice_tcp_server_port);

	juice_set_remote_description(agent, sdp);
	juice_gather_candidates(agent);

	run_passive_ice_tcp(server_socket);
	sleep(2);

	bool success = juice_get_state(agent) == JUICE_STATE_COMPLETED &&
	               atomic_load(&local_gathered_ice_tcp_candidate);

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

static juice_agent_t *agent1;
static juice_agent_t *agent2;

static void on_candidate_bad_tcp_1(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	juice_add_remote_candidate(agent2, sdp);
}

static void on_candidate_bad_tcp_2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	juice_add_remote_candidate(agent1, sdp);
}

int test_tcp_bad_candidate() {
	juice_config_t config1;
	memset(&config1, 0, sizeof(config1));

	config1.cb_candidate = on_candidate_bad_tcp_1;
	config1.user_ptr = NULL;

	agent1 = juice_create(&config1);

	juice_config_t config2;
	memset(&config2, 0, sizeof(config2));

	config1.cb_candidate = on_candidate_bad_tcp_2;
	config2.user_ptr = NULL;

	agent2 = juice_create(&config2);

	if (juice_set_ice_tcp_mode(agent1, JUICE_ICE_TCP_MODE_ACTIVE) || juice_set_ice_tcp_mode(agent2, JUICE_ICE_TCP_MODE_ACTIVE)) {
		printf("Failure\n");
		return -1;
	}

	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent1, sdp1, JUICE_MAX_SDP_STRING_LEN);
	juice_set_remote_description(agent2, sdp1);

	char sdp2[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent2, sdp2, JUICE_MAX_SDP_STRING_LEN);
	juice_set_remote_description(agent1, sdp2);

	// Candidate that doesn't exist
	juice_add_remote_candidate(agent1, "a=candidate:1 1 TCP 2122316799 127.0.0.1 1337 typ host tcptype passive");

	juice_gather_candidates(agent1);
	sleep(2);

	juice_gather_candidates(agent2);
	sleep(2);

	bool success = (juice_get_state(agent1) == JUICE_STATE_COMPLETED && juice_get_state(agent2) == JUICE_STATE_COMPLETED);

	juice_destroy(agent1);
	juice_destroy(agent2);

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}

