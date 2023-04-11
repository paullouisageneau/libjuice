/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef NO_SERVER

#include "juice/juice.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep(unsigned int secs) { Sleep(secs * 1000); }
#else
#include <unistd.h> // for sleep
#endif

#define BUFFER_SIZE 4096

#define TURN_USERNAME1 "server_test1"
#define TURN_PASSWORD1 "79874638521694"

#define TURN_USERNAME2 "server_test2"
#define TURN_PASSWORD2 "36512189907731"

static juice_server_t *server;
static juice_agent_t *agent1;
static juice_agent_t *agent2;
static bool srflx_success = false;
static bool relay_success = false;
static bool success = false;

static void on_state_changed1(juice_agent_t *agent, juice_state_t state, void *user_ptr);
static void on_state_changed2(juice_agent_t *agent, juice_state_t state, void *user_ptr);

static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr);

static void on_gathering_done1(juice_agent_t *agent, void *user_ptr);
static void on_gathering_done2(juice_agent_t *agent, void *user_ptr);

static void on_recv1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);
static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);

int test_server() {
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	// Create server
	juice_server_credentials_t credentials[1];
	memset(&credentials, 0, sizeof(credentials));
	credentials[0].username = TURN_USERNAME1;
	credentials[0].password = TURN_PASSWORD1;

	juice_server_config_t server_config;
	memset(&server_config, 0, sizeof(server_config));
	server_config.port = 3478;
	server_config.credentials = credentials;
	server_config.credentials_count = 1;
	server_config.max_allocations = 100;
	server_config.realm = "Juice test server";
	server = juice_server_create(&server_config);

	if(juice_server_get_port(server) != 3478) {
		printf("juice_server_get_port failed\n");
		juice_server_destroy(server);
		return -1;
	}

	// Added credentials example
	juice_server_credentials_t added_credentials[1];
	memset(&added_credentials, 0, sizeof(added_credentials));
	added_credentials[0].username = TURN_USERNAME2;
	added_credentials[0].password = TURN_PASSWORD2;
	juice_server_add_credentials(server, added_credentials, 60000); // 60s

	// Agent 1: Create agent
	juice_config_t config1;
	memset(&config1, 0, sizeof(config1));

	// Set STUN server
	config1.stun_server_host = "localhost";
	config1.stun_server_port = 3478;

	// Set TURN server
	juice_turn_server_t turn_server1;
	memset(&turn_server1, 0, sizeof(turn_server1));
	turn_server1.host = "localhost";
	turn_server1.port = 3478;
	turn_server1.username = TURN_USERNAME1;
	turn_server1.password = TURN_PASSWORD1;
	config1.turn_servers = &turn_server1;
	config1.turn_servers_count = 1;

	config1.cb_state_changed = on_state_changed1;
	config1.cb_candidate = on_candidate1;
	config1.cb_gathering_done = on_gathering_done1;
	config1.cb_recv = on_recv1;
	config1.user_ptr = NULL;

	agent1 = juice_create(&config1);

	// Agent 2: Create agent
	juice_config_t config2;
	memset(&config2, 0, sizeof(config2));

	// Set STUN server
	config2.stun_server_host = "localhost";
	config2.stun_server_port = 3478;

	// Set TURN server
	juice_turn_server_t turn_server2;
	memset(&turn_server2, 0, sizeof(turn_server2));
	turn_server2.host = "localhost";
	turn_server2.port = 3478;
	turn_server2.username = TURN_USERNAME2;
	turn_server2.password = TURN_PASSWORD2;
	config2.turn_servers = &turn_server2;
	config2.turn_servers_count = 1;

	config2.cb_state_changed = on_state_changed2;
	config2.cb_candidate = on_candidate2;
	config2.cb_gathering_done = on_gathering_done2;
	config2.cb_recv = on_recv2;
	config2.user_ptr = NULL;

	agent2 = juice_create(&config2);

	// Agent 1: Generate local description
	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent1, sdp1, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 1:\n%s\n", sdp1);

	// Agent 2: Receive description from agent 1
	juice_set_remote_description(agent2, sdp1);

	// Agent 2: Generate local description
	char sdp2[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent2, sdp2, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 2:\n%s\n", sdp2);

	// Agent 1: Receive description from agent 2
	juice_set_remote_description(agent1, sdp2);

	// Agent 1: Gather candidates (and send them to agent 2)
	juice_gather_candidates(agent1);
	sleep(2);

	// Agent 2: Gather candidates (and send them to agent 1)
	juice_gather_candidates(agent2);
	sleep(2);

	// -- Connection should be finished --

	// Agent 1: destroy
	juice_destroy(agent1);

	// Agent 2: destroy
	juice_destroy(agent2);

	// Destroy server
	juice_server_destroy(server);

	if (srflx_success && relay_success && success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}

// Agent 1: on state changed
static void on_state_changed1(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State 1: %s\n", juice_state_to_string(state));

	if (state == JUICE_STATE_CONNECTED) {
		// Agent 1: on connected, send a message
		const char *message = "Hello from 1";
		juice_send(agent, message, strlen(message));
	}
}

// Agent 2: on state changed
static void on_state_changed2(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State 2: %s\n", juice_state_to_string(state));
	if (state == JUICE_STATE_CONNECTED) {
		// Agent 2: on connected, send a message
		const char *message = "Hello from 2";
		juice_send(agent, message, strlen(message));
	}
}

// Agent 1: on local candidate gathered
static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	printf("Candidate 1: %s\n", sdp);

	// Success if a valid srflx candidate is emitted
	if (strstr(sdp, " typ srflx raddr 0.0.0.0 rport 0"))
		srflx_success = true;

	// Success if a valid relay candidate is emitted
	if (strstr(sdp, " typ relay raddr 0.0.0.0 rport 0"))
		relay_success = true;

	// Filter relayed candidates
	if (!strstr(sdp, "relay"))
		return;

	// Agent 2: Receive it from agent 1
	juice_add_remote_candidate(agent2, sdp);
}

// Agent 2: on local candidate gathered
static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	printf("Candidate 2: %s\n", sdp);

	// Success if a valid srflx candidate is emitted
	if (strstr(sdp, " typ srflx raddr 0.0.0.0 rport 0"))
		srflx_success = true;

	// Success if a valid relay candidate is emitted
	if (strstr(sdp, " typ relay raddr 0.0.0.0 rport 0"))
		relay_success = true;

	// Filter relayed candidates
	if (!strstr(sdp, "relay"))
		return;

	// Agent 1: Receive it from agent 2
	juice_add_remote_candidate(agent1, sdp);
}

// Agent 1: on local candidates gathering done
static void on_gathering_done1(juice_agent_t *agent, void *user_ptr) {
	printf("Gathering done 1\n");
	juice_set_remote_gathering_done(agent2); // optional
}

// Agent 2: on local candidates gathering done
static void on_gathering_done2(juice_agent_t *agent, void *user_ptr) {
	printf("Gathering done 2\n");
	juice_set_remote_gathering_done(agent1); // optional
}

// Agent 1: on message received
static void on_recv1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	char buffer[BUFFER_SIZE];
	if (size > BUFFER_SIZE - 1)
		size = BUFFER_SIZE - 1;
	memcpy(buffer, data, size);
	buffer[size] = '\0';
	printf("Received 1: %s\n", buffer);
	success = true;
}

// Agent 2: on message received
static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	char buffer[BUFFER_SIZE];
	if (size > BUFFER_SIZE - 1)
		size = BUFFER_SIZE - 1;
	memcpy(buffer, data, size);
	buffer[size] = '\0';
	printf("Received 2: %s\n", buffer);
	success = true;
}

#endif // ifndef NO_SERVER
