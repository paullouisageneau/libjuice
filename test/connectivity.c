/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

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

static juice_agent_t *agent1;
static juice_agent_t *agent2;

static void on_state_changed1(juice_agent_t *agent, juice_state_t state, void *user_ptr);
static void on_state_changed2(juice_agent_t *agent, juice_state_t state, void *user_ptr);

static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr);

static void on_gathering_done1(juice_agent_t *agent, void *user_ptr);
static void on_gathering_done2(juice_agent_t *agent, void *user_ptr);

static void on_recv1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);
static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);

int test_connectivity() {
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	// Agent 1: Create agent
	juice_config_t config1;
	memset(&config1, 0, sizeof(config1));

	// STUN server example
	config1.stun_server_host = "stun.l.google.com";
	config1.stun_server_port = 19302;

	config1.cb_state_changed = on_state_changed1;
	config1.cb_candidate = on_candidate1;
	config1.cb_gathering_done = on_gathering_done1;
	config1.cb_recv = on_recv1;
	config1.user_ptr = NULL;

	agent1 = juice_create(&config1);

	// Agent 2: Create agent
	juice_config_t config2;
	memset(&config2, 0, sizeof(config2));

	// STUN server example
	config2.stun_server_host = "stun.l.google.com";
	config2.stun_server_port = 19302;

	// Port range example
	config2.local_port_range_begin = 60000;
	config2.local_port_range_end = 61000;

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

	// Check states
	juice_state_t state1 = juice_get_state(agent1);
	juice_state_t state2 = juice_get_state(agent2);
	bool success = (state1 == JUICE_STATE_COMPLETED && state2 == JUICE_STATE_COMPLETED);

	// Retrieve candidates
	char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	char remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	if (success &=
	    (juice_get_selected_candidates(agent1, local, JUICE_MAX_CANDIDATE_SDP_STRING_LEN, remote,
	                                   JUICE_MAX_CANDIDATE_SDP_STRING_LEN) == 0)) {
		printf("Local candidate  1: %s\n", local);
		printf("Remote candidate 1: %s\n", remote);
		if ((!strstr(local, "typ host") && !strstr(local, "typ prflx")) ||
		    (!strstr(remote, "typ host") && !strstr(remote, "typ prflx")))
			success = false; // local connection should be possible
	}
	if (success &=
	    (juice_get_selected_candidates(agent2, local, JUICE_MAX_CANDIDATE_SDP_STRING_LEN, remote,
	                                   JUICE_MAX_CANDIDATE_SDP_STRING_LEN) == 0)) {
		printf("Local candidate  2: %s\n", local);
		printf("Remote candidate 2: %s\n", remote);
		if ((!strstr(local, "typ host") && !strstr(local, "typ prflx")) ||
		    (!strstr(remote, "typ host") && !strstr(remote, "typ prflx")))
			success = false; // local connection should be possible
	}

	// Retrieve addresses
	char localAddr[JUICE_MAX_ADDRESS_STRING_LEN];
	char remoteAddr[JUICE_MAX_ADDRESS_STRING_LEN];
	if (success &= (juice_get_selected_addresses(agent1, localAddr, JUICE_MAX_ADDRESS_STRING_LEN,
	                                             remoteAddr, JUICE_MAX_ADDRESS_STRING_LEN) == 0)) {
		printf("Local address  1: %s\n", localAddr);
		printf("Remote address 1: %s\n", remoteAddr);
	}
	if (success &= (juice_get_selected_addresses(agent2, localAddr, JUICE_MAX_ADDRESS_STRING_LEN,
	                                             remoteAddr, JUICE_MAX_ADDRESS_STRING_LEN) == 0)) {
		printf("Local address  2: %s\n", localAddr);
		printf("Remote address 2: %s\n", remoteAddr);
	}

	// Agent 1: destroy
	juice_destroy(agent1);

	// Agent 2: destroy
	juice_destroy(agent2);

	if (success) {
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

	// Agent 2: Receive it from agent 1
	juice_add_remote_candidate(agent2, sdp);
}

// Agent 2: on local candidate gathered
static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	printf("Candidate 2: %s\n", sdp);

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
}

// Agent 2: on message received
static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	char buffer[BUFFER_SIZE];
	if (size > BUFFER_SIZE - 1)
		size = BUFFER_SIZE - 1;
	memcpy(buffer, data, size);
	buffer[size] = '\0';
	printf("Received 2: %s\n", buffer);
}
