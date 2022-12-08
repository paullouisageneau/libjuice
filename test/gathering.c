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

static juice_agent_t *agent;
static bool srflx_success = false;
static bool relay_success = false;
static bool done = false;

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr);
static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_gathering_done(juice_agent_t *agent, void *user_ptr);

int test_gathering() {
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	// Create agent
	juice_config_t config;
	memset(&config, 0, sizeof(config));

	// STUN server example (use your own server in production)
	config.stun_server_host = "stun.stunprotocol.org";
	config.stun_server_port = 3478;

	// TURN server example (use your own server in production)
	juice_turn_server_t turn_server;
	memset(&turn_server, 0, sizeof(turn_server));
	turn_server.host = "openrelay.metered.ca";
	turn_server.port = 80;
	turn_server.username = "openrelayproject";
	turn_server.password = "openrelayproject";
	config.turn_servers = &turn_server;
	config.turn_servers_count = 1;

	config.cb_state_changed = on_state_changed;
	config.cb_candidate = on_candidate;
	config.cb_gathering_done = on_gathering_done;
	config.user_ptr = NULL;

	agent = juice_create(&config);

	// Generate local description
	char sdp[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent, sdp, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description:\n%s\n", sdp);

	// Gather candidates
	juice_gather_candidates(agent);

	// Wait until gathering done
	int secs = 10;
	while (secs-- && !done && !(srflx_success && relay_success))
		sleep(1);

	// Destroy
	juice_destroy(agent);

	// Sleep so we can check destruction went well
	sleep(2);

	if (srflx_success && relay_success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}

// On state changed
static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State: %s\n", juice_state_to_string(state));
}

// On local candidate gathered
static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	printf("Candidate: %s\n", sdp);

	// Success if a valid srflx candidate is emitted
	if (strstr(sdp, " typ srflx raddr 0.0.0.0 rport 0"))
		srflx_success = true;

	// Success if a valid relay candidate is emitted
	if (strstr(sdp, " typ relay raddr 0.0.0.0 rport 0"))
		relay_success = true;
}

// On local candidates gathering done
static void on_gathering_done(juice_agent_t *agent, void *user_ptr) {
	printf("Gathering done\n");

	done = true;
}
