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

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr);
static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);

int test_tcp() {
	juice_set_log_level(JUICE_LOG_LEVEL_VERBOSE);

	juice_config_t config1;
	memset(&config1, 0, sizeof(config1));

	config1.cb_state_changed = on_state_changed;
	config1.cb_recv = on_recv;
	config1.ice_tcp_mode = JUICE_ICE_TCP_MODE_ACTIVE;

	agent = juice_create(&config1);
	if (juice_set_local_ice_attributes(agent, "ufrag", "pw01234567890123456789")) {
	 	printf("Failure\n");
	 	return -1;
	}

	char sdp[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent, sdp, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description:\n%s\n", sdp);

char *remote_description = "a=ice-ufrag:ufrag\r\n"
	"a=ice-pwd:pw01234567890123456789\r\n"
	"a=candidate:1 1 TCP 2122316799 192.168.1.93 8443 typ host\r\n";

	juice_set_remote_description(agent, remote_description);
	juice_gather_candidates(agent);
	sleep(2);

	bool success = juice_get_state(agent) == JUICE_STATE_COMPLETED;

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

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
 	printf("State: %s\n", juice_state_to_string(state));
}

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
}
