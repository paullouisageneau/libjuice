/**
 * Copyright (c) 2022 Paul-Louis Ageneau
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

static juice_agent_t *remoteAgent1;
static juice_agent_t *remoteAgent2;

static bool success;
static bool unhandled;
static bool invokedAfterUnhandle;

void stun_unhandled_unhandle_callback (const juice_mux_binding_request_t *info, void *user_ptr) {
	if (unhandled) {
		invokedAfterUnhandle = true;
	} else {
		success = true;
	}
}

int test_stun_unhandled_unhandle() {
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	uint16_t port = 60004;

	// Generate local description
	char * localSdp = "a=ice-ufrag:G4DJ\n\
a=ice-pwd:ok3ytD4tG2MCJ+9MrELhjO\n\
a=candidate:1 1 UDP 2130706431 127.0.0.1 60004 typ host\n\
a=end-of-candidates\n\
a=ice-options:ice2\n\
";

	// Set up callback
	juice_mux_listen("127.0.0.1", port, &stun_unhandled_unhandle_callback, NULL);

	// Create remote agent
	juice_config_t remoteConfig;
	memset(&remoteConfig, 0, sizeof(remoteConfig));
	remoteConfig.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
	remoteAgent1 = juice_create(&remoteConfig);

	// Remote agent: Receive description from local agent
	juice_set_remote_description(remoteAgent1, localSdp);

	// Remote agent: Gather candidates (and send them to local agent)
	juice_gather_candidates(remoteAgent1);
	sleep(2);

	// -- Should have received unhandled STUN packet(s) --

	// Destroy remote agent
	juice_destroy(remoteAgent1);

	// Remove callback
	juice_mux_listen("127.0.0.1", port, NULL, NULL);
	unhandled = true;

	// Create another remote agent
	juice_config_t remoteConfig2;
	memset(&remoteConfig2, 0, sizeof(remoteConfig));
	remoteConfig2.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
	remoteAgent2 = juice_create(&remoteConfig2);

	// Remote agent: Receive description from local agent
	juice_set_remote_description(remoteAgent2, localSdp);

	// Remote agent: Gather candidates (and send them to local agent)
	juice_gather_candidates(remoteAgent2);
	sleep(2);

	// -- Should only have invoked callback with STUN bind info before unhandle --

	// Destroy remote agent
	juice_destroy(remoteAgent2);

	if (success && !invokedAfterUnhandle) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}
