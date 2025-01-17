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

static juice_agent_t *remoteAgent;
static bool success;

void stun_unhandled_callback (const juice_mux_binding_request_t *info, void *user_ptr) {
	success = true;
}

int test_stun_unhandled() {
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	// Generate local description
	char * localSdp = "a=ice-ufrag:G4DJ\n\
a=ice-pwd:ok3ytD4tG2MCJ+9MrELhjO\n\
a=candidate:1 1 UDP 2130706431 127.0.0.1 60001 typ host\n\
a=end-of-candidates\n\
a=ice-options:ice2\n\
";

	// Set up callback
	juice_mux_listen("127.0.0.1", 60001, &stun_unhandled_callback, NULL);

	// Create remote agent
	juice_config_t remoteConfig;
	memset(&remoteConfig, 0, sizeof(remoteConfig));
	remoteConfig.concurrency_mode = JUICE_CONCURRENCY_MODE_MUX;
	remoteAgent = juice_create(&remoteConfig);

	// Remote agent: Receive description from local agent
	juice_set_remote_description(remoteAgent, localSdp);

	// Remote agent: Gather candidates (and send them to local agent)
	juice_gather_candidates(remoteAgent);
	sleep(2);

	// -- Should have received unhandled STUN packet(s) --

	// Destroy remote agent
	juice_destroy(remoteAgent);

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}
