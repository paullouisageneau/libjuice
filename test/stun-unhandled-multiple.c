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

static juice_agent_t *localAgent;
static juice_agent_t *remoteAgent;
static bool success1;
static bool success2;

void stun_unhandled_multiple_callback1 (const juice_mux_binding_request_t *info, void *user_ptr) {
	success1 = true;
}

void stun_unhandled_multiple_callback2 (const juice_mux_binding_request_t *info, void *user_ptr) {
	success2 = true;
}

int test_stun_unhandled_multiple() {
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	uint16_t port = 60000;

	// Generate local description
	char * localSdp = "a=ice-ufrag:G4DJ\n\
a=ice-pwd:ok3ytD4tG2MCJ+9MrELhjO\n\
a=candidate:1 1 UDP 2130706431 127.0.0.1 60000 typ host\n\
a=candidate:2 1 UDP 2130706431 127.0.0.1 60001 typ host\n\
a=end-of-candidates\n\
a=ice-options:ice2\n\
";

	// Set up callbacks
	if (juice_mux_listen("127.0.0.1", port, &stun_unhandled_multiple_callback1, NULL)) {
		printf("Did not register first unhandled mux callback\n");
		printf("Failure\n");
		return -1;
	}

	if (juice_mux_listen("127.0.0.1", port + 1, &stun_unhandled_multiple_callback2, NULL)) {
		printf("Did not register second unhandled mux callback\n");
		printf("Failure\n");
		return -1;
	}

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

	// -- Should have invoked both callbacks with STUN bind info --

	// Destroy remote agent
	juice_destroy(remoteAgent);

	// Unhandle mux listeners
	if (juice_mux_listen("127.0.0.1", port, NULL, NULL)) {
		printf("Did not unregister first unhandled mux callback\n");
		printf("Failure\n");
		return -1;
	}

	if (juice_mux_listen("127.0.0.1", port + 1, NULL, NULL)) {
		printf("Did not unregister second unhandled mux callback\n");
		printf("Failure\n");
		return -1;
	}

	if (success1 && success2) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}
