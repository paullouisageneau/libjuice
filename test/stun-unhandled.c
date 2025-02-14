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
static bool callbackInvoked;

void stun_unhandled_callback (const juice_mux_binding_request_t *info, void *user_ptr) {
	callbackInvoked = true;
}

int test_stun_unhandled() {
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	uint16_t port = 60000;

	// Generate local description
	const char * localSdp = "a=ice-ufrag:G4DJ\n\
a=ice-pwd:ok3ytD4tG2MCJ+9MrELhjO\n\
a=candidate:1 1 UDP 2130706431 127.0.0.1 60000 typ host\n\
a=end-of-candidates\n\
a=ice-options:ice2\n\
";

	// Set up callback
	if (juice_mux_listen("127.0.0.1", port, &stun_unhandled_callback, NULL)) {
		printf("Did not register unhandled mux callback\n");
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

	// -- Should have received unhandled STUN packet(s) --

	// Destroy remote agent
	juice_destroy(remoteAgent);

	// Unhandle mux listener
	if (juice_mux_listen("127.0.0.1", port, NULL, NULL)) {
		printf("Did not unregister unhandled mux callback\n");
		printf("Failure\n");
		return -1;
	}

	if (callbackInvoked) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}
