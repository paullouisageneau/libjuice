/**
 * Copyright (c) 2024 Paul-Louis Ageneau
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

int test_ufrag() {
	juice_agent_t *agent;
	bool success = true;

	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	// Create agent
	juice_config_t config;
	memset(&config, 0, sizeof(config));

	// STUN server example
	config.ice_ufrag = "ufrag";
	config.ice_pwd = "pwd";

	agent = juice_create(&config);

	// Generate local description
	char sdp[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent, sdp, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description:\n%s\n", sdp);

	if (strstr(sdp, "a=ice-ufrag:ufrag\r\n") == NULL)
		success = false;

	if (strstr(sdp, "a=ice-pwd:pwd\r\n") == NULL)
		success = false;

	// Destroy
	juice_destroy(agent);

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}
