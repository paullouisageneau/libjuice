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
	int ret;

	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	// Create agent
	juice_config_t config;
	memset(&config, 0, sizeof(config));

	agent = juice_create(&config);

	if (juice_set_local_ice_attributes(agent, NULL, NULL) != JUICE_ERR_INVALID)
		success = false;

	if (juice_set_local_ice_attributes(agent, "ufrag", NULL) != JUICE_ERR_INVALID)
		success = false;

	if (juice_set_local_ice_attributes(agent, NULL, "pw01234567890123456789") != JUICE_ERR_INVALID)
		success = false;

	if (juice_set_local_ice_attributes(agent, "ufrag", "pw0123456789012345678") != JUICE_ERR_INVALID)
		success = false;

	if (juice_set_local_ice_attributes(agent, "usr", "pw01234567890123456789") != JUICE_ERR_INVALID)
		success = false;

	if (juice_set_local_ice_attributes(agent, "ufrag:", "pw01234567890123456789") != JUICE_ERR_INVALID)
		success = false;

	if (juice_set_local_ice_attributes(agent, "ufrag", "pw0123456789012345678?") != JUICE_ERR_INVALID)
		success = false;

	// Set local ICE attributes
	juice_set_local_ice_attributes(agent, "ufrag", "pw01234567890123456789");

	// Generate local description
	char sdp[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent, sdp, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description:\n%s\n", sdp);

	if (strstr(sdp, "a=ice-ufrag:ufrag\r\n") == NULL)
		success = false;

	if (strstr(sdp, "a=ice-pwd:pw01234567890123456789\r\n") == NULL)
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
