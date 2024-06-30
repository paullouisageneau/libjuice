/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "juice/juice.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// This is a custom data structure that will be associated with the agent
typedef struct {
	int custom_field1;
	char custom_field2[256];
} custom_data_t;

// This function tests the agent data feature (juice_agent_set_data and juice_agent_get_data)
int test_agent_data() {
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	// Create a basic agent with default configuration
	juice_config_t *juiceConfig = malloc(sizeof(juice_config_t));
	if (!juiceConfig) {
		return -1;
	}

	memset(juiceConfig, 0, sizeof(*juiceConfig));
	juiceConfig->stun_server_host = "stun.l.google.com";
	juiceConfig->stun_server_port = 19302;

	juice_agent_t *agent = juice_create(juiceConfig);
	if (!agent) {
		fprintf(stderr, "Failed to create agent\n");
		free(juiceConfig);
		return -1;
	}

	// Allocate and set custom data
	custom_data_t *customData = malloc(sizeof(custom_data_t));
	if (!customData) {
		fprintf(stderr, "Failed to allocate custom data\n");
		juice_destroy(agent);
		free(juiceConfig);
		return -1;
	}
	customData->custom_field1 = 42;
	strcpy(customData->custom_field2, "Hello, World!");

	// Ensure that get_data returns NULL before set_data
	if (juice_agent_get_data(agent) != NULL) {
		fprintf(stderr, "get_data should return NULL before set_data\n");
		free(customData);
		juice_destroy(agent);
		free(juiceConfig);
		return -1;
	}

	juice_agent_set_data(agent, customData);

	// Retrieve custom data
	const custom_data_t *retrievedData = (custom_data_t*)juice_agent_get_data(agent);
	if (!retrievedData) {
		fprintf(stderr, "Failed to retrieve custom data\n");
		free(customData);
		juice_destroy(agent);
		free(juiceConfig);
		return -1;
	}

	// Validate custom data
	if (retrievedData->custom_field1 != 42 || strcmp(retrievedData->custom_field2, "Hello, World!") != 0) {
		fprintf(stderr, "Custom data validation failed\n");
		free(customData);
		juice_destroy(agent);
		free(juiceConfig);
		return -1;
	}

	// Clean up
	free(customData);
	juice_destroy(agent);
	free(juiceConfig);

	// If all tests passed, return 0
	return 0;
}
