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

static juice_agent_t *agent1;
static juice_agent_t *agent2;

static bool received1;
static bool received2;

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State %s: %s\n", (const char *)user_ptr, juice_state_to_string(state));

	if (state == JUICE_STATE_CONNECTED)
		juice_send(agent, "Hello", 5);
}

static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	juice_add_remote_candidate(agent2, sdp);
}

static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	juice_add_remote_candidate(agent1, sdp);
}

static void on_gathering_done1(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	juice_set_remote_gathering_done(agent2);
}

static void on_gathering_done2(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	juice_set_remote_gathering_done(agent1);
}

static void on_recv1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	(void)agent;
	(void)data;
	(void)size;
	(void)user_ptr;
	received1 = true;
}

static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	(void)agent;
	(void)data;
	(void)size;
	(void)user_ptr;
	received2 = true;
}

static bool report_addresses(juice_agent_t *agent, const char *name) {
	char remote[JUICE_MAX_ADDRESS_STRING_LEN];
	char local[JUICE_MAX_ADDRESS_STRING_LEN];

	if (juice_get_selected_addresses(agent, local, JUICE_MAX_ADDRESS_STRING_LEN, remote,
	                                 JUICE_MAX_ADDRESS_STRING_LEN) != 0)
		return false;

	printf("Local address  %s: %s\n", name, local);
	printf("Remote address %s: %s\n", name, remote);
	return true;
}

int test_pin(void) {
	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	char sdp2[JUICE_MAX_SDP_STRING_LEN];
	juice_config_t config1;
	juice_config_t config2;
	juice_state_t state1;
	juice_state_t state2;
	bool success;

	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	memset(&config1, 0, sizeof(config1));
	config1.pin_local_address = true;
	config1.cb_state_changed = on_state_changed;
	config1.cb_candidate = on_candidate1;
	config1.cb_gathering_done = on_gathering_done1;
	config1.cb_recv = on_recv1;
	config1.user_ptr = (void *)"1";
	agent1 = juice_create(&config1);

	memset(&config2, 0, sizeof(config2));
	config2.pin_local_address = true;
	config2.cb_state_changed = on_state_changed;
	config2.cb_candidate = on_candidate2;
	config2.cb_gathering_done = on_gathering_done2;
	config2.cb_recv = on_recv2;
	config2.user_ptr = (void *)"2";
	agent2 = juice_create(&config2);

	juice_get_local_description(agent1, sdp1, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 1:\n%s\n", sdp1);
	juice_set_remote_description(agent2, sdp1);

	juice_get_local_description(agent2, sdp2, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 2:\n%s\n", sdp2);
	juice_set_remote_description(agent1, sdp2);

	juice_gather_candidates(agent1);
	sleep(2);

	juice_gather_candidates(agent2);
	sleep(2);

	state1 = juice_get_state(agent1);
	state2 = juice_get_state(agent2);
	success = state1 == JUICE_STATE_COMPLETED && state2 == JUICE_STATE_COMPLETED;
	success &= received1 && received2;
	success &= report_addresses(agent1, "1");
	success &= report_addresses(agent2, "2");

	juice_destroy(agent1);
	juice_destroy(agent2);

	if (!success) {
		printf("Failure\n");
		return -1;
	}

	printf("Success\n");
	return 0;
}
