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

#ifdef WIN32
#include <windows.h>
#elif _POSIX_C_SOURCE >= 199309L
#include <time.h>   // for nanosleep
#else
#include <unistd.h> // for usleep
#endif

void sleep_ms(int milliseconds){
#ifdef WIN32
	Sleep(milliseconds);
#elif _POSIX_C_SOURCE >= 199309L
	struct timespec ts;
	ts.tv_sec = milliseconds / 1000;
	ts.tv_nsec = (milliseconds % 1000) * 1000000;
	nanosleep(&ts, NULL);
#else
	if (milliseconds >= 1000)
	  sleep(milliseconds / 1000);
	usleep((milliseconds % 1000) * 1000);
#endif
}

#define BUFFER_SIZE 1500 // Ethernet MTU
#define PACKET_HISTORY_SIZE 2

// The way this struct is accessed would be a data-race in any concurrency mode other than JUICE_CONCURRENCY_MODE_USER
// since on_recv would be called from a different thread than the one that calls juice_user_poll
typedef struct agent_data {
	int id;
	int received;
	int sent;
	char buffer[PACKET_HISTORY_SIZE][BUFFER_SIZE];
} agent_data_t;

static juice_agent_t *agents[2];
static agent_data_t agent_data[2];


static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr);

static void on_gathering_done(juice_agent_t *agent, void *user_ptr);

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);

int test_user() {
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	memset(&agent_data, 0, sizeof(agent_data));

	// Create agents
	juice_config_t config;
	memset(&config, 0, sizeof(config));
	config.concurrency_mode = JUICE_CONCURRENCY_MODE_USER;
	config.stun_server_host = "stun.l.google.com";
	config.stun_server_port = 19302;
	config.cb_state_changed = NULL;
	config.cb_candidate = on_candidate;
	config.cb_gathering_done = on_gathering_done;
	config.cb_recv = on_recv;

	for (int i = 0; i < sizeof(agents) / sizeof(agents[0]); i++) {
		agent_data[i].id = i + 1;
		config.user_ptr = &agent_data[i];
		agents[i] = juice_create(&config);
	}

	// Agent 1: Generate local description
	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agents[0], sdp1, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 1:\n%s\n", sdp1);

	// Agent 2: Receive description from agent 1
	juice_set_remote_description(agents[1], sdp1);

	// Agent 2: Generate local description
	char sdp2[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agents[1], sdp2, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 2:\n%s\n", sdp2);

	// Agent 1: Receive description from agent 2
	juice_set_remote_description(agents[0], sdp2);

	// Agent 1: Gather candidates (and send them to agent 2)
	juice_gather_candidates(agents[0]);
	juice_gather_candidates(agents[1]);

	int polls = 100;
	int timeout_milliseconds = 4000;
	for (int i = 0; i < polls; i++) {

		bool test_done = true;
		for (size_t i = 0; i < sizeof(agents) / sizeof(agents[0]); ++i) {
			juice_agent_t *agent = agents[i];
			int packet_history_index = agent_data[i].received % 2;
			char *buffer = agent_data[i].buffer[packet_history_index];

			// This next call Dequeues datagrams from the OS and facilitates ICE e.g. candidate gathering, keep-alives, etc.
			// After parsing a packet it will call the associated the callback. If it's a packet sent with juice_send we'll get in
			// in the on_recv callback
			juice_user_poll(agent, buffer, BUFFER_SIZE); 

			juice_state_t state = juice_get_state(agent);
			if (state == JUICE_STATE_CONNECTED) {
				// Send three messages
				while (agent_data[i].sent < 3) {
					char message[50];
					snprintf(message, sizeof(message), "Message %d from Agent %d", agent_data[i].sent + 1, agent_data[i].id);
					juice_send(agent, message, strlen(message));
					agent_data[i].sent++;
				}
			}

			// Most likely we'll get our 3 datagrams since it's a local connection,
			// but in case we don't it's not a failure condition because of UDP reliability
			test_done &= agent_data[i].received == 3;
			test_done &= state == JUICE_STATE_COMPLETED;
		}

		if (test_done)
			break;

		sleep_ms(timeout_milliseconds / polls);
	}

	// -- Connection should be finished --

	// Check states
	juice_state_t state1 = juice_get_state(agents[0]);
	juice_state_t state2 = juice_get_state(agents[1]);
	bool success = (state1 == JUICE_STATE_COMPLETED && state2 == JUICE_STATE_COMPLETED);

	// Agent 1: destroy
	juice_destroy(agents[0]);

	// Agent 2: destroy
	juice_destroy(agents[1]);

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}

// On local candidate gathered
static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	agent_data_t *agent_data = user_ptr;
	printf("Candidate %d: %s\n", agent_data->id, sdp);

	// Receive it from the other agent
	if (agent_data->id == 1)
		juice_add_remote_candidate(agents[1], sdp);
	else
		juice_add_remote_candidate(agents[0], sdp);
}

// On local candidates gathering done
static void on_gathering_done(juice_agent_t *agent, void *user_ptr) {
	agent_data_t *agent_data = user_ptr;
	printf("Gathering done %d\n", agent_data->id);

	// optional
	if (agent_data->id == 1)
		juice_set_remote_gathering_done(agents[1]);
	else
		juice_set_remote_gathering_done(agents[0]);
}

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	agent_data_t *agent_data = user_ptr;
	agent_data->received++;

	char buffer[BUFFER_SIZE];
	if (size > BUFFER_SIZE - 1)
		size = BUFFER_SIZE - 1;
	memcpy(buffer, data, size);
	buffer[size] = '\0';
	printf("Received %d: %s\n", agent_data->id, buffer);
}
