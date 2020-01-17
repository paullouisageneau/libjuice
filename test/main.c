/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "juice/juice.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define BUFFER_SIZE 4096

juice_agent_t *agent1;
juice_agent_t *agent2;

void on_state_changed1(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State 1: %s\n", juice_state_to_string(state));
	if (state == JUICE_STATE_CONNECTED) {
		const char *message = "Hello from 1";
		juice_send(agent, message, strlen(message));
	}
}

void on_state_changed2(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State 2: %s\n", juice_state_to_string(state));
	if (state == JUICE_STATE_CONNECTED) {
		const char *message = "Hello from 2";
		juice_send(agent, message, strlen(message));
	}
}

void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	printf("Candidate 1: %s\n", sdp);
	juice_add_remote_candidate(agent2, sdp);
}

void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	printf("Candidate 2: %s\n", sdp);
	juice_add_remote_candidate(agent1, sdp);
}

void on_gathering_done1(juice_agent_t *agent, void *user_ptr) { printf("Gathering done 1\n"); }

void on_gathering_done2(juice_agent_t *agent, void *user_ptr) { printf("Gathering done 2\n"); }

void on_recv1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	char buffer[BUFFER_SIZE];
	if (size > BUFFER_SIZE - 1)
		size = BUFFER_SIZE - 1;
	memcpy(buffer, data, size);
	buffer[size] = '\0';
	printf("Received 1: %s\n", buffer);
}

void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	char buffer[BUFFER_SIZE];
	if (size > BUFFER_SIZE - 1)
		size = BUFFER_SIZE - 1;
	memcpy(buffer, data, size);
	buffer[size] = '\0';
	printf("Received 2: %s\n", buffer);
}

int main(int argc, char **argv) {
	juice_set_log_level(JUICE_LOG_LEVEL_VERBOSE);

	juice_config_t config1;
	// config1.stun_server_host = "stun.l.google.com";
	// config1.stun_server_port = 19302;
	config1.cb_state_changed = on_state_changed1;
	config1.cb_candidate = on_candidate1;
	config1.cb_gathering_done = on_gathering_done1;
	config1.cb_recv = on_recv1;
	config1.user_ptr = NULL;
	agent1 = juice_create(&config1);

	juice_config_t config2;
	// config2.stun_server_host = "stun.l.google.com";
	// config2.stun_server_port = 19302;
	config2.cb_state_changed = on_state_changed2;
	config2.cb_candidate = on_candidate2;
	config2.cb_gathering_done = on_gathering_done2;
	config2.cb_recv = on_recv2;
	config2.user_ptr = NULL;
	agent2 = juice_create(&config2);

	char sdp1[BUFFER_SIZE];
	juice_get_local_description(agent1, sdp1, BUFFER_SIZE);
	printf("Local description 1:\n%s\n", sdp1);

	juice_set_remote_description(agent2, sdp1);

	char sdp2[BUFFER_SIZE];
	juice_get_local_description(agent2, sdp2, BUFFER_SIZE);
	printf("Local description 2:\n%s\n", sdp2);

	juice_set_remote_description(agent1, sdp2);

	juice_gather_candidates(agent1);
	sleep(2);
	juice_gather_candidates(agent2);
	sleep(4);

	char local[256];
	char remote[256];
	if (juice_get_selected_addresses(agent1, local, 256, remote, 256) == 0) {
		printf("Local address  1: %s\r\n", local);
		printf("Remote address 1: %s\r\n", remote);
	}
	if (juice_get_selected_addresses(agent2, local, 256, remote, 256) == 0) {
		printf("Local address  2: %s\r\n", local);
		printf("Remote address 2: %s\r\n", remote);
	}

	juice_destroy(agent1);
	juice_destroy(agent2);
	sleep(2);
	return 0;
}
