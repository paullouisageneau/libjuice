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

void on_state_changed1(juice_agent_t *agent, juice_state_t state,
                       void *user_ptr) {}

void on_state_changed2(juice_agent_t *agent, juice_state_t state,
                       void *user_ptr) {}

void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	printf("Candidate 1: %s\n", sdp);
	juice_add_remote_candidate(agent2, sdp);
}

void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	printf("Candidate 2: %s\n", sdp);
	juice_add_remote_candidate(agent1, sdp);
}

void on_recv1(juice_agent_t *agent, const char *data, size_t size,
              void *user_ptr) {}

void on_recv2(juice_agent_t *agent, const char *data, size_t size,
              void *user_ptr) {}

int main(int argc, char **argv) {
	juice_set_log_level(JUICE_LOG_LEVEL_VERBOSE);

	juice_config_t config1;
	config1.is_lite = false;
	config1.is_controlling = true;
	config1.cb_state_changed = on_state_changed1;
	config1.cb_candidate = on_candidate1;
	config1.cb_recv = on_recv1;
	config1.user_ptr = NULL;
	agent1 = juice_create(&config1);

	juice_config_t config2;
	config2.is_lite = false;
	config2.is_controlling = false;
	config2.cb_state_changed = on_state_changed2;
	config2.cb_candidate = on_candidate2;
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

	juice_destroy(agent1);
	juice_destroy(agent2);
	sleep(2);
	return 0;
}
