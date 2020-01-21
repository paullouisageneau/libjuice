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

#include "crc32.h"
#include "juice/juice.h"
#include "stun.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // for sleep

#define BUFFER_SIZE 4096

juice_agent_t *agent1;
juice_agent_t *agent2;

void on_state_changed1(juice_agent_t *agent, juice_state_t state, void *user_ptr);
void on_state_changed2(juice_agent_t *agent, juice_state_t state, void *user_ptr);
void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr);
void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr);
void on_gathering_done1(juice_agent_t *agent, void *user_ptr);
void on_gathering_done2(juice_agent_t *agent, void *user_ptr);
void on_recv1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);
void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);

int main(int argc, char **argv) {

	// Basic unit tests

	juice_set_log_level(JUICE_LOG_LEVEL_WARN);

	const char *test_crc32 = "The quick brown fox jumps over the lazy dog";
	if (crc32(test_crc32, strlen(test_crc32)) != 0x414fa339) {
		printf("CRC32 implementation check failed\n");
		return -2;
	}

	uint8_t test_message[] = {
	    0x00, 0x01, 0x00, 0x58, // Request type and message length
	    0x21, 0x12, 0xa4, 0x42, // Magic cookie
	    0xb7, 0xe7, 0xa7, 0x01, // Transaction ID
	    0xbc, 0x34, 0xd6, 0x86, //
	    0xfa, 0x87, 0xdf, 0xae, //
	    0x80, 0x22, 0x00, 0x10, // SOFTWARE attribute header
	    0x53, 0x54, 0x55, 0x4e, //
	    0x20, 0x74, 0x65, 0x73, //
	    0x74, 0x20, 0x63, 0x6c, //
	    0x69, 0x65, 0x6e, 0x74, //
	    0x00, 0x24, 0x00, 0x04, // PRIORITY attribute header
	    0x6e, 0x00, 0x01, 0xff, //
	    0x80, 0x29, 0x00, 0x08, // ICE-CONTROLLED attribute header
	    0x93, 0x2f, 0xf9, 0xb1, //
	    0x51, 0x26, 0x3b, 0x36, //
	    0x00, 0x06, 0x00, 0x09, // USERNAME attribute header
	    0x65, 0x76, 0x74, 0x6a, //
	    0x3a, 0x68, 0x36, 0x76, //
	    0x59, 0x20, 0x20, 0x20, //
	    0x00, 0x08, 0x00, 0x14, // MESSAGE-INTEGRITY attribute header
	    0x9a, 0xea, 0xa7, 0x0c, //
	    0xbf, 0xd8, 0xcb, 0x56, //
	    0x78, 0x1e, 0xf2, 0xb5, //
	    0xb2, 0xd3, 0xf2, 0x49, //
	    0xc1, 0xb5, 0x71, 0xa2, //
	    0x80, 0x28, 0x00, 0x04, // FINGERPRINT attribute header
	    0xe5, 0x7a, 0x3b, 0xcf, //
	};
	stun_message_t msg;
	strcpy(msg.username, "evtj:h6vY");
	msg.password = "VOkJxbRl1RmTxUk/WvJxBt";
	if (stun_read(test_message, sizeof(test_message), &msg) <= 0) {
		printf("STUN parsing implementation check failed\n");
		return -2;
	}

	// Connectivity test

	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	juice_config_t config1;
	memset(&config1, 0, sizeof(config1));
	// config1.stun_server_host = "stun.l.google.com";
	// config1.stun_server_port = 19302;
	config1.cb_state_changed = on_state_changed1;
	config1.cb_candidate = on_candidate1;
	config1.cb_gathering_done = on_gathering_done1;
	config1.cb_recv = on_recv1;
	config1.user_ptr = NULL;
	agent1 = juice_create(&config1);

	juice_config_t config2;
	memset(&config2, 0, sizeof(config2));
	// config2.stun_server_host = "stun.l.google.com";
	// config2.stun_server_port = 19302;
	config2.cb_state_changed = on_state_changed2;
	config2.cb_candidate = on_candidate2;
	config2.cb_gathering_done = on_gathering_done2;
	config2.cb_recv = on_recv2;
	config2.user_ptr = NULL;
	agent2 = juice_create(&config2);

	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent1, sdp1, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 1:\n%s\n", sdp1);

	juice_set_remote_description(agent2, sdp1);

	char sdp2[JUICE_MAX_ADDRESS_STRING_LEN];
	juice_get_local_description(agent2, sdp2, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 2:\n%s\n", sdp2);

	juice_set_remote_description(agent1, sdp2);

	juice_gather_candidates(agent1);
	sleep(2);
	juice_gather_candidates(agent2);
	sleep(4);

	bool success = juice_get_state(agent1) == JUICE_STATE_COMPLETED &&
	               juice_get_state(agent2) == JUICE_STATE_COMPLETED;

	char local[JUICE_MAX_ADDRESS_STRING_LEN];
	char remote[JUICE_MAX_ADDRESS_STRING_LEN];
	if (success &= (juice_get_selected_addresses(agent1, local, JUICE_MAX_ADDRESS_STRING_LEN,
	                                             remote, JUICE_MAX_ADDRESS_STRING_LEN) == 0)) {
		printf("Local address  1: %s\n", local);
		printf("Remote address 1: %s\n", remote);
	}
	if (success &= (juice_get_selected_addresses(agent2, local, JUICE_MAX_ADDRESS_STRING_LEN,
	                                             remote, JUICE_MAX_ADDRESS_STRING_LEN) == 0)) {
		printf("Local address  2: %s\n", local);
		printf("Remote address 2: %s\n", remote);
	}

	juice_destroy(agent1);
	juice_destroy(agent2);
	sleep(2);

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}

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

void on_gathering_done1(juice_agent_t *agent, void *user_ptr) {
	printf("Gathering done 1\n");
	juice_set_remote_gathering_done(agent2); // optional
}

void on_gathering_done2(juice_agent_t *agent, void *user_ptr) {
	printf("Gathering done 2\n");
	juice_set_remote_gathering_done(agent1); // optional
}

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
