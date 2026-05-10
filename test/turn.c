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
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
static void sleep(unsigned int secs) { Sleep(secs * 1000); }
static void sleep_ms(int ms) { Sleep((DWORD)ms); }
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
static void sleep_ms(int ms) { usleep((useconds_t)(ms * 1000)); }
#endif

#define BUFFER_SIZE 4096

static juice_agent_t *agent1;
static juice_agent_t *agent2;

static void on_state_changed1(juice_agent_t *agent, juice_state_t state, void *user_ptr);
static void on_state_changed2(juice_agent_t *agent, juice_state_t state, void *user_ptr);

static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr);

static void on_gathering_done1(juice_agent_t *agent, void *user_ptr);
static void on_gathering_done2(juice_agent_t *agent, void *user_ptr);

static void on_recv1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);
static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);

int test_turn() {
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	const char *turn_host = getenv("TURN_HOST2");
	const char *turn_port_str = getenv("TURN_PORT2");
	const char *turn_username = getenv("TURN_USERNAME2");
	const char *turn_password = getenv("TURN_PASSWORD2");

	if (!turn_host || !turn_port_str || !turn_username || !turn_password) {
		printf("TURN_HOST, TURN_PORT, TURN_USERNAME, and TURN_PASSWORD must be set\n");
		return 0;
	}

	// Agent 1: Create agent
	juice_config_t config1;
	memset(&config1, 0, sizeof(config1));

	config1.stun_server_host = turn_host;
	config1.stun_server_port = (uint16_t)atoi(turn_port_str);

	juice_turn_server_t turn_server;
	memset(&turn_server, 0, sizeof(turn_server));
	turn_server.host = turn_host;
	turn_server.port = (uint16_t)atoi(turn_port_str);
	turn_server.username = turn_username;
	turn_server.password = turn_password;
	config1.turn_servers = &turn_server;
	config1.turn_servers_count = 1;

	config1.cb_state_changed = on_state_changed1;
	config1.cb_candidate = on_candidate1;
	config1.cb_gathering_done = on_gathering_done1;
	config1.cb_recv = on_recv1;
	config1.user_ptr = NULL;

	agent1 = juice_create(&config1);

	// Agent 2: Create agent
	juice_config_t config2;
	memset(&config2, 0, sizeof(config2));

	config2.stun_server_host = turn_host;
	config2.stun_server_port = (uint16_t)atoi(turn_port_str);

	config2.cb_state_changed = on_state_changed2;
	config2.cb_candidate = on_candidate2;
	config2.cb_gathering_done = on_gathering_done2;
	config2.cb_recv = on_recv2;
	config2.user_ptr = NULL;

	agent2 = juice_create(&config2);

	// Agent 1: Generate local description
	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent1, sdp1, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 1:\n%s\n", sdp1);

	// Agent 2: Receive description from agent 1
	juice_set_remote_description(agent2, sdp1);

	// Agent 2: Generate local description
	char sdp2[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent2, sdp2, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 2:\n%s\n", sdp2);

	// Agent 1: Receive description from agent 2
	juice_set_remote_description(agent1, sdp2);

	// Agent 1: Gather candidates (and send them to agent 2)
	juice_gather_candidates(agent1);
	sleep(2);

	// Agent 2: Gather candidates (and send them to agent 1)
	juice_gather_candidates(agent2);
	sleep(5);

	// -- Connection should be finished --

	// Check states
	juice_state_t state1 = juice_get_state(agent1);
	juice_state_t state2 = juice_get_state(agent2);
	bool success = ((state1 == JUICE_STATE_COMPLETED || state1 == JUICE_STATE_CONNECTED) &&
	                (state2 == JUICE_STATE_CONNECTED || state2 == JUICE_STATE_COMPLETED));

	// Retrieve candidates
	char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	char remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	if (success &=
	    (juice_get_selected_candidates(agent1, local, JUICE_MAX_CANDIDATE_SDP_STRING_LEN, remote,
	                                   JUICE_MAX_CANDIDATE_SDP_STRING_LEN) == 0)) {
		printf("Local candidate  1: %s\n", local);
		printf("Remote candidate 1: %s\n", remote);

		success &= (strstr(local, "relay") != NULL);
	}
	if (success &=
	    (juice_get_selected_candidates(agent2, local, JUICE_MAX_CANDIDATE_SDP_STRING_LEN, remote,
	                                   JUICE_MAX_CANDIDATE_SDP_STRING_LEN) == 0)) {
		printf("Local candidate  2: %s\n", local);
		printf("Remote candidate 2: %s\n", remote);

		success &= (strstr(remote, "relay") != NULL);
	}

	// Retrieve addresses
	char localAddr[JUICE_MAX_ADDRESS_STRING_LEN];
	char remoteAddr[JUICE_MAX_ADDRESS_STRING_LEN];
	if (success &= (juice_get_selected_addresses(agent1, localAddr, JUICE_MAX_ADDRESS_STRING_LEN,
	                                             remoteAddr, JUICE_MAX_ADDRESS_STRING_LEN) == 0)) {
		printf("Local address  1: %s\n", localAddr);
		printf("Remote address 1: %s\n", remoteAddr);
	}
	if (success &= (juice_get_selected_addresses(agent2, localAddr, JUICE_MAX_ADDRESS_STRING_LEN,
	                                             remoteAddr, JUICE_MAX_ADDRESS_STRING_LEN) == 0)) {
		printf("Local address  2: %s\n", localAddr);
		printf("Remote address 2: %s\n", remoteAddr);
	}

	// Agent 1: destroy
	juice_destroy(agent1);

	// Agent 2: destroy
	juice_destroy(agent2);

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}

// Agent 1: on state changed
static void on_state_changed1(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State 1: %s\n", juice_state_to_string(state));

	if (state == JUICE_STATE_CONNECTED) {
		// Agent 1: on connected, send a message
		const char *message = "Hello from 1";
		juice_send(agent, message, strlen(message));
	}
}

// Agent 2: on state changed
static void on_state_changed2(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State 2: %s\n", juice_state_to_string(state));
	if (state == JUICE_STATE_CONNECTED) {
		// Agent 2: on connected, send a message
		const char *message = "Hello from 2";
		juice_send(agent, message, strlen(message));
	}
}

// Agent 1: on local candidate gathered
static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	// Filter relayed candidates
	if (!strstr(sdp, "relay"))
		return;

	printf("Candidate 1: %s\n", sdp);

	// Agent 2: Receive it from agent 1
	juice_add_remote_candidate(agent2, sdp);
}

// Agent 2: on local candidate gathered
static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	// Filter server reflexive candidates
	if (!strstr(sdp, "srflx")) {
		printf("Filter out candidate 2: %s\n", sdp);
		return;
	}

	printf("Candidate 2: %s\n", sdp);

	// Agent 1: Receive it from agent 2
	juice_add_remote_candidate(agent1, sdp);
}

// Agent 1: on local candidates gathering done
static void on_gathering_done1(juice_agent_t *agent, void *user_ptr) {
	printf("Gathering done 1\n");
	juice_set_remote_gathering_done(agent2); // optional
}

// Agent 2: on local candidates gathering done
static void on_gathering_done2(juice_agent_t *agent, void *user_ptr) {
	printf("Gathering done 2\n");
	juice_set_remote_gathering_done(agent1); // optional
}

// Agent 1: on message received
static void on_recv1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	char buffer[BUFFER_SIZE];
	if (size > BUFFER_SIZE - 1)
		size = BUFFER_SIZE - 1;
	memcpy(buffer, data, size);
	buffer[size] = '\0';
	printf("Received 1: %s\n", buffer);
}

// Agent 2: on message received
static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	char buffer[BUFFER_SIZE];
	if (size > BUFFER_SIZE - 1)
		size = BUFFER_SIZE - 1;
	memcpy(buffer, data, size);
	buffer[size] = '\0';
	printf("Received 2: %s\n", buffer);
}

// ---------------------------------------------------------------------------
// test_turn_tcp_fail
//
// When a TURN TCP connection is refused, the relay STUN entry was not marked
// FAILED, blocking the ICE state machine.  The fix detects the failure via
// conn_turn_tcp_failed() and immediately fails the entry.
//
// Test strategy:
//   • Both agents use ONLY a TURN TCP server pointing at a port with no
//     listener (immediate ECONNREFUSED).
//   • Without the fix the agents would stay in CONNECTING forever because
//     the relay entry keeps spinning and no STUN Allocate is ever sent.
//   • With the fix the relay entry is marked FAILED quickly, no pairs are
//     formed, and both agents reach FAILED within a few seconds.
// ---------------------------------------------------------------------------

// Bind to port 0 and immediately close — any later TCP connect gets ECONNREFUSED.
static int find_refused_tcp_port(void) {
	struct sockaddr_in addr;
#ifdef _WIN32
	int len = (int)sizeof(addr);
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET) return 19998;
#else
	socklen_t len = (socklen_t)sizeof(addr);
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) return 19998;
#endif
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
	    getsockname(sock, (struct sockaddr *)&addr, &len) != 0) {
#ifdef _WIN32
		closesocket(sock);
#else
		close(sock);
#endif
		return 19998;
	}
	int port = ntohs(addr.sin_port);
#ifdef _WIN32
	closesocket(sock);
#else
	close(sock);
#endif
	return port;
}

typedef struct {
	juice_agent_t *agent1;
	juice_agent_t *agent2;
	volatile juice_state_t state1;
	volatile juice_state_t state2;
	volatile bool gathering_done1;
	volatile bool gathering_done2;
} ttf_ctx_t;

static void ttf_on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	ttf_ctx_t *ctx = (ttf_ctx_t *)user_ptr;
	if (agent == ctx->agent1)
		ctx->state1 = state;
	else
		ctx->state2 = state;
	printf("TURN-TCP-fail state: %s\n", juice_state_to_string(state));
}

static void ttf_on_gathering_done(juice_agent_t *agent, void *user_ptr) {
	ttf_ctx_t *ctx = (ttf_ctx_t *)user_ptr;
	if (agent == ctx->agent1) {
		printf("TURN-TCP-fail: gathering done 1\n");
		ctx->gathering_done1 = true;
		juice_set_remote_gathering_done(ctx->agent2);
	} else {
		printf("TURN-TCP-fail: gathering done 2\n");
		ctx->gathering_done2 = true;
		juice_set_remote_gathering_done(ctx->agent1);
	}
}

int test_turn_tcp_fail(void) {
	int refused_port = find_refused_tcp_port();
	printf("Using refused TCP port %d\n", refused_port);

	ttf_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));

	juice_turn_server_t turn_server;
	memset(&turn_server, 0, sizeof(turn_server));
	turn_server.host = "127.0.0.1";
	turn_server.port = (uint16_t)refused_port;
	turn_server.username = "test";
	turn_server.password = "test";

	juice_config_t config;
	memset(&config, 0, sizeof(config));
	config.cb_state_changed = ttf_on_state_changed;
	config.cb_gathering_done = ttf_on_gathering_done;
	config.user_ptr = &ctx;

	ctx.agent1 = juice_create(&config);
	ctx.agent2 = juice_create(&config);
	juice_add_turn_server_tcp(ctx.agent1, &turn_server);
	juice_add_turn_server_tcp(ctx.agent2, &turn_server);

	// Exchange local descriptions so ICE credentials are shared
	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	char sdp2[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(ctx.agent1, sdp1, sizeof(sdp1));
	juice_get_local_description(ctx.agent2, sdp2, sizeof(sdp2));
	juice_set_remote_description(ctx.agent2, sdp1);
	juice_set_remote_description(ctx.agent1, sdp2);

	juice_gather_candidates(ctx.agent1);
	juice_gather_candidates(ctx.agent2);

	// Wait up to 8 s for both gathering_done callbacks to fire.
	//
	// This is the key observable difference between the broken and fixed cases:
	//   Without fix: the relay STUN entry spins in PENDING forever; gathering_done
	//                is never called for either agent.
	//   With fix:    conn_turn_tcp_failed() is detected on the next bookkeeping
	//                tick; the relay entry is immediately marked FAILED and
	//                agent_update_gathering_done() fires within ~2 s.
	//
	// Note: reaching JUICE_STATE_FAILED would require the PAC timer
	// (ICE_PAC_TIMEOUT = ~40 s, RFC 8863), which is too slow for a unit test.
	// Verifying that gathering completes is sufficient proof the fix works.
	for (int ms = 0; ms < 8000; ms += 100) {
		sleep_ms(100);
		if (ctx.gathering_done1 && ctx.gathering_done2)
			break;
	}

	bool success = ctx.gathering_done1 && ctx.gathering_done2 &&
	               ctx.state1 != JUICE_STATE_COMPLETED &&
	               ctx.state2 != JUICE_STATE_COMPLETED;

	printf("Gathering done: %d/%d, states: %s/%s\n",
	       (int)ctx.gathering_done1, (int)ctx.gathering_done2,
	       juice_state_to_string(ctx.state1), juice_state_to_string(ctx.state2));

	juice_destroy(ctx.agent1);
	juice_destroy(ctx.agent2);

	if (success) {
		printf("Success\n");
		return 0;
	}
	printf("Failure: gathering_done not received within 8 seconds after TURN TCP refused\n");
	return -1;
}
