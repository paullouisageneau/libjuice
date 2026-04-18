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
#include <windows.h>
static void sleep_ms(int ms) { Sleep(ms); }
#else
#include <unistd.h>
static void sleep_ms(int ms) { usleep(ms * 1000); }
#endif

#define SEND_COUNT 20
#define SEND_SIZE_MIN 100
#define SEND_SIZE_MAX 1200
#define POLL_MS 100
#define TIMEOUT_GATHER_MS 10000
#define TIMEOUT_CONNECT_MS 30000

typedef struct {
	juice_agent_t *agent1;
	juice_agent_t *agent2;
	volatile int gathering_done1;
	volatile int gathering_done2;
	volatile juice_state_t state1;
	volatile juice_state_t state2;
	volatile int recv_count1;
	volatile int recv_count2;
} test_ctx_t;

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	test_ctx_t *ctx = (test_ctx_t *)user_ptr;
	int id = (agent == ctx->agent1) ? 1 : 2;
	if (id == 1)
		ctx->state1 = state;
	else
		ctx->state2 = state;
	printf("State %d: %s\n", id, juice_state_to_string(state));
	if (state == JUICE_STATE_CONNECTED) {
		char buf[SEND_SIZE_MAX];
		for (int i = 0; i < SEND_COUNT; ++i) {
			int size = SEND_SIZE_MIN +
			           i * (SEND_SIZE_MAX - SEND_SIZE_MIN) / (SEND_COUNT - 1);
			memset(buf, 'A' + id - 1, size);
			juice_send(agent, buf, size);
		}
	}
}

static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	test_ctx_t *ctx = (test_ctx_t *)user_ptr;
	if (!strstr(sdp, "typ relay")) return;
	printf("Candidate 1 (relay): %s\n", sdp);
	juice_add_remote_candidate(ctx->agent2, sdp);
}

static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	test_ctx_t *ctx = (test_ctx_t *)user_ptr;
	if (!strstr(sdp, "typ relay")) return;
	printf("Candidate 2 (relay): %s\n", sdp);
	juice_add_remote_candidate(ctx->agent1, sdp);
}

static void on_gathering_done1(juice_agent_t *agent, void *user_ptr) {
	test_ctx_t *ctx = (test_ctx_t *)user_ptr;
	printf("Gathering done 1\n");
	ctx->gathering_done1 = 1;
	juice_set_remote_gathering_done(ctx->agent2);
}

static void on_gathering_done2(juice_agent_t *agent, void *user_ptr) {
	test_ctx_t *ctx = (test_ctx_t *)user_ptr;
	printf("Gathering done 2\n");
	ctx->gathering_done2 = 1;
	juice_set_remote_gathering_done(ctx->agent1);
}

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	test_ctx_t *ctx = (test_ctx_t *)user_ptr;
	if (agent == ctx->agent1) {
		printf("Received 1: %zu bytes\n", size);
		++ctx->recv_count1;
	} else {
		printf("Received 2: %zu bytes\n", size);
		++ctx->recv_count2;
	}
}

static int run_relay_test(const char *name,
                          const juice_turn_server_t *server1, bool is_tcp1,
                          const juice_turn_server_t *server2, bool is_tcp2,
                          juice_concurrency_mode_t mode) {
	printf("\n=== %s ===\n", name);

	test_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));

	juice_config_t config1;
	memset(&config1, 0, sizeof(config1));
	config1.concurrency_mode = mode;
	config1.cb_state_changed = on_state_changed;
	config1.cb_candidate = on_candidate1;
	config1.cb_gathering_done = on_gathering_done1;
	config1.cb_recv = on_recv;
	config1.user_ptr = &ctx;

	juice_config_t config2;
	memset(&config2, 0, sizeof(config2));
	config2.concurrency_mode = mode;
	config2.cb_state_changed = on_state_changed;
	config2.cb_candidate = on_candidate2;
	config2.cb_gathering_done = on_gathering_done2;
	config2.cb_recv = on_recv;
	config2.user_ptr = &ctx;

	ctx.agent1 = juice_create(&config1);
	ctx.agent2 = juice_create(&config2);
	if (is_tcp1) juice_add_turn_server_tcp(ctx.agent1, server1);
	else         juice_add_turn_server(ctx.agent1, server1);
	if (is_tcp2) juice_add_turn_server_tcp(ctx.agent2, server2);
	else         juice_add_turn_server(ctx.agent2, server2);

	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(ctx.agent1, sdp1, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 1:\n%s\n", sdp1);
	juice_set_remote_description(ctx.agent2, sdp1);

	char sdp2[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(ctx.agent2, sdp2, JUICE_MAX_SDP_STRING_LEN);
	printf("Local description 2:\n%s\n", sdp2);
	juice_set_remote_description(ctx.agent1, sdp2);

	juice_gather_candidates(ctx.agent1);
	for (int t = 0; t < TIMEOUT_GATHER_MS && !ctx.gathering_done1; t += POLL_MS)
		sleep_ms(POLL_MS);

	juice_gather_candidates(ctx.agent2);

	// Wait until both agents reach a terminal state and all messages are received
	for (int t = 0; t < TIMEOUT_CONNECT_MS; t += POLL_MS) {
		juice_state_t s1 = ctx.state1;
		juice_state_t s2 = ctx.state2;
		bool both_terminal =
		    (s1 == JUICE_STATE_COMPLETED || s1 == JUICE_STATE_CONNECTED ||
		     s1 == JUICE_STATE_FAILED) &&
		    (s2 == JUICE_STATE_COMPLETED || s2 == JUICE_STATE_CONNECTED ||
		     s2 == JUICE_STATE_FAILED);
		if (both_terminal && ctx.recv_count1 >= SEND_COUNT && ctx.recv_count2 >= SEND_COUNT)
			break;
		sleep_ms(POLL_MS);
	}

	juice_state_t state1 = juice_get_state(ctx.agent1);
	juice_state_t state2 = juice_get_state(ctx.agent2);
	bool success = ((state1 == JUICE_STATE_COMPLETED || state1 == JUICE_STATE_CONNECTED) &&
	                (state2 == JUICE_STATE_CONNECTED || state2 == JUICE_STATE_COMPLETED));

	printf("Agent 1 received %d/%d message(s), agent 2 received %d/%d message(s)\n",
	       ctx.recv_count1, SEND_COUNT, ctx.recv_count2, SEND_COUNT);
	success &= (ctx.recv_count1 >= SEND_COUNT && ctx.recv_count2 >= SEND_COUNT);

	printf("Agent 1 TURN transport: %s\n", is_tcp1 ? "TCP" : "UDP");
	printf("Agent 2 TURN transport: %s\n", is_tcp2 ? "TCP" : "UDP");

	char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	char remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	if (success &= (juice_get_selected_candidates(ctx.agent1, local,
	                                              JUICE_MAX_CANDIDATE_SDP_STRING_LEN, remote,
	                                              JUICE_MAX_CANDIDATE_SDP_STRING_LEN) == 0)) {
		printf("Local candidate  1: %s\n", local);
		printf("Remote candidate 1: %s\n", remote);
		success &= (strstr(local, "relay") != NULL);
		success &= (strstr(remote, "relay") != NULL);
	}
	if (success &= (juice_get_selected_candidates(ctx.agent2, local,
	                                              JUICE_MAX_CANDIDATE_SDP_STRING_LEN, remote,
	                                              JUICE_MAX_CANDIDATE_SDP_STRING_LEN) == 0)) {
		printf("Local candidate  2: %s\n", local);
		printf("Remote candidate 2: %s\n", remote);
		success &= (strstr(local, "relay") != NULL);
		success &= (strstr(remote, "relay") != NULL);
	}

	char localAddr[JUICE_MAX_ADDRESS_STRING_LEN];
	char remoteAddr[JUICE_MAX_ADDRESS_STRING_LEN];
	if (success &= (juice_get_selected_addresses(ctx.agent1, localAddr,
	                                             JUICE_MAX_ADDRESS_STRING_LEN, remoteAddr,
	                                             JUICE_MAX_ADDRESS_STRING_LEN) == 0)) {
		printf("Local address  1: %s\n", localAddr);
		printf("Remote address 1: %s\n", remoteAddr);
	}
	if (success &= (juice_get_selected_addresses(ctx.agent2, localAddr,
	                                             JUICE_MAX_ADDRESS_STRING_LEN, remoteAddr,
	                                             JUICE_MAX_ADDRESS_STRING_LEN) == 0)) {
		printf("Local address  2: %s\n", localAddr);
		printf("Remote address 2: %s\n", remoteAddr);
	}

	juice_destroy(ctx.agent1);
	juice_destroy(ctx.agent2);

	if (success) {
		printf("%s: Success\n\n", name);
		return 0;
	} else {
		printf("%s: Failure\n\n", name);
		return -1;
	}
}

int test_turn_relay() {
	const char *turn_host = getenv("TURN_HOST");
	const char *turn_port_str = getenv("TURN_PORT");
	const char *turn_username = getenv("TURN_USERNAME");
	const char *turn_password = getenv("TURN_PASSWORD");

	if (!turn_host || !turn_port_str || !turn_username || !turn_password) {
		printf("TURN_HOST, TURN_PORT, TURN_USERNAME, and TURN_PASSWORD must be set\n");
		return 0;
	}

	// Optional second TURN server; falls back to the first if not set
	const char *turn_host2 = getenv("TURN_HOST2");
	const char *turn_port_str2 = getenv("TURN_PORT2");
	const char *turn_username2 = getenv("TURN_USERNAME2");
	const char *turn_password2 = getenv("TURN_PASSWORD2");
	if (!turn_host2)     turn_host2     = turn_host;
	if (!turn_port_str2) turn_port_str2 = turn_port_str;
	if (!turn_username2) turn_username2 = turn_username;
	if (!turn_password2) turn_password2 = turn_password;

	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	uint16_t turn_port  = (uint16_t)atoi(turn_port_str);
	uint16_t turn_port2 = (uint16_t)atoi(turn_port_str2);

#define MAKE_SERVER(var, h, p, u, pw)       \
	juice_turn_server_t var;                \
	memset(&var, 0, sizeof(var));           \
	var.host = (h); var.port = (p);         \
	var.username = (u); var.password = (pw)

	static const struct {
		juice_concurrency_mode_t mode;
		const char *mode_name;
	} modes[] = {
		{JUICE_CONCURRENCY_MODE_POLL,   "poll"},
		{JUICE_CONCURRENCY_MODE_THREAD, "thread"},
	};

	int ret = 0;

	for (int m = 0; m < 2; ++m) {
		juice_concurrency_mode_t mode = modes[m].mode;
		const char *mn = modes[m].mode_name;
		char name[64];

#define RUN(tcp1, tcp2, label) \
		{ \
			MAKE_SERVER(s1, turn_host,  turn_port,  turn_username,  turn_password); \
			MAKE_SERVER(s2, turn_host2, turn_port2, turn_username2, turn_password2); \
			snprintf(name, sizeof(name), "TURN relay %s [%s]", label, mn); \
			ret |= run_relay_test(name, &s1, tcp1, &s2, tcp2, mode); \
			if (ret) return ret;\
		}

		RUN(false, false, "UDP/UDP")
		RUN(true,  true,  "TCP/TCP")
		RUN(true,  false, "TCP/UDP")
		RUN(false, true,  "UDP/TCP")

#undef RUN
	}

#undef MAKE_SERVER
	return ret;
}
