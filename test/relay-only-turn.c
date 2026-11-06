/**
 * Copyright (c) 2026
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "juice/juice.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep(unsigned int secs) { Sleep(secs * 1000); }
#else
#include <unistd.h> // for sleep
#endif

static int wait_for_gathering(const bool *done) {
	for (int i = 0; i < 10 && !*done; ++i)
		sleep(1);
	return *done ? 0 : -1;
}

static juice_agent_t *agent1;
static juice_agent_t *agent2;
static bool non_relay_candidate_emitted;
static bool mixed_mode;
static bool mixed_peer_host_emitted;

typedef struct candidate_observation {
	bool host;
	bool srflx;
	bool done;
	bool non_relay;
} candidate_observation_t;

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	fprintf(stderr, "TURN test ICE state: %s\n", juice_state_to_string(state));
}

static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	fprintf(stderr, "Agent 1 candidate: %s\n", sdp);
	if (!strstr(sdp, " typ relay")) {
		non_relay_candidate_emitted = true;
		return;
	}
	if (juice_add_remote_candidate(agent2, sdp) < 0)
		fprintf(stderr, "Agent 2 rejected relayed candidate: %s\n", sdp);
}

static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	fprintf(stderr, "Agent 2 candidate: %s\n", sdp);
	if (!strstr(sdp, mixed_mode ? " typ host" : " typ relay")) {
		non_relay_candidate_emitted = true;
		return;
	}
	if (mixed_mode)
		mixed_peer_host_emitted = true;
	if (juice_add_remote_candidate(agent1, sdp) < 0)
		fprintf(stderr, "Agent 1 rejected relayed candidate: %s\n", sdp);
}

static void on_observed_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	candidate_observation_t *observation = user_ptr;
	if (strstr(sdp, " typ host"))
		observation->host = true;
	else if (strstr(sdp, " typ srflx"))
		observation->srflx = true;
	if (!strstr(sdp, " typ relay"))
		observation->non_relay = true;
}

static void on_gathering_done(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	candidate_observation_t *observation = user_ptr;
	observation->done = true;
}

static bool agent1_received_data;
static bool agent2_received_data;

static void on_data1(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	static const char expected[] = "relay-only data from agent 2";
	if (size == sizeof(expected) - 1 && memcmp(data, expected, sizeof(expected) - 1) == 0)
		agent1_received_data = true;
}

static void on_data2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	static const char expected[] = "relay-only data from agent 1";
	if (size == sizeof(expected) - 1 && memcmp(data, expected, sizeof(expected) - 1) == 0)
		agent2_received_data = true;
}

static int test_default_all_stun(void) {
	candidate_observation_t observation = {0};
	juice_config_t config;
	memset(&config, 0, sizeof(config));
	config.stun_server_host = "127.0.0.1";
	config.stun_server_port = 3478;
	config.cb_candidate = on_observed_candidate;
	config.cb_gathering_done = on_gathering_done;
	config.user_ptr = &observation;

	juice_agent_t *agent = juice_create(&config);
	if (!agent)
		return -1;
	int ret = juice_gather_candidates(agent);
	if (ret >= 0)
		ret = wait_for_gathering(&observation.done);

	char sdp[JUICE_MAX_SDP_STRING_LEN];
	int sdp_ret = juice_get_local_description(agent, sdp, sizeof(sdp));
	bool success = ret >= 0 && sdp_ret >= 0 && observation.done && observation.host &&
	               observation.srflx && strstr(sdp, " typ host") &&
	               strstr(sdp, " typ srflx");
	if (!success)
		fprintf(stderr,
		        "Default All/STUN regression: done=%d host_cb=%d srflx_cb=%d host_sdp=%d "
		        "srflx_sdp=%d\n",
		        observation.done, observation.host, observation.srflx,
		        sdp_ret >= 0 && strstr(sdp, " typ host") != NULL,
		        sdp_ret >= 0 && strstr(sdp, " typ srflx") != NULL);
	juice_destroy(agent);
	return success ? 0 : -1;
}

static void on_failure_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	candidate_observation_t *observation = user_ptr;
	if (!strstr(sdp, " typ relay"))
		observation->non_relay = true;
}

static int test_no_direct_fallback(uint16_t port, const char *username, const char *password,
                                   const char *name) {
	candidate_observation_t observation = {0};
	candidate_observation_t peer_observation = {0};
	juice_turn_server_t turn;
	memset(&turn, 0, sizeof(turn));
	turn.host = "127.0.0.1";
	turn.port = port;
	turn.username = username;
	turn.password = password;

	juice_config_t relay_config;
	memset(&relay_config, 0, sizeof(relay_config));
	relay_config.turn_servers = &turn;
	relay_config.turn_servers_count = 1;
	relay_config.cb_candidate = on_failure_candidate;
	relay_config.cb_gathering_done = on_gathering_done;
	relay_config.user_ptr = &observation;

	juice_config_t peer_config;
	memset(&peer_config, 0, sizeof(peer_config));
	peer_config.cb_gathering_done = on_gathering_done;
	peer_config.user_ptr = &peer_observation;
	juice_agent_t *relay_agent = juice_create(&relay_config);
	juice_agent_t *direct_peer = juice_create(&peer_config);
	if (!relay_agent || !direct_peer ||
	    juice_set_ice_transport_policy(relay_agent, JUICE_ICE_TRANSPORT_POLICY_RELAY) !=
	        JUICE_ERR_SUCCESS) {
		juice_destroy(relay_agent);
		juice_destroy(direct_peer);
		return -1;
	}

	if (juice_gather_candidates(relay_agent) < 0 ||
	    juice_gather_candidates(direct_peer) < 0) {
		juice_destroy(relay_agent);
		juice_destroy(direct_peer);
		return -1;
	}

	// Wait for TURN retries to finish before checking for direct fallback.
	for (int i = 0; i < 30 && (!observation.done || !peer_observation.done); ++i)
		sleep(1);
	if (!observation.done || !peer_observation.done) {
		fprintf(stderr,
		        "Relay-only failure test (%s) gathering timed out (relay_done=%d peer_done=%d)\n",
		        name, observation.done, peer_observation.done);
		juice_destroy(relay_agent);
		juice_destroy(direct_peer);
		return -1;
	}

	char relay_sdp[JUICE_MAX_SDP_STRING_LEN];
	char peer_sdp[JUICE_MAX_SDP_STRING_LEN];
	int relay_ret = juice_get_local_description(relay_agent, relay_sdp, sizeof(relay_sdp));
	int peer_ret = juice_get_local_description(direct_peer, peer_sdp, sizeof(peer_sdp));
	bool setup_ok = relay_ret >= 0 && peer_ret >= 0 &&
	                strstr(relay_sdp, " typ host") == NULL &&
	                strstr(relay_sdp, " typ srflx") == NULL &&
	                juice_set_remote_description(relay_agent, peer_sdp) >= 0 &&
	                juice_set_remote_description(direct_peer, relay_sdp) >= 0 &&
	                juice_set_remote_gathering_done(relay_agent) >= 0 &&
	                juice_set_remote_gathering_done(direct_peer) >= 0;
	if (!setup_ok) {
		fprintf(stderr, "Relay-only failure test (%s) setup/gathering failed (done=%d)\n",
		        name, observation.done);
		juice_destroy(relay_agent);
		juice_destroy(direct_peer);
		return -1;
	}

	for (int i = 0; i < 5; ++i) {
		juice_state_t state = juice_get_state(relay_agent);
		if (state == JUICE_STATE_CONNECTED || state == JUICE_STATE_COMPLETED)
			break;
		sleep(1);
	}

	char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	char remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	bool selected = juice_get_selected_candidates(relay_agent, local, sizeof(local), remote,
	                                              sizeof(remote)) >= 0;
	juice_state_t state = juice_get_state(relay_agent);
	bool connected = state == JUICE_STATE_CONNECTED || state == JUICE_STATE_COMPLETED;
	bool success = !connected && !selected && !observation.non_relay;

	if (!success)
		fprintf(stderr,
		        "Relay-only no-direct-fallback (%s) failed: state=%s selected=%d non_relay_cb=%d\n",
		        name, juice_state_to_string(state), selected, observation.non_relay);
	else
		fprintf(stderr, "Relay-only no-direct-fallback (%s): passed\n", name);

	juice_destroy(relay_agent);
	juice_destroy(direct_peer);
	return success ? 0 : -1;
}

static int test_turn_connection(juice_turn_server_t *turn, bool use_mixed_mode) {
	mixed_mode = use_mixed_mode;
	juice_config_t config1;
	memset(&config1, 0, sizeof(config1));
	config1.turn_servers = turn;
	config1.turn_servers_count = 1;
	config1.stun_server_host = "127.0.0.1";
	config1.stun_server_port = 3478;
	config1.cb_candidate = on_candidate1;
	config1.cb_state_changed = on_state_changed;
	config1.cb_recv = on_data1;

	juice_config_t config2 = config1;
	if (mixed_mode) {
		config2.turn_servers = NULL;
		config2.turn_servers_count = 0;
		config2.stun_server_host = NULL;
		config2.bind_address = "127.0.0.1";
	}
	config2.cb_candidate = on_candidate2;
	config2.cb_recv = on_data2;

	agent1_received_data = false;
	agent2_received_data = false;
	mixed_peer_host_emitted = false;

	non_relay_candidate_emitted = false;
	agent1 = juice_create(&config1);
	agent2 = juice_create(&config2);
	if (!agent1 || !agent2 ||
	    juice_set_ice_transport_policy(agent1, JUICE_ICE_TRANSPORT_POLICY_RELAY) !=
	        JUICE_ERR_SUCCESS ||
	    (!mixed_mode && juice_set_ice_transport_policy(agent2, JUICE_ICE_TRANSPORT_POLICY_RELAY) !=
	                        JUICE_ERR_SUCCESS)) {
		juice_destroy(agent1);
		juice_destroy(agent2);
		return -1;
	}

	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	char sdp2[JUICE_MAX_SDP_STRING_LEN];
	if (juice_get_local_description(agent1, sdp1, sizeof(sdp1)) < 0 ||
	    juice_get_local_description(agent2, sdp2, sizeof(sdp2)) < 0 ||
	    juice_set_remote_description(agent1, sdp2) < 0 ||
	    juice_set_remote_description(agent2, sdp1) < 0) {
		juice_destroy(agent1);
		juice_destroy(agent2);
		return -1;
	}

	if (juice_gather_candidates(agent1) < 0 || juice_gather_candidates(agent2) < 0) {
		juice_destroy(agent1);
		juice_destroy(agent2);
		agent1 = NULL;
		agent2 = NULL;
		return -1;
	}

	bool connected = false;
	for (int i = 0; i < 20; ++i) {
		juice_state_t state1 = juice_get_state(agent1);
		juice_state_t state2 = juice_get_state(agent2);
		if ((state1 == JUICE_STATE_CONNECTED || state1 == JUICE_STATE_COMPLETED) &&
		    (state2 == JUICE_STATE_CONNECTED || state2 == JUICE_STATE_COMPLETED)) {
			connected = true;
			break;
		}
		sleep(1);
	}

	fprintf(stderr, "connected=%d state1=%s state2=%s non_relay=%d\n", connected,
	        juice_state_to_string(juice_get_state(agent1)),
	        juice_state_to_string(juice_get_state(agent2)), non_relay_candidate_emitted);
	bool success = connected && !non_relay_candidate_emitted &&
	               (!mixed_mode || mixed_peer_host_emitted);
	if (success) {
		static const char data1[] = "relay-only data from agent 1";
		static const char data2[] = "relay-only data from agent 2";
		if (juice_send(agent1, data1, sizeof(data1) - 1) < 0 ||
		    juice_send(agent2, data2, sizeof(data2) - 1) < 0) {
			success = false;
		} else {
			for (int i = 0; i < 5 && (!agent1_received_data || !agent2_received_data); ++i)
				sleep(1);
			success = agent1_received_data && agent2_received_data;
		}
		if (!success)
			fprintf(stderr, "Relay-only TURN data test failed: agent1_received=%d agent2_received=%d\\n",
			        agent1_received_data, agent2_received_data);
	}
	char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	char remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
	if (success &&
	    (juice_get_selected_candidates(agent1, local, sizeof(local), remote, sizeof(remote)) < 0 ||
	     !strstr(local, " typ relay") ||
	     !strstr(remote, mixed_mode ? " typ host" : " typ relay")))
		success = false;
	if (success &&
	    (juice_get_selected_candidates(agent2, local, sizeof(local), remote, sizeof(remote)) < 0 ||
	     !strstr(local, mixed_mode ? " typ host" : " typ relay") ||
	     !strstr(remote, " typ relay")))
		success = false;
	if (success &&
	    (juice_get_local_description(agent1, sdp1, sizeof(sdp1)) < 0 ||
	     juice_get_local_description(agent2, sdp2, sizeof(sdp2)) < 0 ||
	     strstr(sdp1, " typ host") || strstr(sdp1, " typ srflx") ||
	     (mixed_mode ? !strstr(sdp2, " typ host") || strstr(sdp2, " typ relay")
	                 : strstr(sdp2, " typ host") || strstr(sdp2, " typ srflx"))))
		success = false;

	printf("Relay-only TURN %s test: %s\n", mixed_mode ? "mixed-mode" : "relay-to-relay",
	       success ? "passed" : "failed");
	juice_destroy(agent1);
	juice_destroy(agent2);
	agent1 = NULL;
	agent2 = NULL;
	return success ? 0 : -1;
}

int test_relay_only_turn(void) {
	juice_server_credentials_t credentials;
	memset(&credentials, 0, sizeof(credentials));
	credentials.username = "testuser";
	credentials.password = "testpass";

	juice_server_config_t server_config;
	memset(&server_config, 0, sizeof(server_config));
	server_config.bind_address = "127.0.0.1";
	server_config.external_address = "127.0.0.1";
	server_config.port = 3478;
	server_config.relay_port_range_begin = 49160;
	server_config.relay_port_range_end = 49200;
	server_config.credentials = &credentials;
	server_config.credentials_count = 1;
	server_config.max_allocations = 100;
	server_config.realm = "localhost";
	juice_server_t *server = juice_server_create(&server_config);
	if (!server) {
		fprintf(stderr, "Failed to create embedded TURN server\n");
		return -1;
	}
	if (juice_server_get_port(server) != 3478) {
		fprintf(stderr, "Failed to bind embedded TURN server to port 3478\n");
		juice_server_destroy(server);
		return -1;
	}

	juice_turn_server_t turn;
	memset(&turn, 0, sizeof(turn));
	turn.host = "127.0.0.1";
	turn.port = 3478;
	turn.username = "testuser";
	turn.password = "testpass";

	int result = test_turn_connection(&turn, false);
	if (result == 0 && test_turn_connection(&turn, true) < 0)
		result = -1;
	if (result == 0 && test_default_all_stun() < 0)
		result = -1;
	if (result == 0 &&
	    test_no_direct_fallback(3479, "testuser", "testpass", "TURN unavailable") < 0)
		result = -1;
	if (result == 0 &&
	    test_no_direct_fallback(3478, "wronguser", "wrongpass", "invalid credentials") < 0)
		result = -1;
	juice_server_destroy(server);
	return result;
}
