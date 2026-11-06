/**
 * Copyright (c) 2026
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "agent.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
static void sleep(unsigned int secs) { Sleep(secs * 1000); }
#else
#include <arpa/inet.h>
#include <unistd.h> // for sleep
#endif

static int wait_for_gathering(const bool *done) {
	for (int i = 0; i < 10 && !*done; ++i)
		sleep(1);
	return *done ? 0 : -1;
}

typedef struct candidate_observation {
	bool host;
	bool srflx;
	bool prflx;
	bool done;
	bool received_data;
} candidate_observation_t;

static void on_data(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	(void)agent;
	(void)data;
	(void)size;
	candidate_observation_t *observation = user_ptr;
	observation->received_data = true;
}

static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	candidate_observation_t *observation = user_ptr;
	if (strstr(sdp, " typ host"))
		observation->host = true;
	else if (strstr(sdp, " typ srflx"))
		observation->srflx = true;
	else if (strstr(sdp, " typ prflx"))
		observation->prflx = true;
}

static void on_gathering_done(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	candidate_observation_t *observation = user_ptr;
	observation->done = true;
}

static int test_relay_only_filtering(void) {
	candidate_observation_t observation = {0};
	juice_config_t config;
	memset(&config, 0, sizeof(config));
	config.stun_server_host = "stun.invalid";
	config.stun_server_port = 3478;
	config.cb_candidate = on_candidate;
	config.cb_gathering_done = on_gathering_done;
	config.cb_recv = on_data;
	config.user_ptr = &observation;

	juice_agent_t *agent = juice_create(&config);
	if (!agent)
		return -1;

	bool const api_ok =
	    juice_set_ice_transport_policy(NULL, JUICE_ICE_TRANSPORT_POLICY_RELAY) ==
	        JUICE_ERR_INVALID &&
	    juice_set_ice_transport_policy(agent, (juice_ice_transport_policy_t)-1) ==
	        JUICE_ERR_INVALID &&
	    juice_set_ice_transport_policy(agent, JUICE_ICE_TRANSPORT_POLICY_ALL) ==
	        JUICE_ERR_SUCCESS &&
	    juice_set_ice_transport_policy(agent, JUICE_ICE_TRANSPORT_POLICY_RELAY) ==
	        JUICE_ERR_SUCCESS;
	if (!api_ok) {
		fprintf(stderr, "ICE transport policy setter rejected a valid configuration\n");
		juice_destroy(agent);
		return -1;
	}

	int ret = juice_gather_candidates(agent);
	if (ret >= 0)
		ret = wait_for_gathering(&observation.done);
	bool const late_change_rejected =
	    juice_set_ice_transport_policy(agent, JUICE_ICE_TRANSPORT_POLICY_ALL) ==
	    JUICE_ERR_FAILED;

	struct sockaddr_in reflexive_address;
	memset(&reflexive_address, 0, sizeof(reflexive_address));
	reflexive_address.sin_family = AF_INET;
	reflexive_address.sin_port = htons(50001);
	reflexive_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr_record_t reflexive_record;
	memset(&reflexive_record, 0, sizeof(reflexive_record));
	memcpy(&reflexive_record.addr, &reflexive_address, sizeof(reflexive_address));
	reflexive_record.len = sizeof(reflexive_address);
	reflexive_record.socktype = SOCK_DGRAM;
	int srflx_ret = agent_add_local_reflexive_candidate(
	    agent, ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE, &reflexive_record);

	reflexive_address.sin_port = htons(50002);
	memcpy(&reflexive_record.addr, &reflexive_address, sizeof(reflexive_address));
	int prflx_ret = agent_add_local_reflexive_candidate(
	    agent, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE, &reflexive_record);
	int srflx_count = ice_candidates_count(&agent->local, ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);
	int prflx_count = ice_candidates_count(&agent->local, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE);

	char sdp[JUICE_MAX_SDP_STRING_LEN];
	int sdp_ret = juice_get_local_description(agent, sdp, sizeof(sdp));
	int host_count = ice_candidates_count(&agent->local, ICE_CANDIDATE_TYPE_HOST);
	bool success = ret >= 0 && sdp_ret >= 0 && observation.done && late_change_rejected &&
	               host_count == 0 && srflx_ret >= 0 && prflx_ret >= 0 &&
	               srflx_count == 0 && prflx_count == 0 && agent->entries_count == 0 &&
	               !agent->resolver_thread_started && !observation.host &&
	               !observation.srflx && !observation.prflx &&
	               strstr(sdp, " typ host") == NULL && strstr(sdp, " typ srflx") == NULL &&
	               strstr(sdp, " typ prflx") == NULL;

	if (success) {
		struct sockaddr_in address;
		memset(&address, 0, sizeof(address));
		address.sin_family = AF_INET;
		address.sin_port = htons(50000);
		address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr_record_t source;
		memset(&source, 0, sizeof(source));
		memcpy(&source.addr, &address, sizeof(address));
		source.len = sizeof(address);
		source.socktype = SOCK_DGRAM;

		int prflx_count_before_input =
		    ice_candidates_count(&agent->local, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE);
		int remote_prflx_before_input =
		    ice_candidates_count(&agent->remote, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE);
		agent->state = JUICE_STATE_CONNECTING;
		char payload[] = "direct application data";
		int data_ret = agent_input(agent, payload, sizeof(payload), &source, NULL);

		stun_message_t message;
		memset(&message, 0, sizeof(message));
		message.msg_class = STUN_CLASS_REQUEST;
		message.msg_method = STUN_METHOD_BINDING;
		message.priority = 1234;
		message.has_ice_controlling = true;
		message.ice_controlling = 1;
		snprintf(message.credentials.username, sizeof(message.credentials.username),
		         "%s:remote", agent->local.ice_ufrag);
		char stun_packet[256];
		int stun_size = stun_write(stun_packet, sizeof(stun_packet),
		                           &message, agent->local.ice_pwd);
		int stun_ret = stun_size > 0
		                   ? agent_input(agent, stun_packet, (size_t)stun_size, &source, NULL)
		                   : 0;

		// Direct packets must not create an ICE path or deliver data.
		success = data_ret < 0 && stun_size > 0 && stun_ret == 0 &&
		          !observation.received_data && agent->candidate_pairs_count == 0 &&
		          agent->entries_count == 0 &&
		          ice_candidates_count(&agent->local, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE) ==
		              prflx_count_before_input &&
		          ice_candidates_count(&agent->remote, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE) ==
		              remote_prflx_before_input;
		if (!success)
			fprintf(stderr,
			        "Relay-only direct-input regression: data_ret=%d stun_ret=%d received=%d "
			        "local_prflx=%d remote_prflx=%d pairs=%d\n",
			        data_ret, stun_ret, observation.received_data,
			        ice_candidates_count(&agent->local, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE),
			        ice_candidates_count(&agent->remote, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE),
			        agent->candidate_pairs_count);

		char const remote_sdp[] =
		    "a=ice-ufrag:remote\r\n"
		    "a=ice-pwd:0123456789012345678901\r\n"
		    "a=candidate:1 1 UDP 2122260223 127.0.0.1 50500 typ host\r\n";
		bool const remote_ok =
		    juice_set_remote_description(agent, remote_sdp) == JUICE_ERR_SUCCESS &&
		    agent->candidate_pairs_count == 0 && agent->entries_count == 0;
		if (!remote_ok)
			fprintf(stderr, "Relay-only mode created a direct pair for a remote host candidate\n");
		success = success && remote_ok;
	}

	if (!success)
		fprintf(stderr,
		        "Relay-only privacy regression: gathering_done=%d internal_hosts=%d "
		        "srflx_ret=%d prflx_ret=%d srflx_count=%d prflx_count=%d "
		        "stun_entries=%d host_cb=%d srflx_cb=%d prflx_cb=%d host_sdp=%d srflx_sdp=%d\n",
		        observation.done, host_count, srflx_ret, prflx_ret, srflx_count, prflx_count,
		        agent->entries_count, observation.host, observation.srflx, observation.prflx,
		        sdp_ret >= 0 && strstr(sdp, " typ host") != NULL,
		        sdp_ret >= 0 && strstr(sdp, " typ srflx") != NULL);

	juice_destroy(agent);
	return success ? 0 : -1;
}

int test_relay_only(void) {
	if (test_relay_only_filtering() < 0)
		return -1;
	return 0;
}
