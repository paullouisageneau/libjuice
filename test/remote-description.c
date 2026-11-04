/**
 * Copyright (c) 2026
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "agent.h"

#include <stdio.h>
#include <string.h>

// Reproduces a valid incoming check before SDP: the learned public remote
// peer-reflexive endpoint must remain attached to its active candidate pair.
int test_remote_description_early_stun(void) {
	juice_config_t config = {0};
	juice_agent_t *agent = juice_create(&config);
	if (!agent)
		return -1;

	// Process an authenticated STUN check without opening a network socket.
	agent->state = JUICE_STATE_CONNECTING;
	agent->mode = AGENT_MODE_CONTROLLED;

	stun_message_t request = {0};
	request.msg_class = STUN_CLASS_REQUEST;
	request.msg_method = STUN_METHOD_BINDING;
	request.priority = 123456789;
	request.has_ice_controlling = true;
	request.ice_controlling = 1;
	snprintf(request.credentials.username, sizeof(request.credentials.username), "%s:%s",
	         agent->local.ice_ufrag, "remote");

	char packet[512];
	int const size = stun_write(packet, sizeof(packet), &request, agent->local.ice_pwd);
	if (size <= 0) {
		juice_destroy(agent);
		return -1;
	}

	struct sockaddr_in address = {0};
	address.sin_family = AF_INET;
	address.sin_port = htons(17212);
	if (inet_pton(AF_INET, "79.127.184.208", &address.sin_addr) != 1) {
		juice_destroy(agent);
		return -1;
	}
	addr_record_t source = {0};
	memcpy(&source.addr, &address, sizeof(address));
	source.len = sizeof(address);
	source.socktype = SOCK_DGRAM;

	(void)agent_input(agent, packet, (size_t)size, &source, NULL);
	bool const learned = agent->remote.candidates_count == 1 &&
	                     agent->candidate_pairs_count == 1 && agent->entries_count == 1 &&
	                     agent->remote.candidates[0].type == ICE_CANDIDATE_TYPE_PEER_REFLEXIVE &&
	                     agent->remote.candidates[0].priority == request.priority &&
	                     agent->candidate_pairs[0].remote == &agent->remote.candidates[0] &&
	                     agent->entries[0].pair == &agent->candidate_pairs[0] &&
	                     addr_record_is_equal(&agent->entries[0].record, &source, true);
	if (!learned) {
		fprintf(stderr, "Early STUN check failed to create a peer-reflexive pair\n");
		juice_destroy(agent);
		return -1;
	}

	ice_candidate_pair_t *pair = &agent->candidate_pairs[0];
	agent_stun_entry_t *entry = &agent->entries[0];
	uint32_t const original_priority = pair->remote->priority;
	uint64_t const original_pair_priority = pair->priority;

	// Simulate the pair already being selected; SDP must not disturb it.
	pair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
	pair->nominated = true;
	agent->selected_pair = pair;
	atomic_store(&agent->selected_entry, entry);

	char const sdp[] =
	    "a=ice-ufrag:remote\r\n"
	    "a=ice-pwd:0123456789012345678901\r\n"
	    "a=candidate:1 1 UDP 2100000000 172.18.0.6 51029 typ host\r\n"
	    "a=candidate:2 1 UDP 2114000000 79.127.184.208 17212 typ srflx\r\n";
	bool ok = juice_set_remote_description(agent, sdp) == JUICE_ERR_SUCCESS;

	// Keep the STUN-learned pair intact while accepting separately signaled
	// candidates, including a server-reflexive candidate for the same endpoint.
	ice_candidate_t *signaled = ice_find_candidate_from_addr(
	    &agent->remote, &source, ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE);
	ok &= pair->remote == &agent->remote.candidates[0] &&
	      pair->remote->type == ICE_CANDIDATE_TYPE_PEER_REFLEXIVE &&
	      pair->remote->priority == original_priority &&
	      pair->priority == original_pair_priority &&
	      addr_record_is_equal(&pair->remote->resolved, &source, true) &&
	      addr_record_is_equal(&entry->record, &source, true) &&
	      pair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED && pair->nominated &&
	      agent->selected_pair == pair &&
	      signaled && signaled != pair->remote && signaled->priority == 2114000000;

	// The application must still see the public endpoint, not the private
	// host candidate advertised in the late SDP.
	char remote_address[JUICE_MAX_ADDRESS_STRING_LEN] = {0};
	ok &= juice_get_selected_addresses(agent, NULL, 0, remote_address,
	                                 sizeof(remote_address)) == JUICE_ERR_SUCCESS &&
	      strcmp(remote_address, "79.127.184.208:17212") == 0;

	// A subsequent same-address trickle must not displace the selected pair.
	char const matching_trickle[] =
	    "a=candidate:4 1 UDP 2116000000 79.127.184.208 17212 typ srflx";
	ok &= juice_add_remote_candidate(agent, matching_trickle) == JUICE_ERR_SUCCESS &&
	      pair->remote == &agent->remote.candidates[0] &&
	      addr_record_is_equal(&pair->remote->resolved, &source, true) &&
	      pair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED &&
	      agent->selected_pair == pair;

	if (!ok)
		fprintf(stderr, "Early peer-reflexive candidate or selected path changed after signaling\n");

	juice_destroy(agent);
	return ok ? 0 : -1;
}
