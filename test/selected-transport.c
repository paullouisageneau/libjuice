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

static bool set_address(addr_record_t *record, const char *ip, uint16_t port) {
	struct sockaddr_in address = {0};
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &address.sin_addr) != 1)
		return false;
	memset(record, 0, sizeof(*record));
	memcpy(&record->addr, &address, sizeof(address));
	record->len = sizeof(address);
	record->socktype = SOCK_DGRAM;
	return true;
}

int test_selected_transport(void) {
	char remote[JUICE_MAX_ADDRESS_STRING_LEN];
	char advertised[JUICE_MAX_ADDRESS_STRING_LEN];
	char too_short[2];
	juice_config_t config = {0};
	juice_agent_t *agent = juice_create(&config);
	if (!agent)
		return -1;

	bool success = juice_get_selected_remote_transport_address(NULL, remote, sizeof(remote)) ==
	                   JUICE_ERR_INVALID &&
	               juice_get_selected_remote_transport_address(agent, NULL, sizeof(remote)) ==
	                   JUICE_ERR_INVALID &&
	               juice_get_selected_remote_transport_address(agent, remote, 0) ==
	                   JUICE_ERR_INVALID &&
	               juice_get_selected_remote_transport_address(agent, remote, sizeof(remote)) ==
	                   JUICE_ERR_NOT_AVAIL;

	// Model a remote candidate that advertises a private address while the
	// nominated ICE transport entry is reachable through a public NAT address.
	ice_candidate_t *candidate = agent->remote.candidates;
	candidate->type = ICE_CANDIDATE_TYPE_HOST;
	if (!set_address(&candidate->resolved, "172.18.0.6", 51029)) {
		juice_destroy(agent);
		return -1;
	}
	ice_candidate_pair_t *pair = agent->candidate_pairs;
	pair->remote = candidate;
	agent->selected_pair = pair;

	agent_stun_entry_t *entry = agent->entries;
	entry->pair = pair;
	if (!set_address(&entry->record, "79.127.184.208", 17212)) {
		juice_destroy(agent);
		return -1;
	}
	atomic_store(&agent->selected_entry, entry);

	success = success &&
	          juice_get_selected_addresses(agent, NULL, 0, advertised, sizeof(advertised)) ==
	              JUICE_ERR_SUCCESS &&
	          strcmp(advertised, "172.18.0.6:51029") == 0 &&
	          juice_get_selected_remote_transport_address(agent, remote, sizeof(remote)) ==
	              JUICE_ERR_SUCCESS &&
	          strcmp(remote, "79.127.184.208:17212") == 0 &&
	          juice_get_selected_remote_transport_address(agent, too_short, sizeof(too_short)) ==
	              JUICE_ERR_FAILED;

	// An outgoing TURN packet is sent to the relay server, but the logical
	// destination must still be the selected remote peer, not the TURN server.
	agent_stun_entry_t *relay = agent->entries + 1;
	if (!set_address(&relay->record, "198.51.100.20", 3478)) {
		juice_destroy(agent);
		return -1;
	}
	entry->relay_entry = relay;
	success = success &&
	          juice_get_selected_remote_transport_address(agent, remote, sizeof(remote)) ==
	              JUICE_ERR_SUCCESS &&
	          strcmp(remote, "79.127.184.208:17212") == 0;

	atomic_store(&agent->selected_entry, NULL);
	success = success &&
	          juice_get_selected_remote_transport_address(agent, remote, sizeof(remote)) ==
	              JUICE_ERR_NOT_AVAIL;

	if (!success)
		fprintf(stderr, "Selected transport endpoint regression failed\n");
	juice_destroy(agent);
	return success ? 0 : -1;
}
