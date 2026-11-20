/**
 * Copyright (c) 2026
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "juice/juice.h"

#include "socket.h"
#include "stun.h"
#include "timestamp.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PEER_UFRAG "peer"
#define PEER_PWD "peerpeerpeerpeerpeerpeer"
#define BUFFER_SIZE 4096
#define WANTED_NOMINATIONS 2
#define WAIT_TIME 15000 // msecs

static void answer(socket_t sock, const stun_message_t *request, const struct sockaddr *source,
                   socklen_t source_len)
{
	stun_message_t response;
	memset(&response, 0, sizeof(response));
	response.msg_class = STUN_CLASS_RESP_SUCCESS;
	response.msg_method = STUN_METHOD_BINDING;
	memcpy(response.transaction_id, request->transaction_id, STUN_TRANSACTION_ID_SIZE);
	memcpy(&response.mapped.addr, source, source_len);
	response.mapped.len = source_len;

	char buffer[BUFFER_SIZE];
	int size = stun_write(buffer, sizeof(buffer), &response, PEER_PWD);
	if (size > 0)
	{
		sendto(sock, buffer, size, 0, source, source_len);
	}
}

// The peer is a bare socket that answers every check but, like libnice 0.1.5 and 0.1.7 before
// they start negotiating, does not keep the first nomination it receives. The controlling
// agent has to nominate the pair again for such a peer to ever see one it keeps.
int test_nomination_repeated()
{
#if defined(JUICE_DISABLE_CONSENT_FRESHNESS) && JUICE_DISABLE_CONSENT_FRESHNESS
	printf("Skipped, the later checks are indications without consent freshness\n");
	return 0;
#else
	juice_set_log_level(JUICE_LOG_LEVEL_DEBUG);

	juice_config_t config;
	memset(&config, 0, sizeof(config));
	juice_agent_t *agent = juice_create(&config);
	if (!agent)
	{
		return -1;
	}

	// Asking for the local description first makes the agent the controlling one
	char sdp[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent, sdp, sizeof(sdp));

	socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in bound;
	memset(&bound, 0, sizeof(bound));
	bound.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &bound.sin_addr);
	socklen_t bound_len = sizeof(bound);
	if (sock == INVALID_SOCKET || bind(sock, (struct sockaddr *)&bound, sizeof(bound)) != 0 ||
	    getsockname(sock, (struct sockaddr *)&bound, &bound_len) != 0)
	{
		fprintf(stderr, "Could not open the peer socket\n");
		juice_destroy(agent);
		return -1;
	}

	char remote[JUICE_MAX_SDP_STRING_LEN];
	snprintf(remote, sizeof(remote), "a=ice-ufrag:%s\na=ice-pwd:%s\n", PEER_UFRAG, PEER_PWD);
	char candidate[128];
	snprintf(candidate, sizeof(candidate), "a=candidate:1 1 UDP 2130706431 127.0.0.1 %hu typ host",
	         (unsigned short)ntohs(bound.sin_port));
	if (juice_set_remote_description(agent, remote) != JUICE_ERR_SUCCESS ||
	    juice_add_remote_candidate(agent, candidate) != JUICE_ERR_SUCCESS ||
	    juice_set_remote_gathering_done(agent) != JUICE_ERR_SUCCESS ||
	    juice_gather_candidates(agent) != JUICE_ERR_SUCCESS)
	{
		fprintf(stderr, "Could not set up the agent\n");
		closesocket(sock);
		juice_destroy(agent);
		return -1;
	}

	int nominations = 0;
	timestamp_t deadline = current_timestamp() + WAIT_TIME;
	while (nominations < WANTED_NOMINATIONS && current_timestamp() < deadline)
	{
		struct pollfd pfd;
		memset(&pfd, 0, sizeof(pfd));
		pfd.fd = sock;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 100) <= 0)
		{
			continue;
		}

		char buffer[BUFFER_SIZE];
		struct sockaddr_storage source;
		socklen_t source_len = sizeof(source);
		int size = (int)recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&source,
		                         &source_len);
		if (size <= 0)
		{
			continue;
		}

		stun_message_t request;
		memset(&request, 0, sizeof(request));
		if (stun_read(buffer, size, &request) < 0 || request.msg_class != STUN_CLASS_REQUEST ||
		    request.msg_method != STUN_METHOD_BINDING ||
		    !stun_check_integrity(buffer, size, &request, PEER_PWD))
		{
			continue;
		}

		if (request.use_candidate)
		{
			++nominations;
			printf("Peer received check %d with USE-CANDIDATE\n", nominations);
		}

		answer(sock, &request, (struct sockaddr *)&source, source_len);
	}

	closesocket(sock);
	juice_destroy(agent);

	if (nominations < WANTED_NOMINATIONS)
	{
		fprintf(stderr, "Peer received USE-CANDIDATE %d time(s), expected %d\n", nominations,
		        WANTED_NOMINATIONS);
		printf("Failure\n");
		return -1;
	}

	printf("Success\n");
	return 0;
#endif
}
