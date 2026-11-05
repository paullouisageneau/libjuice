/**
 * Copyright (c) 2026 moLink contributors
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
#include <ws2tcpip.h>
#include <windows.h>
static void sleep_ms(unsigned int ms) { Sleep(ms); }
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
static void sleep_ms(unsigned int ms) {
	struct timespec ts;
	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;
	nanosleep(&ts, NULL);
}
#endif

typedef struct endpoint endpoint_t;
typedef struct packet packet_t;

struct endpoint {
	juice_agent_t *agent;
	endpoint_t *peer;
	struct sockaddr_storage addr;
	int addrlen;
	bool gathering_done;
};

struct packet {
	endpoint_t *from;
	endpoint_t *to;
	char *data;
	size_t size;
	packet_t *next;
};

static packet_t *queue_head = NULL;
static packet_t *queue_tail = NULL;

static void enqueue(endpoint_t *from, endpoint_t *to, const void *data, size_t size) {
	packet_t *packet = calloc(1, sizeof(packet_t));
	if (!packet)
		return;
	packet->data = malloc(size);
	if (!packet->data) {
		free(packet);
		return;
	}
	memcpy(packet->data, data, size);
	packet->size = size;
	packet->from = from;
	packet->to = to;
	if (queue_tail)
		queue_tail->next = packet;
	else
		queue_head = packet;
	queue_tail = packet;
}

static int fake_sendto(void *user_ptr, const void *data, size_t size, const void *dst, int dstlen) {
	(void)dst;
	(void)dstlen;
	endpoint_t *from = (endpoint_t *)user_ptr;
	if (!from || !from->peer)
		return -1;
	enqueue(from, from->peer, data, size);
	return 0;
}

static void drain_queue(void) {
	while (queue_head) {
		packet_t *packet = queue_head;
		queue_head = packet->next;
		if (!queue_head)
			queue_tail = NULL;

		juice_agent_input(packet->to->agent, packet->data, packet->size,
		                  &packet->from->addr, packet->from->addrlen);
		free(packet->data);
		free(packet);
	}
}

static void on_candidate_a(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_candidate_b(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_gathering_a(juice_agent_t *agent, void *user_ptr);
static void on_gathering_b(juice_agent_t *agent, void *user_ptr);

static endpoint_t endpoint_a;
static endpoint_t endpoint_b;

static void on_candidate_a(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	juice_add_remote_candidate(endpoint_b.agent, sdp);
}

static void on_candidate_b(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	juice_add_remote_candidate(endpoint_a.agent, sdp);
}

static void on_gathering_a(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	((endpoint_t *)user_ptr)->gathering_done = true;
}

static void on_gathering_b(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	((endpoint_t *)user_ptr)->gathering_done = true;
}

static void setup_endpoint(endpoint_t *endpoint, endpoint_t *peer, uint16_t port,
                           juice_cb_candidate_t on_candidate,
                           juice_cb_gathering_done_t on_gathering) {
	memset(endpoint, 0, sizeof(*endpoint));
	endpoint->peer = peer;
	endpoint->addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in *addr = (struct sockaddr_in *)&endpoint->addr;
	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);
	addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	juice_config_t config;
	memset(&config, 0, sizeof(config));
	config.concurrency_mode = JUICE_CONCURRENCY_MODE_EXTERNAL;
	config.external.sendto = fake_sendto;
	config.external.user_ptr = endpoint;
	config.external.local_address = "127.0.0.1";
	config.external.local_port = port;
	config.external.address_family = JUICE_ADDRESS_FAMILY_IPV4;
	config.cb_candidate = on_candidate;
	config.cb_gathering_done = on_gathering;
	config.user_ptr = endpoint;
	endpoint->agent = juice_create(&config);
}

int test_external(void) {
	juice_set_log_level(JUICE_LOG_LEVEL_WARN);

	queue_head = NULL;
	queue_tail = NULL;

	setup_endpoint(&endpoint_a, &endpoint_b, 20001, on_candidate_a, on_gathering_a);
	setup_endpoint(&endpoint_b, &endpoint_a, 20002, on_candidate_b, on_gathering_b);
	if (!endpoint_a.agent || !endpoint_b.agent) {
		fprintf(stderr, "external: juice_create failed\n");
		return -1;
	}

	char sdp_a[JUICE_MAX_SDP_STRING_LEN];
	char sdp_b[JUICE_MAX_SDP_STRING_LEN];
	if (juice_get_local_description(endpoint_a.agent, sdp_a, sizeof(sdp_a)) != 0 ||
	    juice_get_local_description(endpoint_b.agent, sdp_b, sizeof(sdp_b)) != 0) {
		fprintf(stderr, "external: local description failed\n");
		return -1;
	}
	if (juice_set_remote_description(endpoint_a.agent, sdp_b) != 0 ||
	    juice_set_remote_description(endpoint_b.agent, sdp_a) != 0) {
		fprintf(stderr, "external: remote description failed\n");
		return -1;
	}

	if (juice_gather_candidates(endpoint_a.agent) != 0 ||
	    juice_gather_candidates(endpoint_b.agent) != 0) {
		fprintf(stderr, "external: gathering failed\n");
		return -1;
	}

	juice_state_t state_a = JUICE_STATE_DISCONNECTED;
	juice_state_t state_b = JUICE_STATE_DISCONNECTED;
	for (int i = 0; i < 500; ++i) {
		drain_queue();
		juice_agent_tick(endpoint_a.agent);
		juice_agent_tick(endpoint_b.agent);
		sleep_ms(10);

		state_a = juice_get_state(endpoint_a.agent);
		state_b = juice_get_state(endpoint_b.agent);
		if (state_a == JUICE_STATE_COMPLETED && state_b == JUICE_STATE_COMPLETED)
			break;
		if (state_a == JUICE_STATE_FAILED || state_b == JUICE_STATE_FAILED)
			break;
	}
	drain_queue();

	if (state_a != JUICE_STATE_COMPLETED || state_b != JUICE_STATE_COMPLETED) {
		fprintf(stderr, "external: ICE did not complete (a=%d, b=%d)\n", (int)state_a,
		        (int)state_b);
		return -1;
	}

	// Application data is not consumed by the agent: the caller keeps using its
	// own socket in external mode.
	const char payload[] = "application data";
	if (juice_agent_input(endpoint_a.agent, payload, sizeof(payload), &endpoint_b.addr,
	                      endpoint_b.addrlen) != 0) {
		fprintf(stderr, "external: non-STUN data was consumed\n");
		return -1;
	}

	// The addresses the ICE layer selected are the ones the fake transport used.
	char local[JUICE_MAX_ADDRESS_STRING_LEN];
	char remote[JUICE_MAX_ADDRESS_STRING_LEN];
	if (juice_get_selected_addresses(endpoint_a.agent, local, sizeof(local), remote,
	                                 sizeof(remote)) != 0) {
		fprintf(stderr, "external: selected addresses unavailable\n");
		return -1;
	}
	if (strstr(local, "127.0.0.1") == NULL || strstr(remote, "127.0.0.1") == NULL) {
		fprintf(stderr, "external: unexpected selected addresses %s -> %s\n", local, remote);
		return -1;
	}

	juice_destroy(endpoint_a.agent);
	juice_destroy(endpoint_b.agent);
	endpoint_a.agent = NULL;
	endpoint_b.agent = NULL;

	printf("External-mode ICE selected %s -> %s\n", local, remote);
	return 0;
}
