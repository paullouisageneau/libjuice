/**
 * Copyright (c) 2026 Nemirtingas
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
static void sleep_ms(unsigned int ms) { Sleep(ms); }
static CRITICAL_SECTION recv_lock;
static void lock_init(void) { InitializeCriticalSection(&recv_lock); }
static void lock_destroy(void) { DeleteCriticalSection(&recv_lock); }
static void lock(void) { EnterCriticalSection(&recv_lock); }
static void unlock(void) { LeaveCriticalSection(&recv_lock); }
#else
#include <pthread.h>
#include <unistd.h>
static void sleep_ms(unsigned int ms) { usleep(ms * 1000); }
static pthread_mutex_t recv_lock = PTHREAD_MUTEX_INITIALIZER;
static void lock_init(void) {}
static void lock_destroy(void) {}
static void lock(void) { pthread_mutex_lock(&recv_lock); }
static void unlock(void) { pthread_mutex_unlock(&recv_lock); }
#endif

#define BATCH_TURN_PORT 3479
#define BATCH_TURN_USERNAME "batch_test"
#define BATCH_TURN_PASSWORD "51837264098351"

// Larger than the internal batch limit to test chunking
#define MAX_RECORDS 512
// Receive buffers of agents and server are 4096 bytes
#define MAX_DATAGRAM_SIZE 4096
// The local TURN server fails to relay datagrams larger than about 4 KiB minus headers,
// with single sends as well
#define MAX_RELAYED_DATAGRAM_SIZE 4000

typedef enum candidate_filter {
	FILTER_NONE = 0,
	FILTER_IPV4, // IPv4 candidates only, to test IPv4-mapped addresses on dual-stack sockets
	FILTER_RELAY // relayed candidates only
} candidate_filter_t;

typedef struct batch_scenario {
	const char *name;
	juice_concurrency_mode_t mode1; // sender
	juice_concurrency_mode_t mode2; // receiver
	uint16_t port1;
	uint16_t port2;
	candidate_filter_t filter;
} batch_scenario_t;

typedef struct record {
	size_t size;
	char data[MAX_DATAGRAM_SIZE];
} record_t;

static juice_agent_t *agent1;
static juice_agent_t *agent2;
static candidate_filter_t filter;

static record_t *received;    // written by the receiving agent thread
static size_t received_count; // protected by recv_lock
static bool received_overflow;
static size_t expected_count; // number of datagrams sent so far, only used by the main thread

static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr);
static void on_gathering_done1(juice_agent_t *agent, void *user_ptr);
static void on_gathering_done2(juice_agent_t *agent, void *user_ptr);
static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr);

// Deterministic content for the datagram with sequence number seq
static void fill_datagram(char *data, size_t size, size_t seq) {
	for (size_t i = 0; i < size; ++i)
		data[i] = (char)((seq * 131 + i * 7 + (i >> 8)) & 0xFF);
}

static bool wait_received(size_t count, unsigned int timeout_ms) {
	for (unsigned int t = 0; t < timeout_ms; t += 10) {
		lock();
		size_t current = received_count;
		unlock();
		if (current >= count)
			return true;
		sleep_ms(10);
	}
	return false;
}

// Check that the datagrams with sequence numbers [first, first + count) arrived intact and in order
static bool check_received(size_t first, const size_t *sizes, size_t count) {
	if (!wait_received(first + count, 5000)) {
		lock();
		printf("Timeout: received %d datagrams, expected %d\n", (int)received_count,
		       (int)(first + count));
		unlock();
		return false;
	}

	sleep_ms(50); // make sure no unexpected datagram arrives
	lock();
	bool success = !received_overflow && received_count == first + count;
	if (!success)
		printf("Received %d datagrams, expected %d\n", (int)received_count, (int)(first + count));

	char *expected = malloc(MAX_DATAGRAM_SIZE);
	for (size_t i = 0; success && i < count; ++i) {
		const record_t *r = received + first + i;
		fill_datagram(expected, sizes[i], first + i);
		if (r->size != sizes[i] || memcmp(r->data, expected, sizes[i]) != 0) {
			printf("Datagram %d mismatch: received size %d, expected size %d\n", (int)(first + i),
			       (int)r->size, (int)sizes[i]);
			success = false;
		}
	}
	free(expected);
	unlock();
	return success;
}

// Send a batch of datagrams with the given sizes, retrying on partial sends, and check reception
static bool send_and_check(const size_t *sizes, size_t count, int ds) {
	juice_buffer_t *buffers = calloc(count, sizeof(juice_buffer_t));
	char *storage = malloc(count * MAX_DATAGRAM_SIZE);
	if (!buffers || !storage) {
		free(buffers);
		free(storage);
		return false;
	}

	size_t first = expected_count;
	for (size_t i = 0; i < count; ++i) {
		char *data = storage + i * MAX_DATAGRAM_SIZE;
		fill_datagram(data, sizes[i], first + i);
		buffers[i].data = data;
		buffers[i].size = sizes[i];
	}

	bool success = true;
	size_t sent = 0;
	int retries = 0;
	while (sent < count) {
		int ret = ds != 0 ? juice_send_batch_diffserv(agent1, buffers + sent, count - sent, ds)
		                  : juice_send_batch(agent1, buffers + sent, count - sent);
		if (ret == JUICE_ERR_AGAIN && ++retries < 100) {
			sleep_ms(10);
			continue;
		}
		if (ret <= 0 || (size_t)ret > count - sent) {
			printf("juice_send_batch failed, ret=%d\n", ret);
			success = false;
			break;
		}
		sent += (size_t)ret;
	}

	expected_count += sent;
	if (success)
		success = check_received(first, sizes, count);

	free(buffers);
	free(storage);
	return success;
}

static bool send_single_and_check(size_t size) {
	char *data = malloc(size);
	size_t first = expected_count;
	fill_datagram(data, size, first);
	bool success = juice_send(agent1, data, size) == JUICE_ERR_SUCCESS;
	free(data);
	if (!success) {
		printf("juice_send failed\n");
		return false;
	}
	++expected_count;
	return check_received(first, &size, 1);
}

static bool run_checks(size_t max_size) {
	size_t sizes[MAX_RECORDS];

	// Count 0
	juice_buffer_t empty = {NULL, 0};
	if (juice_send_batch(agent1, NULL, 0) != 0 || juice_send_batch(agent1, &empty, 0) != 0) {
		printf("Empty batch failed\n");
		return false;
	}

	// Count 1
	sizes[0] = 100;
	if (!send_and_check(sizes, 1, 0)) {
		printf("Single datagram batch failed\n");
		return false;
	}

	// Various sizes
	for (size_t i = 0; i < 10; ++i)
		sizes[i] = 1 + i * 133;
	if (!send_and_check(sizes, 10, 0)) {
		printf("Batch with various sizes failed\n");
		return false;
	}

	// Same size with a shorter last datagram, larger than the internal limit
	for (size_t i = 0; i < 150; ++i)
		sizes[i] = 1000;
	sizes[150] = 500;
	if (!send_and_check(sizes, 151, 0)) {
		printf("Large batch failed\n");
		return false;
	}

	// Runs of identical sizes interleaved with different sizes
	for (size_t i = 0; i < 100; ++i)
		sizes[i] = (i / 7) % 2 == 0 ? 1200 : 300 + (i % 3);
	if (!send_and_check(sizes, 100, 0)) {
		printf("Batch with runs of sizes failed\n");
		return false;
	}

	// Maximum size datagrams
	for (size_t i = 0; i < 15; ++i)
		sizes[i] = max_size;
	if (!send_and_check(sizes, 15, 0)) {
		printf("Batch with maximum size datagrams failed\n");
		return false;
	}

	// Differentiated Services (Expedited Forwarding)
	for (size_t i = 0; i < 20; ++i)
		sizes[i] = 800;
	if (!send_and_check(sizes, 20, 0xB8)) {
		printf("Batch with Differentiated Services failed\n");
		return false;
	}

	// Interleaved with single sends
	sizes[0] = 50;
	sizes[1] = 60;
	sizes[2] = 70;
	if (!send_single_and_check(42) || !send_and_check(sizes, 3, 0) || !send_single_and_check(43)) {
		printf("Batch interleaved with single sends failed\n");
		return false;
	}

	// Invalid arguments
	juice_buffer_t invalid = {NULL, 10};
	if (juice_send_batch(NULL, &empty, 1) != JUICE_ERR_INVALID ||
	    juice_send_batch(agent1, NULL, 1) != JUICE_ERR_INVALID ||
	    juice_send_batch(agent1, &invalid, 1) != JUICE_ERR_INVALID) {
		printf("Invalid arguments check failed\n");
		return false;
	}

	return true;
}

static bool wait_completed(unsigned int timeout_ms) {
	for (unsigned int t = 0; t < timeout_ms; t += 100) {
		juice_state_t state1 = juice_get_state(agent1);
		juice_state_t state2 = juice_get_state(agent2);
		if (state1 == JUICE_STATE_FAILED || state2 == JUICE_STATE_FAILED)
			return false;
		if (state1 == JUICE_STATE_COMPLETED && state2 == JUICE_STATE_COMPLETED)
			return true;
		sleep_ms(100);
	}
	return false;
}

static int run_scenario(const batch_scenario_t *scenario) {
	printf("Batch scenario: %s\n", scenario->name);

	received_count = 0;
	received_overflow = false;
	expected_count = 0;
	filter = scenario->filter;
	bool turn = scenario->filter == FILTER_RELAY;

	// To make sure the sender uses its relayed candidate, it is bound to IPv4 localhost while
	// relayed addresses are on IPv6 localhost. Otherwise, as TURN permissions only consider IP
	// addresses, the sender could reach the relayed candidate of the receiver directly.
	juice_server_t *server = NULL;
	juice_turn_server_t turn_server;
	memset(&turn_server, 0, sizeof(turn_server));
	if (turn) {
#ifndef NO_SERVER
		juice_server_credentials_t credentials;
		memset(&credentials, 0, sizeof(credentials));
		credentials.username = BATCH_TURN_USERNAME;
		credentials.password = BATCH_TURN_PASSWORD;

		juice_server_config_t server_config;
		memset(&server_config, 0, sizeof(server_config));
		server_config.port = BATCH_TURN_PORT;
		server_config.credentials = &credentials;
		server_config.credentials_count = 1;
		server_config.max_allocations = 10;
		server_config.realm = "Juice batch test";
		server_config.external_address = "::1";
		server = juice_server_create(&server_config);
		if (!server) {
			printf("Server creation failed\n");
			return -1;
		}

		turn_server.host = "127.0.0.1";
		turn_server.port = BATCH_TURN_PORT;
		turn_server.username = BATCH_TURN_USERNAME;
		turn_server.password = BATCH_TURN_PASSWORD;
#else
		printf("Skipped, no server support\n");
		return 0;
#endif
	}

	juice_config_t config1;
	memset(&config1, 0, sizeof(config1));
	config1.concurrency_mode = scenario->mode1;
	config1.local_port_range_begin = scenario->port1;
	config1.local_port_range_end = scenario->port1;
	config1.cb_candidate = on_candidate1;
	config1.cb_gathering_done = on_gathering_done1;
	if (turn) {
		config1.bind_address = "127.0.0.1";
		config1.turn_servers = &turn_server;
		config1.turn_servers_count = 1;
	}
	agent1 = juice_create(&config1);

	juice_config_t config2;
	memset(&config2, 0, sizeof(config2));
	config2.concurrency_mode = scenario->mode2;
	config2.local_port_range_begin = scenario->port2;
	config2.local_port_range_end = scenario->port2;
	config2.cb_candidate = on_candidate2;
	config2.cb_gathering_done = on_gathering_done2;
	config2.cb_recv = on_recv2;
	if (turn) {
		config2.turn_servers = &turn_server;
		config2.turn_servers_count = 1;
	}
	agent2 = juice_create(&config2);

	bool success = agent1 && agent2;
	if (success) {
		char sdp1[JUICE_MAX_SDP_STRING_LEN];
		juice_get_local_description(agent1, sdp1, JUICE_MAX_SDP_STRING_LEN);
		juice_set_remote_description(agent2, sdp1);

		char sdp2[JUICE_MAX_SDP_STRING_LEN];
		juice_get_local_description(agent2, sdp2, JUICE_MAX_SDP_STRING_LEN);
		juice_set_remote_description(agent1, sdp2);

		juice_gather_candidates(agent1);
		juice_gather_candidates(agent2);

		success = wait_completed(15000);
		if (!success)
			printf("Connection failed\n");
	}

	if (success) {
		char local[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
		char remote[JUICE_MAX_CANDIDATE_SDP_STRING_LEN];
		if (juice_get_selected_candidates(agent1, local, JUICE_MAX_CANDIDATE_SDP_STRING_LEN, remote,
		                                  JUICE_MAX_CANDIDATE_SDP_STRING_LEN) == 0) {
			printf("Local candidate  1: %s\n", local);
			printf("Remote candidate 1: %s\n", remote);
			if (turn && !strstr(local, "typ relay"))
				success = false; // must be relayed
		} else {
			success = false;
		}
	}

	if (success)
		success = run_checks(turn ? MAX_RELAYED_DATAGRAM_SIZE : MAX_DATAGRAM_SIZE);

	juice_destroy(agent1);
	juice_destroy(agent2);
	agent1 = agent2 = NULL;

	if (server)
		juice_server_destroy(server);

	printf("%s\n", success ? "Success" : "Failure");
	return success ? 0 : -1;
}

int test_batch(void) {
	juice_set_log_level(JUICE_LOG_LEVEL_WARN);

	received = calloc(MAX_RECORDS, sizeof(record_t));
	if (!received)
		return -1;

	lock_init();

	const batch_scenario_t scenarios[] = {
	    {"poll to poll", JUICE_CONCURRENCY_MODE_POLL, JUICE_CONCURRENCY_MODE_POLL, 0, 0,
	     FILTER_NONE},
	    {"poll to poll over IPv4", JUICE_CONCURRENCY_MODE_POLL, JUICE_CONCURRENCY_MODE_POLL, 0, 0,
	     FILTER_IPV4},
	    {"thread to thread", JUICE_CONCURRENCY_MODE_THREAD, JUICE_CONCURRENCY_MODE_THREAD, 0, 0,
	     FILTER_NONE},
	    {"mux to poll", JUICE_CONCURRENCY_MODE_MUX, JUICE_CONCURRENCY_MODE_POLL, 60010, 0,
	     FILTER_NONE},
	    {"poll to mux", JUICE_CONCURRENCY_MODE_POLL, JUICE_CONCURRENCY_MODE_MUX, 0, 60011,
	     FILTER_NONE},
	    {"poll to poll via TURN", JUICE_CONCURRENCY_MODE_POLL, JUICE_CONCURRENCY_MODE_POLL, 0, 0,
	     FILTER_RELAY},
	    {"thread to poll via TURN", JUICE_CONCURRENCY_MODE_THREAD, JUICE_CONCURRENCY_MODE_POLL, 0,
	     0, FILTER_RELAY}, // TURN is not supported in mux mode
	};

	int ret = 0;
	for (size_t i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); ++i) {
		if (run_scenario(scenarios + i) < 0) {
			ret = -1;
			break;
		}
	}

	if (ret == 0) {
		// Sending while not connected must fail
		juice_config_t config;
		memset(&config, 0, sizeof(config));
		juice_agent_t *agent = juice_create(&config);
		juice_buffer_t buffer = {"test", 4};
		if (juice_send_batch(agent, &buffer, 1) != JUICE_ERR_FAILED) {
			printf("Sending while not connected did not fail\n");
			ret = -1;
		}
		juice_destroy(agent);
	}

	lock_destroy();
	free(received);
	received = NULL;
	return ret;
}

static bool accept_candidate(const char *sdp) {
	switch (filter) {
	case FILTER_IPV4: {
		// a=candidate:<foundation> <component> <transport> <priority> <address> <port> typ ...
		char address[64];
		if (sscanf(sdp, "a=candidate:%*s %*s %*s %*s %63s", address) != 1)
			return false;
		return strchr(address, ':') == NULL;
	}
	case FILTER_RELAY:
		return strstr(sdp, " typ relay") != NULL;
	default:
		return true;
	}
}

static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	if (!accept_candidate(sdp))
		return;

	juice_add_remote_candidate(agent2, sdp);
}

static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	if (!accept_candidate(sdp))
		return;

	juice_add_remote_candidate(agent1, sdp);
}

static void on_gathering_done1(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	juice_set_remote_gathering_done(agent2);
}

static void on_gathering_done2(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	juice_set_remote_gathering_done(agent1);
}

static void on_recv2(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	(void)agent;
	(void)user_ptr;
	lock();
	if (received_count < MAX_RECORDS && size <= MAX_DATAGRAM_SIZE) {
		record_t *r = received + received_count;
		r->size = size;
		memcpy(r->data, data, size);
		++received_count;
	} else {
		received_overflow = true;
	}
	unlock();
}
