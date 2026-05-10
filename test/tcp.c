/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "juice/juice.h"

#include "stun.h"
#include "tcp.h"
#include "thread.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static void sleep(unsigned int secs) { Sleep(secs * 1000); }
#else
#include <unistd.h> // for sleep
#endif

#define STUN_WRITE_BUFFER_SIZE 150
#define ICE_PWD "pw01234567890123456789"

atomic(bool) local_gathered_ice_tcp_candidate = false;

static void on_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	if (strstr(sdp, "9 typ host tcptype active")) {
		atomic_store(&local_gathered_ice_tcp_candidate, true);
	}
}

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	printf("State: %s\n", juice_state_to_string(state));
}

socket_t start_ice_tcp_server(int ice_tcp_server_port) {
	socket_t server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket == INVALID_SOCKET)
		return INVALID_SOCKET;

	struct sockaddr_in server_sockaddr;
	memset(&server_sockaddr, 0, sizeof(server_sockaddr));
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_sockaddr.sin_port = htons(ice_tcp_server_port);

	if ((bind(server_socket, (const struct sockaddr *)&server_sockaddr, sizeof(server_sockaddr))) !=
	    0)
		goto error;

	if (listen(server_socket, 1) != 0)
		goto error;

	return server_socket;

error:
	closesocket(server_socket);
	return INVALID_SOCKET;
}

void run_passive_ice_tcp(socket_t server_socket) {
	socket_t client_socket = accept(server_socket, NULL, NULL);
	if(client_socket == INVALID_SOCKET)
		return;

	tcp_conn_t *conn = _tcp_conn_init(TCP_FRAMING_ICE);
	if (!conn) {
		closesocket(client_socket);
		return;
	}

	for (int i = 0; i < 2;) {
		int len;
		if ((len = _juice_tcp_ice_read(client_socket, &conn->read)) < 0)
			goto done;

		stun_message_t msg;
		memset(&msg, 0, sizeof(msg));

		if (_juice_stun_read(conn->read.buffer, len, &msg) < 0)
			goto done;

		if (msg.msg_class != STUN_CLASS_REQUEST)
			continue;

		msg.msg_class = STUN_CLASS_RESP_SUCCESS;
		msg.msg_method = STUN_METHOD_BINDING;
		msg.priority = 0;
		msg.ice_controlling = 0;

		char buffer[STUN_WRITE_BUFFER_SIZE];
		if ((len = _juice_stun_write(buffer, STUN_WRITE_BUFFER_SIZE, &msg, ICE_PWD)) < 0)
			goto done;

		if (_juice_tcp_ice_write(client_socket, buffer, len, &conn->write) < 0)
			goto done;

		i++;
	}

done:
	free(conn);
	closesocket(server_socket);
	(void)client_socket; // intentionally kept open: agent must not lose connectivity before sleep(2)
}

int test_tcp() {
	juice_config_t config;
	memset(&config, 0, sizeof(config));

	config.cb_state_changed = on_state_changed;
	config.cb_candidate = on_candidate;

	juice_agent_t *agent = juice_create(&config);
	if (juice_set_local_ice_attributes(agent, "ufrag", "pw01234567890123456789")) {
		printf("Failure\n");
		return -1;
	}

	if (juice_set_ice_tcp_mode(agent, JUICE_ICE_TCP_MODE_ACTIVE)) {
		printf("Failure\n");
		return -1;
	}

	srand((unsigned int)time(NULL));
	int ice_tcp_server_port = (rand() % (6000 - 5000 + 1)) + 5000;
	socket_t server_socket = start_ice_tcp_server(ice_tcp_server_port);
	if (server_socket == INVALID_SOCKET) {
		printf("Failure\n");
		return -1;
	}

	char sdp[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent, sdp, JUICE_MAX_SDP_STRING_LEN);

	snprintf(sdp, JUICE_MAX_SDP_STRING_LEN,
	         "a=ice-ufrag:ufrag\r\n"
	         "a=ice-pwd:%s\r\n"
	         "a=candidate:1 1 TCP 2122316799 127.0.0.1 %d typ host tcptype passive\r\n"
	         "a=candidate:2 1 TCP 3122316799 127.0.0.1 %d typ host tcptype so\r\n"
	         "a=candidate:3 1 TCP 4122316799 127.0.0.1 9 typ host tcptype active\r\n",
	         ICE_PWD, ice_tcp_server_port + 2, ice_tcp_server_port);

	juice_set_remote_description(agent, sdp);
	juice_gather_candidates(agent);

	run_passive_ice_tcp(server_socket);
	sleep(2);

	bool success = juice_get_state(agent) == JUICE_STATE_COMPLETED &&
	               atomic_load(&local_gathered_ice_tcp_candidate);

	// Agent destroy
	juice_destroy(agent);

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}

static int make_tcp_loopback_pair(socket_t *wr, socket_t *rd) {
	struct sockaddr_in addr;
	socklen_t len;
	socket_t server, client, accepted;
	ctl_t nbio;
	int reuse = 1;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server == INVALID_SOCKET) {
		printf("make_tcp_loopback_pair: server socket() failed errno=%d\n", sockerrno);
		return -1;
	}

	setsockopt(server, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

	if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		printf("make_tcp_loopback_pair: bind() failed errno=%d\n", sockerrno);
		goto error_server;
	}

	len = sizeof(addr);
	if (getsockname(server, (struct sockaddr *)&addr, &len) != 0) {
		printf("make_tcp_loopback_pair: getsockname() failed errno=%d\n", sockerrno);
		goto error_server;
	}

	if (listen(server, 1) != 0) {
		printf("make_tcp_loopback_pair: listen() failed errno=%d\n", sockerrno);
		goto error_server;
	}

	client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client == INVALID_SOCKET) {
		printf("make_tcp_loopback_pair: client socket() failed errno=%d\n", sockerrno);
		goto error_server;
	}

	// Use non-blocking connect so we can call accept() on the same thread
	// without risking a deadlock if the kernel waits for accept before
	// completing the handshake.
	nbio = 1;
	ioctlsocket(client, FIONBIO, &nbio);

	connect(client, (struct sockaddr *)&addr, sizeof(addr));
	// connect returns WSAEWOULDBLOCK / EINPROGRESS — that's expected

	accepted = accept(server, NULL, NULL);
	closesocket(server);
	if (accepted == INVALID_SOCKET) {
		printf("make_tcp_loopback_pair: accept() failed errno=%d\n", sockerrno);
		closesocket(client);
		return -1;
	}

	// Wait for client-side connect to finish, then restore blocking mode.
	{
		struct pollfd pfd;
		pfd.fd = client;
		pfd.events = POLLOUT;
		pfd.revents = 0;
		if (poll(&pfd, 1, 2000) <= 0) {
			printf("make_tcp_loopback_pair: poll() timed out waiting for connect\n");
			closesocket(client);
			closesocket(accepted);
			return -1;
		}
	}

	nbio = 0;
	ioctlsocket(client, FIONBIO, &nbio);  // writer is blocking

	nbio = 1;
	ioctlsocket(accepted, FIONBIO, &nbio); // reader is non-blocking

	*wr = client;
	*rd = accepted;
	return 0;

error_server:
	closesocket(server);
	return -1;
}

static int tcp_ice_read_retry(socket_t rd, tcp_read_context_t *ctx) {
	for (int i = 0; i < 200; i++) {
		int ret = _juice_tcp_ice_read(rd, ctx);
		if (ret != -SEAGAIN && ret != -SEWOULDBLOCK)
			return ret;
#ifdef _WIN32
		Sleep(1);
#else
		usleep(1000);
#endif
	}
	return -SEAGAIN;
}

static int tcp_stun_read_retry(socket_t rd, tcp_read_context_t *ctx) {
	for (int i = 0; i < 200; i++) {
		int ret = _juice_tcp_stun_read(rd, ctx);
		if (ret != -SEAGAIN && ret != -SEWOULDBLOCK)
			return ret;
#ifdef _WIN32
		Sleep(1);
#else
		usleep(1000);
#endif
	}
	return -SEAGAIN;
}

static void wait_for_data(void) {
#ifdef _WIN32
	Sleep(5);
#else
	usleep(5000);
#endif
}

int test_tcp_ice_read_unit(void) {
	// Frame: 2-byte RFC4571 header (length=3) + payload "abc"
	char frame[] = {0x00, 0x03, 'a', 'b', 'c'};
	int frame_size = (int)sizeof(frame);

	// Test all first-chunk sizes 1..(header_size+1) = 1..3.
	// Covers every split within the 2-byte header plus one byte into the payload.
	for (int first = 1; first <= 3; first++) {
		socket_t wr, rd;
		if (make_tcp_loopback_pair(&wr, &rd) != 0) {
			printf("Failure (socket pair for first=%d)\n", first);
			return -1;
		}

		tcp_conn_t* ctx = _tcp_conn_init(TCP_FRAMING_ICE);

		send(wr, frame, first, 0);
		wait_for_data();

		int ret = _juice_tcp_ice_read(rd, &ctx->read);
		if (ret != -SEAGAIN && ret != -SEWOULDBLOCK) {
			printf("ICE-TCP fragmented (first=%d): expected EAGAIN, got %d\n", first, ret);
			closesocket(wr);
			closesocket(rd);
			return -1;
		}

		send(wr, frame + first, frame_size - first, 0);
		ret = tcp_ice_read_retry(rd, &ctx->read);
		if (ret != 3 || memcmp(ctx->read.buffer, "abc", 3) != 0) {
			printf("ICE-TCP fragmented (first=%d): expected 3/'abc', got ret=%d\n", first, ret);
			closesocket(wr);
			closesocket(rd);
			return -1;
		}

		closesocket(wr);
		closesocket(rd);
	}

	// Empty datagram (length==0) followed by a real frame — must be silently discarded.
	{
		socket_t wr, rd;
		if (make_tcp_loopback_pair(&wr, &rd) != 0) {
			printf("Failure (socket pair for empty datagram test)\n");
			return -1;
		}

		char frames[] = {0x00, 0x00,  // empty frame
		                 0x00, 0x04, 'd', 'a', 't', 'a'};
		tcp_conn_t* ctx = _tcp_conn_init(TCP_FRAMING_ICE);
		
		send(wr, frames, sizeof(frames), 0);
		int ret = tcp_ice_read_retry(rd, &ctx->read);
		if (ret != 4 || memcmp(ctx->read.buffer, "data", 4) != 0) {
			printf("ICE-TCP empty datagram: expected 4/'data', got ret=%d\n", ret);
			closesocket(wr);
			closesocket(rd);
			return -1;
		}

		closesocket(wr);
		closesocket(rd);
	}

	printf("Success\n");
	return 0;
}

int test_tcp_stun_read_unit(void) {
	// ChannelData frame (first byte 0x40..0x4F): 4-byte header + payload.
	// Header: channel=0x4000 (bytes 0-1), length=4 (bytes 2-3), payload "data".
	// No padding needed (4 bytes payload is already 4-byte aligned).
	char frame[] = {0x40, 0x00, 0x00, 0x04, 'd', 'a', 't', 'a'};
	int frame_size = (int)sizeof(frame);

	// Test all first-chunk sizes 1..(CHANNEL_DATA_HEADER_SIZE+1) = 1..5.
	// Covers every split within the 4-byte minimum header plus one byte into the payload.
	for (int first = 1; first <= 5; first++) {
		socket_t wr, rd;
		if (make_tcp_loopback_pair(&wr, &rd) != 0) {
			printf("Failure (socket pair for first=%d)\n", first);
			return -1;
		}

		tcp_conn_t* ctx = _tcp_conn_init(TCP_FRAMING_STUN);

		send(wr, frame, first, 0);
		wait_for_data();

		int ret = _juice_tcp_stun_read(rd, &ctx->read);
		if (ret != -SEAGAIN && ret != -SEWOULDBLOCK) {
			printf("TURN-TCP fragmented (first=%d): expected EAGAIN, got %d\n", first, ret);
			closesocket(wr);
			closesocket(rd);
			return -1;
		}

		send(wr, frame + first, frame_size - first, 0);
		ret = tcp_stun_read_retry(rd, &ctx->read);
		if (ret != frame_size || memcmp(ctx->read.buffer, frame, frame_size) != 0) {
			printf("TURN-TCP fragmented (first=%d): expected %d bytes, got ret=%d\n", first, frame_size, ret);
			closesocket(wr);
			closesocket(rd);
			return -1;
		}

		closesocket(wr);
		closesocket(rd);
	}

	// STUN message (first byte 0x00..0x3F): 20-byte header + payload.
	// Minimal binding request: 4-byte channel header + 16-byte rest, no attributes (length=0).
	// Total 20 bytes.
	{
		char stun_frame[20];
		memset(stun_frame, 0, sizeof(stun_frame));
		stun_frame[0] = 0x00; stun_frame[1] = 0x01; // Binding request
		stun_frame[2] = 0x00; stun_frame[3] = 0x00; // Length = 0
		stun_frame[4] = 0x21; stun_frame[5] = 0x12; // Magic cookie
		stun_frame[6] = 0xA4; stun_frame[7] = 0x42;
		// transaction ID: bytes 8-19, leave as zero

		// Test all splits through CHANNEL_DATA_HEADER_SIZE+1 = 5
		for (int first = 1; first <= 5; first++) {
			socket_t wr, rd;
			if (make_tcp_loopback_pair(&wr, &rd) != 0) {
				printf("Failure (socket pair for STUN first=%d)\n", first);
				return -1;
			}

			tcp_conn_t* ctx = _tcp_conn_init(TCP_FRAMING_STUN);

			send(wr, stun_frame, first, 0);
			wait_for_data();

			int ret = _juice_tcp_stun_read(rd, &ctx->read);
			if (ret != -SEAGAIN && ret != -SEWOULDBLOCK) {
				printf("TURN-TCP STUN fragmented (first=%d): expected EAGAIN, got %d\n", first, ret);
				closesocket(wr);
				closesocket(rd);
				return -1;
			}

			send(wr, stun_frame + first, 20 - first, 0);
			ret = tcp_stun_read_retry(rd, &ctx->read);
			if (ret != 20 || memcmp(ctx->read.buffer, stun_frame, 20) != 0) {
				printf("TURN-TCP STUN fragmented (first=%d): expected 20 bytes, got ret=%d\n", first, ret);
				closesocket(wr);
				closesocket(rd);
				return -1;
			}

			closesocket(wr);
			closesocket(rd);
		}
	}

	printf("Success\n");
	return 0;
}

// Verify that tcp_stun_write/read reject payloads larger than TCP_BUFFER_SIZE.
int test_tcp_stun_max_size(void) {
	// Write: payload exactly at limit must succeed; one byte over must fail.
	{
		socket_t wr, rd;
		if (make_tcp_loopback_pair(&wr, &rd) != 0) {
			printf("Failure: socket pair\n");
			return -1;
		}
		tcp_conn_t *wc = _tcp_conn_init(TCP_FRAMING_STUN);
		char *buf = (char *)malloc(TCP_BUFFER_SIZE + 1);
		if (!wc || !buf) { printf("Failure: alloc\n"); return -1; }

		// Build a minimal STUN frame sized exactly at TCP_BUFFER_SIZE
		memset(buf, 0, TCP_BUFFER_SIZE);
		buf[0] = 0x00; buf[1] = 0x01; // binding request
		uint16_t pl_be = htons((uint16_t)(TCP_BUFFER_SIZE - STUN_HEADER_SIZE));
		memcpy(buf + 2, &pl_be, 2);

		int ret = _juice_tcp_stun_write(wr, buf, TCP_BUFFER_SIZE, &wc->write);
		if (ret < 0) {
			printf("Failure: write at limit returned %d\n", ret);
			free(wc); free(buf); closesocket(wr); closesocket(rd);
			return -1;
		}

		// One byte over the limit must be rejected immediately
		wc->write.pending = false;
		ret = _juice_tcp_stun_write(wr, buf, TCP_BUFFER_SIZE + 1, &wc->write);
		if (ret != -SEMSGSIZE) {
			printf("Failure: write over limit expected -SEMSGSIZE, got %d\n", ret);
			free(wc); free(buf); closesocket(wr); closesocket(rd);
			return -1;
		}

		free(wc); free(buf);
		closesocket(wr); closesocket(rd);
	}

	printf("Success\n");
	return 0;
}

// conn_poll_send compared `ret == SEAGAIN` (positive) against the
// return value of tcp_ice_write, which always returns -SEAGAIN (negative).
// The mismatch meant a buffered pending write was never recognised as "sent".
// This test verifies tcp_ice_write returns a strictly negative value when a
// prior write is still pending, so the fixed `ret == -SEAGAIN` comparison works.
int test_tcp_ice_write_eagain(void) {
	socket_t wr, rd;
	if (make_tcp_loopback_pair(&wr, &rd) != 0) {
		printf("Failure: socket pair\n");
		return -1;
	}

	tcp_conn_t *ctx = _tcp_conn_init(TCP_FRAMING_ICE);
	if (!ctx) {
		printf("Failure: init\n");
		closesocket(wr); closesocket(rd);
		return -1;
	}

	char data[64];
	memset(data, 0xAB, sizeof(data));

	// Simulate a pending write: mark the context as if a prior send() filled
	// the OS buffer and the datagram is waiting for a retry.  When data != NULL
	// and pending == true, tcp_ice_write immediately returns -SEAGAIN (line 64
	// in tcp.c) without calling send() at all, so the result is deterministic.
	ctx->write.pending = true;

	int ret = _juice_tcp_ice_write(wr, data, sizeof(data), &ctx->write);

	bool ok = true;
	// Must return a NEGATIVE errno so conn_poll_send's fixed `ret == -SEAGAIN`
	// comparison matches.  The old bug used `ret == SEAGAIN` (positive) which
	// could never be true, causing spurious send failures.
	if (ret != -SEAGAIN && ret != -SEWOULDBLOCK) {
		printf("tcp_ice_write EAGAIN: expected -SEAGAIN or -SEWOULDBLOCK, got %d\n", ret);
		ok = false;
	}
	// Guard: a positive return would have satisfied the OLD buggy comparison —
	// that would be a regression, not a fix.
	if (ret > 0) {
		printf("tcp_ice_write EAGAIN: got positive ret=%d (old buggy path)\n", ret);
		ok = false;
	}

	free(ctx);
	closesocket(wr);
	closesocket(rd);

	if (!ok) { printf("Failure\n"); return -1; }
	printf("Success\n");
	return 0;
}

static juice_agent_t *agent1;
static juice_agent_t *agent2;

static void on_candidate_bad_tcp_1(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	juice_add_remote_candidate(agent2, sdp);
}

static void on_candidate_bad_tcp_2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	juice_add_remote_candidate(agent1, sdp);
}

int test_tcp_bad_candidate() {
	juice_config_t config1;
	memset(&config1, 0, sizeof(config1));

	config1.cb_candidate = on_candidate_bad_tcp_1;
	config1.user_ptr = NULL;

	agent1 = juice_create(&config1);

	juice_config_t config2;
	memset(&config2, 0, sizeof(config2));

	config1.cb_candidate = on_candidate_bad_tcp_2;
	config2.user_ptr = NULL;

	agent2 = juice_create(&config2);

	if (juice_set_ice_tcp_mode(agent1, JUICE_ICE_TCP_MODE_ACTIVE) || juice_set_ice_tcp_mode(agent2, JUICE_ICE_TCP_MODE_ACTIVE)) {
		printf("Failure\n");
		return -1;
	}

	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent1, sdp1, JUICE_MAX_SDP_STRING_LEN);
	juice_set_remote_description(agent2, sdp1);

	char sdp2[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(agent2, sdp2, JUICE_MAX_SDP_STRING_LEN);
	juice_set_remote_description(agent1, sdp2);

	// Candidate that doesn't exist
	juice_add_remote_candidate(agent1, "a=candidate:1 1 TCP 2122316799 127.0.0.1 1337 typ host tcptype passive");

	juice_gather_candidates(agent1);
	sleep(2);

	juice_gather_candidates(agent2);
	sleep(2);

	bool success = (juice_get_state(agent1) == JUICE_STATE_COMPLETED && juice_get_state(agent2) == JUICE_STATE_COMPLETED);

	juice_destroy(agent1);
	juice_destroy(agent2);

	if (success) {
		printf("Success\n");
		return 0;
	} else {
		printf("Failure\n");
		return -1;
	}
}

