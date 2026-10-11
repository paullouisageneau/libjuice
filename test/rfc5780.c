/**
 * Copyright (c) 2026 Daniel Golle
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "juice/juice.h"
#include "stun.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET test_socket_t;
#define TEST_INVALID_SOCKET INVALID_SOCKET
#define test_closesocket closesocket
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
typedef int test_socket_t;
#define TEST_INVALID_SOCKET (-1)
#define test_closesocket close
#endif

#define BUFFER_SIZE 4096
#define LOCALHOST 0x7F000001 // 127.0.0.1

static const uint8_t transaction_id[STUN_TRANSACTION_ID_SIZE] = "0123456789A";

static void set_ipv4(addr_record_t *record, uint32_t address, uint16_t port) {
	memset(record, 0, sizeof(*record));
	struct sockaddr_in *sin = (struct sockaddr_in *)&record->addr;
	sin->sin_family = AF_INET;
	sin->sin_port = htons(port);
	sin->sin_addr.s_addr = htonl(address);
	record->len = sizeof(*sin);
	record->socktype = SOCK_DGRAM;
}

static bool is_ipv4(const addr_record_t *record, uint32_t address, uint16_t port) {
	if (record->addr.ss_family != AF_INET)
		return false;

	const struct sockaddr_in *sin = (const struct sockaddr_in *)&record->addr;
	return sin->sin_port == htons(port) && sin->sin_addr.s_addr == htonl(address);
}

static void init_binding_request(stun_message_t *msg) {
	memset(msg, 0, sizeof(*msg));
	msg->msg_class = STUN_CLASS_REQUEST;
	msg->msg_method = STUN_METHOD_BINDING;
	memcpy(msg->transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE);
}

static const uint8_t *find_attr(const uint8_t *buffer, int size, uint16_t type) {
	const uint8_t *pos = buffer + sizeof(struct stun_header);
	const uint8_t *end = buffer + size;
	while (pos + sizeof(struct stun_attr) <= end) {
		size_t length = (size_t)(pos[2] << 8 | pos[3]);
		if ((uint16_t)(pos[0] << 8 | pos[1]) == type)
			return pos;

		pos += sizeof(struct stun_attr) + ((length + 3) & ~(size_t)3);
	}
	return NULL;
}

static int test_rfc5780_request_attributes(void) {
	char padding[64];
	memset(padding, 0, sizeof(padding));

	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_class = STUN_CLASS_REQUEST;
	msg.msg_method = STUN_METHOD_BINDING;
	memcpy(msg.transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE);
	msg.change_request = STUN_CHANGE_REQUEST_IP | STUN_CHANGE_REQUEST_PORT;
	msg.has_change_request = true;
	msg.response_port = 3479;
	msg.has_response_port = true;
	msg.padding = padding;
	msg.padding_size = sizeof(padding);

	uint8_t buffer[BUFFER_SIZE];
	int size = _juice_stun_write(buffer, BUFFER_SIZE, &msg, NULL);
	if (size <= 0) {
		printf("Writing RFC 5780 request attributes failed\n");
		return -1;
	}

	stun_message_t parsed;
	memset(&parsed, 0, sizeof(parsed));
	if (_juice_stun_read(buffer, size, &parsed) <= 0) {
		printf("Reading RFC 5780 request attributes failed\n");
		return -1;
	}

	if (!parsed.has_change_request || !parsed.change_ip || !parsed.change_port) {
		printf("CHANGE-REQUEST is incorrect\n");
		return -1;
	}
	if (!parsed.has_response_port || parsed.response_port != 3479) {
		printf("RESPONSE-PORT is incorrect\n");
		return -1;
	}
	if (parsed.padding_size != sizeof(padding)) {
		printf("PADDING is incorrect\n");
		return -1;
	}

	const uint8_t *attr = find_attr(buffer, size, STUN_ATTR_RESPONSE_PORT);
	if (!attr || attr[2] != 0 || attr[3] != 2) {
		printf("RESPONSE-PORT attribute length is incorrect\n");
		return -1;
	}

	// Some implementations count the 2 padding bytes in the attribute length instead
	uint8_t raw[BUFFER_SIZE];
	memcpy(raw, buffer, sizeof(struct stun_header)); // same header, with a single attribute
	raw[2] = 0;
	raw[3] = sizeof(struct stun_attr) + 4;
	uint8_t *raw_attr = raw + sizeof(struct stun_header);
	raw_attr[0] = STUN_ATTR_RESPONSE_PORT >> 8;
	raw_attr[1] = STUN_ATTR_RESPONSE_PORT & 0xFF;
	raw_attr[2] = 0;
	raw_attr[3] = 4;
	raw_attr[4] = 3479 >> 8;
	raw_attr[5] = 3479 & 0xFF;
	raw_attr[6] = 0;
	raw_attr[7] = 0;

	size = (int)(sizeof(struct stun_header) + sizeof(struct stun_attr) + 4);
	memset(&parsed, 0, sizeof(parsed));
	if (_juice_stun_read(raw, size, &parsed) <= 0) {
		printf("Reading a 4-byte long RESPONSE-PORT failed\n");
		return -1;
	}
	if (!parsed.has_response_port || parsed.response_port != 3479) {
		printf("RESPONSE-PORT read from a 4-byte long attribute is incorrect\n");
		return -1;
	}

	return 0;
}

static int test_rfc5780_response_attributes(void) {
	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_class = STUN_CLASS_RESP_SUCCESS;
	msg.msg_method = STUN_METHOD_BINDING;
	memcpy(msg.transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE);
	set_ipv4(&msg.mapped, 0xC0000201, 12345);        // 192.0.2.1
	set_ipv4(&msg.response_origin, 0xC0000202, 3478); // 192.0.2.2
	set_ipv4(&msg.other_address, 0xC0000203, 3479);   // 192.0.2.3

	uint8_t buffer[BUFFER_SIZE];
	int size = _juice_stun_write(buffer, BUFFER_SIZE, &msg, NULL);
	if (size <= 0) {
		printf("Writing RFC 5780 response attributes failed\n");
		return -1;
	}

	stun_message_t parsed;
	memset(&parsed, 0, sizeof(parsed));
	if (_juice_stun_read(buffer, size, &parsed) <= 0) {
		printf("Reading RFC 5780 response attributes failed\n");
		return -1;
	}

	if (!is_ipv4(&parsed.mapped, 0xC0000201, 12345)) {
		printf("XOR-MAPPED-ADDRESS is incorrect\n");
		return -1;
	}
	if (!is_ipv4(&parsed.response_origin, 0xC0000202, 3478)) {
		printf("RESPONSE-ORIGIN is incorrect\n");
		return -1;
	}
	if (!is_ipv4(&parsed.other_address, 0xC0000203, 3479)) {
		printf("OTHER-ADDRESS is incorrect\n");
		return -1;
	}

	return 0;
}

static int test_rfc5780_unknown_attributes(void) {
	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_class = STUN_CLASS_RESP_ERROR;
	msg.msg_method = STUN_METHOD_BINDING;
	memcpy(msg.transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE);
	msg.error_code = 420;
	msg.unknown_attributes[0] = STUN_ATTR_CHANGE_REQUEST;
	msg.unknown_attributes_count = 1;

	uint8_t buffer[BUFFER_SIZE];
	int size = _juice_stun_write(buffer, BUFFER_SIZE, &msg, NULL);
	if (size <= 0) {
		printf("Writing UNKNOWN-ATTRIBUTES failed\n");
		return -1;
	}

	stun_message_t parsed;
	memset(&parsed, 0, sizeof(parsed));
	if (_juice_stun_read(buffer, size, &parsed) <= 0) {
		printf("Reading UNKNOWN-ATTRIBUTES failed\n");
		return -1;
	}

	if (parsed.error_code != 420) {
		printf("Error code is incorrect\n");
		return -1;
	}
	if (parsed.unknown_attributes_count != 1 ||
	    parsed.unknown_attributes[0] != STUN_ATTR_CHANGE_REQUEST) {
		printf("UNKNOWN-ATTRIBUTES is incorrect\n");
		return -1;
	}

	return 0;
}

#ifndef NO_SERVER

static test_socket_t create_test_socket(uint16_t *port) {
	test_socket_t sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == TEST_INVALID_SOCKET)
		return TEST_INVALID_SOCKET;

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(LOCALHOST);
	if (bind(sock, (const struct sockaddr *)&sin, sizeof(sin))) {
		test_closesocket(sock);
		return TEST_INVALID_SOCKET;
	}

	socklen_t sinlen = sizeof(sin);
	if (getsockname(sock, (struct sockaddr *)&sin, &sinlen)) {
		test_closesocket(sock);
		return TEST_INVALID_SOCKET;
	}
	*port = ntohs(sin.sin_port);

#ifdef _WIN32
	DWORD timeout = 1000;
#else
	struct timeval timeout = {1, 0};
#endif
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
	return sock;
}

static int send_stun(test_socket_t sock, uint16_t port, const stun_message_t *msg) {
	char buffer[BUFFER_SIZE];
	int size = _juice_stun_write(buffer, BUFFER_SIZE, msg, NULL);
	if (size <= 0)
		return -1;

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = htonl(LOCALHOST);
	if (sendto(sock, buffer, size, 0, (const struct sockaddr *)&sin, sizeof(sin)) != size)
		return -1;

	return 0;
}

static int recv_stun(test_socket_t sock, stun_message_t *msg) {
	char buffer[BUFFER_SIZE];
	int len = (int)recvfrom(sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
	if (len <= 0)
		return -1;

	memset(msg, 0, sizeof(*msg));
	if (_juice_stun_read(buffer, len, msg) <= 0)
		return -1;

	if (memcmp(msg->transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE) != 0)
		return -1;

	return 0;
}

static int test_rfc5780_server_behavior(uint16_t server_port) {
	uint16_t port, alternate_port;
	test_socket_t sock = create_test_socket(&port);
	test_socket_t alternate_sock = create_test_socket(&alternate_port);
	if (sock == TEST_INVALID_SOCKET || alternate_sock == TEST_INVALID_SOCKET) {
		printf("Test socket creation failed\n");
		goto error;
	}

	// A Binding request must be answered with RESPONSE-ORIGIN and without OTHER-ADDRESS
	stun_message_t msg;
	stun_message_t ans;
	init_binding_request(&msg);
	if (send_stun(sock, server_port, &msg) || recv_stun(sock, &ans)) {
		printf("No answer to Binding request\n");
		goto error;
	}
	if (ans.msg_class != STUN_CLASS_RESP_SUCCESS || !is_ipv4(&ans.mapped, LOCALHOST, port)) {
		printf("Binding response is incorrect\n");
		goto error;
	}
	if (!is_ipv4(&ans.response_origin, LOCALHOST, server_port)) {
		printf("RESPONSE-ORIGIN is missing or incorrect\n");
		goto error;
	}
	if (ans.other_address.len) {
		printf("OTHER-ADDRESS must not be advertised by a server with a single address\n");
		goto error;
	}

	// An empty CHANGE-REQUEST must not be rejected
	init_binding_request(&msg);
	msg.has_change_request = true;
	if (send_stun(sock, server_port, &msg) || recv_stun(sock, &ans)) {
		printf("No answer to Binding request with an empty CHANGE-REQUEST\n");
		goto error;
	}
	if (ans.msg_class != STUN_CLASS_RESP_SUCCESS) {
		printf("Binding request with an empty CHANGE-REQUEST was rejected\n");
		goto error;
	}

	// CHANGE-REQUEST must be answered with 420 as the server has a single address
	init_binding_request(&msg);
	msg.has_change_request = true;
	msg.change_request = STUN_CHANGE_REQUEST_IP | STUN_CHANGE_REQUEST_PORT;
	if (send_stun(sock, server_port, &msg) || recv_stun(sock, &ans)) {
		printf("No answer to Binding request with CHANGE-REQUEST\n");
		goto error;
	}
	if (ans.msg_class != STUN_CLASS_RESP_ERROR || ans.error_code != 420) {
		printf("Binding request with CHANGE-REQUEST was not answered with 420\n");
		goto error;
	}
	if (ans.unknown_attributes_count != 1 ||
	    ans.unknown_attributes[0] != STUN_ATTR_CHANGE_REQUEST) {
		printf("420 answer does not list CHANGE-REQUEST in UNKNOWN-ATTRIBUTES\n");
		goto error;
	}

	// RESPONSE-PORT must redirect the response to the requested port
	init_binding_request(&msg);
	msg.has_response_port = true;
	msg.response_port = alternate_port;
	if (send_stun(sock, server_port, &msg) || recv_stun(alternate_sock, &ans)) {
		printf("No answer on the port requested with RESPONSE-PORT\n");
		goto error;
	}
	if (ans.msg_class != STUN_CLASS_RESP_SUCCESS || !is_ipv4(&ans.mapped, LOCALHOST, port)) {
		printf("Binding response on the requested port is incorrect\n");
		goto error;
	}

	// RESPONSE-PORT together with PADDING must be rejected
	char padding[64];
	memset(padding, 0, sizeof(padding));
	init_binding_request(&msg);
	msg.has_response_port = true;
	msg.response_port = alternate_port;
	msg.padding = padding;
	msg.padding_size = sizeof(padding);
	if (send_stun(sock, server_port, &msg) || recv_stun(sock, &ans)) {
		printf("No answer to Binding request with RESPONSE-PORT and PADDING\n");
		goto error;
	}
	if (ans.msg_class != STUN_CLASS_RESP_ERROR || ans.error_code != 400) {
		printf("Binding request with RESPONSE-PORT and PADDING was not rejected\n");
		goto error;
	}

	test_closesocket(sock);
	test_closesocket(alternate_sock);
	return 0;

error:
	if (sock != TEST_INVALID_SOCKET)
		test_closesocket(sock);
	if (alternate_sock != TEST_INVALID_SOCKET)
		test_closesocket(alternate_sock);

	return -1;
}

static int test_rfc5780_server(void) {
	juice_server_config_t config;
	memset(&config, 0, sizeof(config));
	config.bind_address = "127.0.0.1";

	juice_server_t *server = juice_server_create(&config);
	if (!server) {
		printf("Server creation failed\n");
		return -1;
	}

	int ret = test_rfc5780_server_behavior(juice_server_get_port(server));
	juice_server_destroy(server);
	return ret;
}

#endif // ifndef NO_SERVER

int test_rfc5780(void) {
	if (test_rfc5780_request_attributes())
		return -1;

	if (test_rfc5780_response_attributes())
		return -1;

	if (test_rfc5780_unknown_attributes())
		return -1;

#ifndef NO_SERVER
	if (test_rfc5780_server())
		return -1;
#endif

	printf("Success\n");
	return 0;
}

#ifndef _WIN32

// Opt-in check against public STUN servers, enabled with JUICE_RUN_PUBLIC_STUN_TESTS
static int probe_public_server(const char *host, const char *service) {
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;

	struct addrinfo *res = NULL;
	if (getaddrinfo(host, service, &hints, &res)) {
		printf("Address resolution failed for %s:%s\n", host, service);
		return -1;
	}

	int ret = -1;
	int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sock < 0) {
		printf("Socket creation failed for %s:%s\n", host, service);
		goto finish;
	}

	struct timeval timeout = {2, 0};
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

	stun_message_t msg;
	init_binding_request(&msg);

	char buffer[BUFFER_SIZE];
	int size = _juice_stun_write(buffer, BUFFER_SIZE, &msg, NULL);
	if (size <= 0 || sendto(sock, buffer, size, 0, res->ai_addr, res->ai_addrlen) != size) {
		printf("Sending to %s:%s failed\n", host, service);
		goto finish;
	}

	int len = (int)recvfrom(sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
	if (len <= 0) {
		printf("No answer from %s:%s\n", host, service);
		goto finish;
	}

	stun_message_t ans;
	memset(&ans, 0, sizeof(ans));
	if (_juice_stun_read(buffer, len, &ans) <= 0) {
		printf("Reading the answer from %s:%s failed\n", host, service);
		goto finish;
	}

	printf("%s:%s answered with response origin=%s and other address=%s\n", host, service,
	       ans.response_origin.len ? "yes" : "no", ans.other_address.len ? "yes" : "no");

	ret = ans.response_origin.len && ans.other_address.len ? 0 : -1;

finish:
	if (sock >= 0)
		close(sock);
	freeaddrinfo(res);
	return ret;
}

int test_rfc5780_public(void) {
	const char *hosts[] = {"stun.nextcloud.com", "stun.voip.blackberry.com", "stun.acronis.com"};

	if (!getenv("JUICE_RUN_PUBLIC_STUN_TESTS"))
		return 0;

	for (size_t i = 0; i < sizeof(hosts) / sizeof(hosts[0]); ++i) {
		if (probe_public_server(hosts[i], "3478") == 0) {
			printf("Success\n");
			return 0;
		}
	}

	printf("No public server advertised RESPONSE-ORIGIN and OTHER-ADDRESS\n");
	return -1;
}

#endif // ifndef _WIN32
