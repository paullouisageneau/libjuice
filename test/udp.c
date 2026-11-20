/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "udp.h"

#include <stdio.h>
#include <string.h>

int test_udp_dual_stack(void) {
#ifdef _WIN32
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data))
		return -1;
#endif

	udp_socket_config_t config = {0};
	socket_t sock = udp_create_socket(&config);
	int ret = -1;
	if (sock == INVALID_SOCKET)
		goto cleanup;

	addr_record_t bound;
	if (udp_get_bound_addr(sock, &bound) != 0)
		goto cleanup;

	if (bound.addr.ss_family == AF_INET6) {
		sockopt_t v6only = 1;
		socklen_t len = sizeof(v6only);
		if (getsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&v6only, &len) != 0 ||
		    v6only != 0) {
			fprintf(stderr, "Default UDP socket does not support IPv4\n");
			goto cleanup;
		}
	} else if (bound.addr.ss_family != AF_INET) {
		goto cleanup;
	}

	addr_record_t dst = {0};
	struct sockaddr_in addr = {0};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(9);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	memcpy(&dst.addr, &addr, sizeof(addr));
	dst.len = sizeof(addr);
	dst.socktype = SOCK_DGRAM;

	if (udp_sendto(sock, "x", 1, &dst) != 1) {
		fprintf(stderr, "IPv4 UDP send failed, errno=%d\n", sockerrno);
		goto cleanup;
	}
	if (udp_sendto_self(sock, "x", 1) != 1)
		goto cleanup;

	ret = 0;

cleanup:
	if (sock != INVALID_SOCKET)
		closesocket(sock);
#ifdef _WIN32
	WSACleanup();
#endif
	return ret;
}
