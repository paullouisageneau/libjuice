/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "nat.h"

static int sockaddr_equal(const struct sockaddr_storage *a,
				   const struct sockaddr_storage *b) {

	if (a->ss_family == AF_INET && b->ss_family == AF_INET) {
		struct sockaddr_in *sa, *sb;

		sa = (struct sockaddr_in *) a;
		sb = (struct sockaddr_in *) b;

		return sa->sin_addr.s_addr == sb->sin_addr.s_addr;
	} if (a->ss_family == AF_INET6 && b->ss_family == AF_INET6) {
		struct sockaddr_in6 *sa, *sb;

		sa = (struct sockaddr_in6 *) a;
		sb = (struct sockaddr_in6 *) b;

		return memcmp(sa->sin6_addr.s6_addr, sb->sin6_addr.s6_addr,
					  sizeof(sa->sin6_addr.s6_addr)) == 0;
	}

	return 0;
}

int juice_nat_do_test(socket_t sock, addr_record_t *srv_addr, struct timeval *timeout,
				   juice_nat_detect_phase_t phase, addr_record_t *mapped_addr,
				   addr_record_t *changed_ip) {

	stun_message_t msg;
	char buffer[BUFFER_SIZE];

	if (mapped_addr) memset(mapped_addr, 0, sizeof(addr_record_t));
	if (changed_ip) memset(changed_ip, 0, sizeof(addr_record_t));

	memset(&msg, 0, sizeof(msg));
	msg.msg_class = STUN_CLASS_REQUEST;
	msg.msg_method = STUN_METHOD_BINDING;
	juice_random(msg.transaction_id, STUN_TRANSACTION_ID_SIZE);

	switch (phase) {
		case JUICE_NAT_DETECT_TESTI:
			msg.change_request = 0;
			break;
		case JUICE_NAT_DETECT_TESTII:
			msg.change_request = STUN_VALUE_CHANGE_IP ^ STUN_VALUE_CHANGE_PORT;
			break;
		case JUICE_NAT_DETECT_TESTIII:
			msg.change_request = STUN_VALUE_CHANGE_PORT;
			break;
		default:
			JLOG_ERROR("Unknown test phase");
			return -2;
	}

	int msg_size = stun_write(buffer, BUFFER_SIZE, &msg, NULL);
	if (msg_size <= 0) {
		return -2;
	}

	if (udp_sendto(sock, buffer, msg_size, srv_addr) <= 0){
		return -2;
	}

	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(sock, &readfds);

	int n = SOCKET_TO_INT(sock) + 1;
	int ret = select(n, &readfds, NULL, NULL, timeout);
	if (ret == 0) return -1;
	if (ret < 0) return -2;

	addr_record_t src;
	msg_size = udp_recvfrom(sock, buffer, BUFFER_SIZE, &src);

	struct sockaddr_in *addr = (struct sockaddr_in *)&src.addr;

	if (stun_read(buffer, msg_size, &msg) < 0) {
		JLOG_ERROR("STUN read error");
		return -2;
	}

	switch(msg.msg_class) {
		case  STUN_CLASS_RESP_SUCCESS:
			if (msg.mapped.len == 0) {
				JLOG_ERROR("Expected MAPPED-ADDRESS in success response");
				return -2;
			}

			memcpy(mapped_addr, &msg.mapped, sizeof(addr_record_t));
			if (changed_ip && msg.changed_ip.len) {
				printf("here\n");
				memcpy(changed_ip, &msg.changed_ip, sizeof(addr_record_t));
			}

			return 0;
		case STUN_CLASS_RESP_ERROR:
			JLOG_ERROR("Error response, code = %d\n", msg.error_code);
			return -2;
		default:
			return -2;
	}
}

const char *juice_nat_type_name(juice_nat_type_t nat_type) {
	switch (nat_type) {
		case JUICE_NAT_TYPE_OPEN:
			return "Open Internet";
		case JUICE_NAT_TYPE_FULL_CONE:
			return "Full Cone";
		case JUICE_NAT_TYPE_RESTRICTED:
			return "Restricted";
		case JUICE_NAT_TYPE_PORT_RESTRICTED:
			return "Port Restricted";
		case JUICE_NAT_TYPE_SYMMETRIC:
			return "Symmetric";
		case JUICE_NAT_TYPE_SYMMETRIC_UDP:
			return "Symmetric UDP";
		case JUICE_NAT_TYPE_BLOCKED:
			return "Blocked";
		case JUICE_NAT_TYPE_UNKNOWN:
		default:
			return "Unknown";
	}
}

juice_nat_type_t juice_nat_detect(const char *stun_host, unsigned short stun_port,
								  addr_record_t *mapped_addr) {

	addr_record_t local_addrs[MAX_LOCAL_ADDRESSES];
	addr_record_t changed_ip;
	int local_addrs_count = 0;
	udp_socket_config_t config;
	struct timeval timeout;
	addr_record_t addr;
	addr_record_t *mapped_addr2 = &addr;
	int n;

	memset(mapped_addr, 0, sizeof(addr_record_t));

	memset(&config, 0, sizeof(config));
	socket_t sock = udp_create_socket(&config);
	if (sock == INVALID_SOCKET) {
		JLOG_ERROR("Failed to create UDP socket");
		return JUICE_NAT_TYPE_UNKNOWN;
	}

	local_addrs_count = udp_get_addrs(sock, local_addrs, MAX_LOCAL_ADDRESSES);

	char service[8];
	snprintf(service, 8, "%hu", stun_port);
	addr_record_t srv_addrs[1];
	if (!addr_resolve(stun_host, service, srv_addrs, 1)) {
		JLOG_ERROR("Failed to resolve STUN server address");
		return JUICE_NAT_TYPE_UNKNOWN;
	}

	timeout.tv_sec = (long)(JUICE_NAT_TIMEOUT / 1000);
	timeout.tv_usec = (long)0;
	int ret = DO_TESTI(sock, &srv_addrs[0], &timeout, mapped_addr, &changed_ip);
	switch (ret) {
		case -1:
			return JUICE_NAT_TYPE_BLOCKED;
		case -2:
			return JUICE_NAT_TYPE_UNKNOWN;
	}

	int same_ip = 0;
	int same_port = 0;

	for (n = 0; n < local_addrs_count; n++) {
		if (sockaddr_equal(&local_addrs[n].addr, &mapped_addr->addr)) {
			same_ip = 1;
			break;
		}
	}

	timeout.tv_sec = (long)(JUICE_NAT_TIMEOUT / 1000);
	timeout.tv_usec = (long)0;
	ret = DO_TESTII(sock, &srv_addrs[0], &timeout, mapped_addr2, NULL);
	if (same_ip) {
		switch (ret){
			case -1:
				return JUICE_NAT_TYPE_SYMMETRIC_UDP;
			case -2:
				return JUICE_NAT_TYPE_UNKNOWN;
		}

		return JUICE_NAT_TYPE_OPEN;
	}

	if (ret == 0) return JUICE_NAT_TYPE_FULL_CONE;

	timeout.tv_sec = (long)(JUICE_NAT_TIMEOUT / 1000);
	timeout.tv_usec = (long)0;
	if (changed_ip.len) {
		ret = DO_TESTI(sock, &changed_ip, &timeout, mapped_addr2, NULL);
	}
	else {
		ret = DO_TESTI(sock, &srv_addrs[0], &timeout, mapped_addr2, NULL);
	}

	if (ret != 0) return JUICE_NAT_TYPE_UNKNOWN;
	if (mapped_addr->addr.ss_family == mapped_addr2->addr.ss_family &&
		sockaddr_equal(&mapped_addr->addr, &mapped_addr2->addr)) {

		unsigned short port1, port2;
		if (mapped_addr->addr.ss_family == AF_INET) {
			port1 = ntohs(((struct sockaddr_in *)&mapped_addr->addr)->sin_port);
			port2 = ntohs(((struct sockaddr_in *)&mapped_addr2->addr)->sin_port);
		}
		else {
			port1 = ntohs(((struct sockaddr_in6 *)&mapped_addr->addr)->sin6_port);
			port2 = ntohs(((struct sockaddr_in6 *)&mapped_addr2->addr)->sin6_port);
		}

		if (port1 == port2) same_port = 1;
	}

	if (!same_port) return JUICE_NAT_TYPE_SYMMETRIC;
	timeout.tv_sec = (long)(JUICE_NAT_TIMEOUT / 1000);
	timeout.tv_usec = (long)0;
	ret = DO_TESTIII(sock, &srv_addrs[0], &timeout, mapped_addr2, NULL);
	switch (ret){
		case -1:
			return JUICE_NAT_TYPE_PORT_RESTRICTED;
		case -2:
			return JUICE_NAT_TYPE_UNKNOWN;
	}

	return JUICE_NAT_TYPE_RESTRICTED;
}
