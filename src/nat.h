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

#ifndef JUICE_NAT_H
#define JUICE_NAT_H

#include <stdio.h>
#include <string.h>

#include "stun.h"
#include "random.h"
#include "udp.h"
#include "log.h"

#define BUFFER_SIZE 4096
#define MAX_LOCAL_ADDRESSES 16
#define JUICE_NAT_TIMEOUT 3000

typedef enum juice_nat_type {
	JUICE_NAT_TYPE_OPEN,
	JUICE_NAT_TYPE_FULL_CONE,
	JUICE_NAT_TYPE_RESTRICTED,
	JUICE_NAT_TYPE_PORT_RESTRICTED,
	JUICE_NAT_TYPE_SYMMETRIC,
	JUICE_NAT_TYPE_SYMMETRIC_UDP,
	JUICE_NAT_TYPE_BLOCKED,
	JUICE_NAT_TYPE_UNKNOWN
} juice_nat_type_t;

typedef enum juice_nat_test_phase {
	JUICE_NAT_DETECT_TESTI,
	JUICE_NAT_DETECT_TESTII,
	JUICE_NAT_DETECT_TESTIII
} juice_nat_detect_phase_t;

#define DO_TESTI(sock, srv_addr, timeout, mapped_addr, changed_ip) \
	juice_nat_do_test(sock, srv_addr, timeout, JUICE_NAT_DETECT_TESTI, mapped_addr, changed_ip);
#define DO_TESTII(sock, srv_addr, timeout, mapped_addr, changed_ip) \
	juice_nat_do_test(sock, srv_addr, timeout, JUICE_NAT_DETECT_TESTII, mapped_addr, changed_ip);
#define DO_TESTIII(sock, srv_addr, timeout, mapped_addr, changed_ip) \
	juice_nat_do_test(sock, srv_addr, timeout, JUICE_NAT_DETECT_TESTIII, mapped_addr, changed_ip);

const char *juice_nat_type_name(juice_nat_type_t nat_type);
int do_test(socket_t sock, addr_record_t *srv_addr, struct timeval *timeout,
		    juice_nat_detect_phase_t phase, addr_record_t *mapped_addr);
juice_nat_type_t juice_nat_detect(const char *stun_host, unsigned short stun_port,
								  addr_record_t *mapped_addr);

#endif // JUICE_NAT_H
