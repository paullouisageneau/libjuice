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

#include "juice/juice.h"

#include <stdio.h>

int test_crc32(void);
int test_stun(void);
int test_connectivity(void);
int test_server(void);

int main(int argc, char **argv) {
	juice_set_log_level(JUICE_LOG_LEVEL_WARN);

	printf("\nRunning CRC32 implementation test...\n");
	if (test_crc32()) {
		fprintf(stderr, "CRC32 implementation test failed\n");
		return -2;
	}

	printf("\nRunning STUN parsing implementation test...\n");
	if (test_stun()) {
		fprintf(stderr, "STUN parsing implementation test failed\n");
		return -3;
	}

	printf("\nRunning connectivity test...\n");
	if (test_connectivity()) {
		fprintf(stderr, "Connectivity test failed\n");
		return -1;
	}

	printf("\nRunning STUN server test...\n");
	if (test_server()) {
		fprintf(stderr, "STUN server test failed\n");
		return -1;
	}

	return 0;
}

