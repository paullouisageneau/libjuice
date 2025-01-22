/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef JUICE_TCP_H
#define JUICE_TCP_H

#include "addr.h"
#include "juice.h"
#include "socket.h"

socket_t tcp_create_socket(const addr_record_t *dst);
int tcp_ice_write(socket_t sock, const char *data, size_t size);
int tcp_ice_read(socket_t sock, char *buffer, size_t size, uint16_t *ice_tcp_len);

// Export for tests
JUICE_EXPORT int _juice_tcp_ice_write(socket_t sock, const char *data, size_t size);
JUICE_EXPORT int _juice_tcp_ice_read(socket_t sock, char *buffer, size_t size, uint16_t *ice_tcp_len);
#endif
