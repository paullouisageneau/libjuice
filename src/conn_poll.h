/**
 * Copyright (c) 2022 Paul-Louis Ageneau
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

#ifndef JUICE_CONN_POLL_H
#define JUICE_CONN_POLL_H

#include "addr.h"
#include "conn.h"
#include "thread.h"
#include "timestamp.h"

#include <stdbool.h>
#include <stdint.h>

int conn_poll_registry_init(conn_registry_t *registry, udp_socket_config_t *config);
void conn_poll_registry_cleanup(conn_registry_t *registry);

int conn_poll_init(juice_agent_t *agent, conn_registry_t *registry, udp_socket_config_t *config);
void conn_poll_cleanup(juice_agent_t *agent);
void conn_poll_lock(juice_agent_t *agent);
void conn_poll_unlock(juice_agent_t *agent);
int conn_poll_interrupt(juice_agent_t *agent);
int conn_poll_send(juice_agent_t *agent, const addr_record_t *dst, const char *data, size_t size,
                        int ds);
int conn_poll_get_addrs(juice_agent_t *agent, addr_record_t *records, size_t size);

#endif
