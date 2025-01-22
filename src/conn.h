/**
 * Copyright (c) 2022 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef JUICE_CONN_H
#define JUICE_CONN_H

#include "addr.h"
#include "juice.h"
#include "thread.h"
#include "timestamp.h"
#include "udp.h"

#include <stdbool.h>
#include <stdint.h>

typedef struct juice_agent juice_agent_t;

// Generic connection interface for agents
// This interface abstracts sockets and polling to allow for different concurrency modes.
// See include/juice/juice.h for implemented concurrency modes

typedef struct conn_registry {
	void *impl;
	mutex_t mutex;
	juice_agent_t **agents;
	int agents_size;
	int agents_count;
} conn_registry_t;

typedef struct conn_mode_entry {
	int (*registry_init_func)(conn_registry_t *registry, udp_socket_config_t *config);
	void (*registry_cleanup_func)(conn_registry_t *registry);

	int (*init_func)(juice_agent_t *agent, struct conn_registry *registry,
	                 udp_socket_config_t *config);
	void (*cleanup_func)(juice_agent_t *agent);
	void (*lock_func)(juice_agent_t *agent);
	void (*unlock_func)(juice_agent_t *agent);
	int (*interrupt_func)(juice_agent_t *agent);
	int (*send_func)(juice_agent_t *agent, const addr_record_t *dst, const char *data, size_t size,
	                 int ds);
	int (*get_addrs_func)(juice_agent_t *agent, addr_record_t *records, size_t size);
	int (*mux_listen_func)(conn_registry_t *registry, juice_cb_mux_incoming_t cb, void *user_ptr);
	conn_registry_t *(*get_registry_func)(udp_socket_config_t *config);
	bool (*can_release_registry_func)(conn_registry_t *registry);

	mutex_t mutex;
	conn_registry_t *registry;
} conn_mode_entry_t;

conn_mode_entry_t *conn_get_mode_entry(juice_concurrency_mode_t mode);
int conn_create(juice_agent_t *agent, udp_socket_config_t *config);
void conn_destroy(juice_agent_t *agent);
void conn_lock(juice_agent_t *agent);
void conn_unlock(juice_agent_t *agent);
int conn_interrupt(juice_agent_t *agent);
int conn_send(juice_agent_t *agent, const addr_record_t *dst, const char *data, size_t size,
              int ds);
int conn_get_addrs(juice_agent_t *agent, addr_record_t *records, size_t size);

#endif
