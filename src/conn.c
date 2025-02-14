/**
 * Copyright (c) 2022 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "conn.h"
#include "agent.h"
#include "conn_mux.h"
#include "conn_poll.h"
#include "conn_thread.h"
#include "conn_user.h"
#include "log.h"

#include <assert.h>
#include <string.h>

#define INITIAL_REGISTRY_SIZE 16

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

	mutex_t mutex;
	conn_registry_t *registry; // left NULL for concurrency modes that don't use a global registry
} conn_mode_entry_t;

#define MODE_ENTRIES_SIZE 4

static conn_mode_entry_t mode_entries[MODE_ENTRIES_SIZE] = {
    {conn_poll_registry_init, conn_poll_registry_cleanup, conn_poll_init, conn_poll_cleanup,
     conn_poll_lock, conn_poll_unlock, conn_poll_interrupt, conn_poll_send, conn_poll_get_addrs,
     MUTEX_INITIALIZER, NULL},
    {conn_mux_registry_init, conn_mux_registry_cleanup, conn_mux_init, conn_mux_cleanup,
     conn_mux_lock, conn_mux_unlock, conn_mux_interrupt, conn_mux_send, conn_mux_get_addrs,
     MUTEX_INITIALIZER, NULL},
    {NULL, NULL, conn_thread_init, conn_thread_cleanup, conn_thread_lock, conn_thread_unlock,
     conn_thread_interrupt, conn_thread_send, conn_thread_get_addrs, MUTEX_INITIALIZER, NULL},
	{NULL, NULL, conn_user_init, conn_user_cleanup, conn_user_lock, conn_user_unlock,
     conn_user_interrupt, conn_user_send, conn_user_get_addrs, MUTEX_INITIALIZER, NULL},
};

static conn_mode_entry_t *get_mode_entry(juice_agent_t *agent) {
	juice_concurrency_mode_t mode = agent->config.concurrency_mode;
	assert(mode >= 0 && mode < MODE_ENTRIES_SIZE);
	return mode_entries + (int)mode;
}

static int acquire_registry(conn_mode_entry_t *entry, udp_socket_config_t *config) {
	// entry must be locked
	conn_registry_t *registry = entry->registry;
	if (!registry) {
		if (!entry->registry_init_func)
			return 0;

		JLOG_DEBUG("Creating connections registry");

		registry = calloc(1, sizeof(conn_registry_t));
		if (!registry) {
			JLOG_FATAL("Memory allocation failed for connections registry");
			return -1;
		}

		registry->agents = malloc(INITIAL_REGISTRY_SIZE * sizeof(juice_agent_t *));
		if (!registry->agents) {
			JLOG_FATAL("Memory allocation failed for connections array");
			free(registry);
			return -1;
		}

		registry->agents_size = INITIAL_REGISTRY_SIZE;
		registry->agents_count = 0;
		memset(registry->agents, 0, INITIAL_REGISTRY_SIZE * sizeof(juice_agent_t *));

		mutex_init(&registry->mutex, MUTEX_RECURSIVE);
		mutex_lock(&registry->mutex);

		if (entry->registry_init_func(registry, config)) {
			JLOG_FATAL("Registry initialization failed");
			mutex_unlock(&registry->mutex);
			free(registry->agents);
			free(registry);
			return -1;
		}

		entry->registry = registry;

	} else {
		mutex_lock(&registry->mutex);
	}

	// registry is locked
	return 0;
}

static void release_registry(conn_mode_entry_t *entry) {
	// entry must be locked
	conn_registry_t *registry = entry->registry;
	if (!registry)
		return;

	// registry must be locked

	if (registry->agents_count == 0 && registry->cb_mux_incoming == NULL) {
		JLOG_DEBUG("No connection left, destroying connections registry");
		mutex_unlock(&registry->mutex);

		if (entry->registry_cleanup_func)
			entry->registry_cleanup_func(registry);

		free(registry->agents);
		free(registry);
		entry->registry = NULL;
		return;
	}

	JLOG_VERBOSE("%d connection%s left", registry->agents_count,
	             registry->agents_count >= 2 ? "s" : "");

	mutex_unlock(&registry->mutex);
}

int conn_create(juice_agent_t *agent, udp_socket_config_t *config) {
	conn_mode_entry_t *entry = get_mode_entry(agent);
	mutex_lock(&entry->mutex);
	if(acquire_registry(entry, config)) { // locks the registry if created
		mutex_unlock(&entry->mutex);
		return -1;
	}

	conn_registry_t *registry = entry->registry;

	JLOG_DEBUG("Creating connection");
	if (registry) {
		int i = 0;
		while (i < registry->agents_size && registry->agents[i])
			++i;

		if (i == registry->agents_size) {
			int new_size = registry->agents_size * 2;
			JLOG_DEBUG("Reallocating connections array, new_size=%d", new_size);
			assert(new_size > 0);

			juice_agent_t **new_agents =
			    realloc(registry->agents, new_size * sizeof(juice_agent_t *));
			if (!new_agents) {
				JLOG_FATAL("Memory reallocation failed for connections array");
				mutex_unlock(&registry->mutex);
				mutex_unlock(&entry->mutex);
				return -1;
			}

			registry->agents = new_agents;
			registry->agents_size = new_size;
			memset(registry->agents + i, 0, (new_size - i) * sizeof(juice_agent_t *));
		}

		if (get_mode_entry(agent)->init_func(agent, registry, config)) {
			release_registry(entry); // unlocks the registry
			mutex_unlock(&entry->mutex);
			return -1;
		}

		registry->agents[i] = agent;
		agent->conn_index = i;
		++registry->agents_count;

		mutex_unlock(&registry->mutex);

	} else {
		if (get_mode_entry(agent)->init_func(agent, NULL, config)) {
			mutex_unlock(&entry->mutex);
			return -1;
		}

		agent->conn_index = -1;
	}

	mutex_unlock(&entry->mutex);
	conn_interrupt(agent);
	return 0;
}

void conn_destroy(juice_agent_t *agent) {
	conn_mode_entry_t *entry = get_mode_entry(agent);
	mutex_lock(&entry->mutex);

	JLOG_DEBUG("Destroying connection");
	conn_registry_t *registry = entry->registry;
	if (registry) {
		mutex_lock(&registry->mutex);

		entry->cleanup_func(agent);

		if (agent->conn_index >= 0) {
			int i = agent->conn_index;
			assert(registry->agents[i] == agent);
			registry->agents[i] = NULL;
			agent->conn_index = -1;
		}

		assert(registry->agents_count > 0);
		--registry->agents_count;

		release_registry(entry); // unlocks the registry

	} else {
		entry->cleanup_func(agent);
		assert(agent->conn_index < 0);
	}

	mutex_unlock(&entry->mutex);
}

void conn_lock(juice_agent_t *agent) {
	if (!agent->conn_impl)
		return;

	get_mode_entry(agent)->lock_func(agent);
}

void conn_unlock(juice_agent_t *agent) {
	if (!agent->conn_impl)
		return;

	get_mode_entry(agent)->unlock_func(agent);
}

int conn_interrupt(juice_agent_t *agent) {
	if (!agent->conn_impl)
		return -1;

	return get_mode_entry(agent)->interrupt_func(agent);
}

int conn_send(juice_agent_t *agent, const addr_record_t *dst, const char *data, size_t size,
              int ds) {
	if (!agent->conn_impl)
		return -1;

	return get_mode_entry(agent)->send_func(agent, dst, data, size, ds);
}

int conn_get_addrs(juice_agent_t *agent, addr_record_t *records, size_t size) {
	if (!agent->conn_impl)
		return -1;

	return get_mode_entry(agent)->get_addrs_func(agent, records, size);
}

static int juice_mux_stop_listen(const char *bind_address, int local_port) {
    (void)bind_address;
    (void)local_port;

	conn_mode_entry_t *entry = &mode_entries[JUICE_CONCURRENCY_MODE_MUX];

	mutex_lock(&entry->mutex);

	conn_registry_t *registry = entry->registry;
	if (!registry) {
		mutex_unlock(&entry->mutex);
		return -1;
	}

	mutex_lock(&registry->mutex);

	registry->cb_mux_incoming = NULL;
	registry->mux_incoming_user_ptr = NULL;
	conn_mux_interrupt_registry(registry);

	release_registry(entry);

	mutex_unlock(&entry->mutex);

	return 0;
}

int juice_mux_listen(const char *bind_address, int local_port, juice_cb_mux_incoming_t cb, void *user_ptr)
{
	if (!cb)
		return juice_mux_stop_listen(bind_address, local_port);

	conn_mode_entry_t *entry = &mode_entries[JUICE_CONCURRENCY_MODE_MUX];

	udp_socket_config_t config;
	config.bind_address = bind_address;
	config.port_begin = config.port_end = local_port;

	mutex_lock(&entry->mutex);

	if (entry->registry) {
		mutex_unlock(&entry->mutex);
		JLOG_DEBUG("juice_mux_listen needs to be called before establishing any mux connection.");
		return -1;
	}

	if(acquire_registry(entry, &config)) { // locks the registry if created
		mutex_unlock(&entry->mutex);
		return -1;
	}

	conn_registry_t *registry = entry->registry;
	if(!registry) {
		mutex_unlock(&entry->mutex);
		return -1;
	}

	registry->cb_mux_incoming = cb;
	registry->mux_incoming_user_ptr = user_ptr;

	mutex_unlock(&registry->mutex);
	mutex_unlock(&entry->mutex);
	return 0;
}
