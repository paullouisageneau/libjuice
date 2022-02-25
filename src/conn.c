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

#include "conn.h"
#include "agent.h"
#include "conn_poll.h"
#include "conn_thread.h"
#include "conn_mux.h"
#include "log.h"

#include <assert.h>
#include <string.h>

#define INITIAL_REGISTRY_SIZE 2

static conn_registry_t *registry = NULL;
static mutex_t init_mutex = MUTEX_INITIALIZER;
static juice_concurrency_mode_t concurrency_mode = JUICE_CONCURRENCY_MODE_POLL;

typedef struct conn_mode_entry  {
	int (*init_func)(conn_registry_t *registry, udp_socket_config_t *config);
	void (*cleanup_func)(conn_registry_t *registry);
} conn_mode_entry_t;

#define MODE_ENTRIES_SIZE 3

static const conn_mode_entry_t mode_entries[MODE_ENTRIES_SIZE] = {
	{conn_poll_registry_init, conn_poll_registry_cleanup},
	{conn_mux_registry_init, conn_mux_registry_cleanup },
	{conn_thread_registry_init, conn_thread_registry_cleanup }
};

JUICE_EXPORT void juice_set_concurrency_mode(juice_concurrency_mode_t mode) {
	mutex_lock(&init_mutex);
	if(mode >= 0 && mode < MODE_ENTRIES_SIZE) {
		concurrency_mode = mode;
	} else {
		JLOG_ERROR("Invalid concurrency mode");
	}
	mutex_unlock(&init_mutex);
}

JUICE_EXPORT juice_concurrency_mode_t juice_get_concurrency_mode(void) {
	mutex_lock(&init_mutex);
	juice_concurrency_mode_t result = concurrency_mode;
	mutex_unlock(&init_mutex);
	return result;
}

int conn_create(juice_agent_t *agent, udp_socket_config_t *config) {
	mutex_lock(&init_mutex);
	JLOG_DEBUG("Creating connection");

	if (!registry) {
		JLOG_DEBUG("Creating connections registry");

		registry = calloc(1, sizeof(conn_registry_t));
		if (!registry) {
			JLOG_FATAL("Memory allocation failed for connections registry");
			mutex_unlock(&init_mutex);
			return -1;
		}
		registry->agents = calloc(INITIAL_REGISTRY_SIZE, sizeof(juice_agent_t *));
		if (!registry->agents) {
			JLOG_FATAL("Memory allocation failed for connections array");
			mutex_unlock(&init_mutex);
			return -1;
		}
		registry->agents_size = INITIAL_REGISTRY_SIZE;
		registry->agents_count = 0;

		mutex_init(&registry->mutex, MUTEX_RECURSIVE);
		mutex_lock(&registry->mutex);

		registry->mode = concurrency_mode;
		if (mode_entries[registry->mode].init_func(registry, config)) {
			mutex_unlock(&registry->mutex);
			mutex_unlock(&init_mutex);
			return -1;
		}

	} else {
		mutex_lock(&registry->mutex);
	}
	mutex_unlock(&init_mutex);

	int i = 0;
	while (i < registry->agents_size) {
		if (!registry->agents[i])
			break;

		++i;
	}

	if (i == registry->agents_size) {
		int new_size = registry->agents_size * 2;
		JLOG_DEBUG("Reallocating connections array, new_size=%d", new_size);

		juice_agent_t **new_agents = realloc(registry->agents, new_size * sizeof(juice_agent_t *));
		if (!new_agents) {
			JLOG_FATAL("Memory reallocation failed for connections array");
			mutex_unlock(&registry->mutex);
			return -1;
		}

		registry->agents = new_agents;
		registry->agents_size = new_size;
		memset(registry->agents + i, 0, (new_size - i) * sizeof(juice_agent_t));
	}

	registry->agents[i] = agent;
	agent->conn_index = i;

	if (registry->init_func(agent, registry, config)) {
		mutex_unlock(&registry->mutex);
		return -1;
	}

	++registry->agents_count;

	mutex_unlock(&registry->mutex);
	conn_interrupt(agent);
	return 0;
}

void conn_destroy(juice_agent_t *agent) {
	assert(registry);
	mutex_lock(&init_mutex);
	mutex_lock(&registry->mutex);
	JLOG_DEBUG("Destroying connection");

	registry->cleanup_func(agent);

	int i = agent->conn_index;
	assert(i >= 0 && i < registry->agents_size);
	assert(registry->agents[i] == agent);
	registry->agents[i] = NULL;
	agent->conn_index = -1;

	assert(registry->agents_count > 0);
	if (--registry->agents_count == 0) {
		JLOG_DEBUG("No connection left, destroying connections registry");
		mutex_unlock(&registry->mutex);

		mode_entries[registry->mode].cleanup_func(registry);
		free(registry->agents);
		free(registry);
		registry = NULL;

		mutex_unlock(&init_mutex);
		return;
	}

	JLOG_VERBOSE("%d connection%s left", registry->agents_count,
	             registry->agents_count >= 2 ? "s" : "");

	mutex_unlock(&registry->mutex);
	mutex_unlock(&init_mutex);
}

void conn_lock(juice_agent_t *agent) {
	if (!agent->conn_impl)
		return;

	assert(registry);
	mutex_lock(&registry->mutex);
}

void conn_unlock(juice_agent_t *agent) {
	if (!agent->conn_impl)
		return;

	assert(registry);
	mutex_unlock(&registry->mutex);
}

int conn_interrupt(juice_agent_t *agent) {
	if (!agent->conn_impl)
		return -1;

	assert(registry);
	return registry->interrupt_func(agent);
}

int conn_send(juice_agent_t *agent, const addr_record_t *dst, const char *data, size_t size,
              int ds) {
	if (!agent->conn_impl)
		return -1;

	assert(registry);
	return registry->send_func(agent, dst, data, size, ds);
}

int conn_get_addrs(juice_agent_t *agent, addr_record_t *records, size_t size) {
	if (!agent->conn_impl)
		return -1;

	assert(registry);
	return registry->get_addrs_func(agent, records, size);
}
