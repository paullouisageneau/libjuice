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

#include "agent.h"
#include "ice.h"
#include "juice.h"
#include "log.h"
#include "random.h"
#include "stun.h"
#include "turn.h"
#include "udp.h"
#include "transport.h"

#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#endif

// RFC 8656: The Permission Lifetime MUST be 300 seconds (= 5 minutes)
#define PERMISSION_LIFETIME 300000 // ms

// RFC 8656: Channel bindings last for 10 minutes unless refreshed
#define BIND_LIFETIME 600000 // ms

#define BUFFER_SIZE 4096
#define DEFAULT_MAX_RECORDS_COUNT 8

static char *alloc_string_copy(const char *orig) {
	if (!orig)
		return NULL;
	char *copy = malloc(strlen(orig) + 1);
	strcpy(copy, orig);
	return copy;
}

static void *alloc_copy(const void *orig, size_t size) {
	if (!orig || !size)
		return NULL;
	char *copy = malloc(size);
	memcpy(copy, orig, size);
	return copy;
}

juice_agent_t *agent_create(const juice_config_t *config) {
	JLOG_VERBOSE("Creating agent");

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
		JLOG_FATAL("WSAStartup failed");
		return NULL;
	}
#endif

	juice_agent_t *agent = calloc(1, sizeof(juice_agent_t));
	if (!agent) {
		JLOG_FATAL("alloc for agent failed");
		return NULL;
	}

	mutex_init(&agent->mutex, MUTEX_RECURSIVE);
	mutex_init(&agent->send_mutex, 0);

	agent->config = *config;

	if (agent->config.stun_server_host) {
		agent->config.stun_server_host = alloc_string_copy(agent->config.stun_server_host);
		if (!agent->config.stun_server_host) {
			JLOG_FATAL("alloc for STUN server host failed");
			goto error;
		}
	}

	if (agent->config.turn_servers_count) {
		size_t turn_servers_size = agent->config.turn_servers_count * sizeof(juice_turn_server_t);
		agent->config.turn_servers = alloc_copy(agent->config.turn_servers, turn_servers_size);
		if (!agent->config.turn_servers) {
			JLOG_FATAL("alloc for TURN server credentials array failed");
			goto error;
		}

		for (int i = 0; i < agent->config.turn_servers_count; ++i) {
			juice_turn_server_t *turn_server = agent->config.turn_servers + i;
			turn_server->host = alloc_string_copy(turn_server->host);
			turn_server->username = alloc_string_copy(turn_server->username);
			turn_server->password = alloc_string_copy(turn_server->password);
			if (!turn_server->host || !turn_server->username || !turn_server->password) {
				JLOG_FATAL("alloc for TURN server credentials array failed");
				goto error;
			}
		}
	}

	if (agent->config.bind_address) {
		agent->config.bind_address = alloc_string_copy(agent->config.bind_address);
		if (!agent->config.bind_address) {
			JLOG_FATAL("alloc for bind address failed");
			goto error;
		}
	}

	agent->state = JUICE_STATE_DISCONNECTED;
	agent->mode = AGENT_MODE_UNKNOWN;
	agent->sock = INVALID_SOCKET;
	agent->send_ds = 0;

#ifdef NO_ATOMICS
	agent->selected_entry = NULL;
#else
	atomic_init(&agent->selected_entry, NULL);
#endif

	ice_create_local_description(&agent->local);

	// RFC 8445: 16.1. Attributes
	// The content of the [ICE-CONTROLLED/ICE-CONTROLLING] attribute is a 64-bit
	// unsigned integer in network byte order, which contains a random number.
	// The number is used for solving role conflicts, when it is referred to as
	// the "tiebreaker value".  An ICE agent MUST use the same number for
	// all Binding requests, for all streams, within an ICE session, unless
	// it has received a 487 response, in which case it MUST change the
	// number.
	juice_random(&agent->ice_tiebreaker, sizeof(agent->ice_tiebreaker));

	return agent;

error:
	agent_do_destroy(agent);
	return NULL;
}

void agent_do_destroy(juice_agent_t *agent) {
	JLOG_DEBUG("Destroying agent");
	if (agent->sock != INVALID_SOCKET)
		closesocket(agent->sock);

	mutex_destroy(&agent->mutex);
	mutex_destroy(&agent->send_mutex);

	// Free credentials in entries
	for (int i = 0; i < agent->entries_count; ++i) {
		agent_stun_entry_t *entry = agent->entries + i;
		if (entry->turn) {
			turn_destroy_map(&entry->turn->map);
			free(entry->turn);
		}
	}

	// Free strings in config
	free((void *)agent->config.stun_server_host);
	for (int i = 0; i < agent->config.turn_servers_count; ++i) {
		juice_turn_server_t *turn_server = agent->config.turn_servers + i;
		free((void *)turn_server->host);
		free((void *)turn_server->username);
		free((void *)turn_server->password);
	}
	free(agent->config.turn_servers);
	free((void *)agent->config.bind_address);
	free(agent);

#ifdef _WIN32
	WSACleanup();
#endif
	JLOG_VERBOSE("Destroyed agent");
}

void agent_destroy(juice_agent_t *agent) {
	mutex_lock(&agent->mutex);

	if (agent->thread_started) {
		JLOG_DEBUG("Waiting for agent thread");
		agent->thread_stopped = true;
		mutex_unlock(&agent->mutex);
		agent_interrupt(agent);
		thread_join(agent->thread, NULL);
	} else {
		mutex_unlock(&agent->mutex);
	}
	agent_do_destroy(agent);
}

thread_return_t THREAD_CALL agent_thread_entry(void *arg) {
	agent_run((juice_agent_t *)arg);
	return (thread_return_t)0;
}

int agent_gather_candidates(juice_agent_t *agent) {
	mutex_lock(&agent->mutex);
	if (agent->sock != INVALID_SOCKET) {
		JLOG_WARN("Candidates gathering already started");
		mutex_unlock(&agent->mutex);
		return 0;
	}

	udp_socket_config_t socket_config;
	memset(&socket_config, 0, sizeof(socket_config));
	socket_config.bind_address = agent->config.bind_address;
	socket_config.port_begin = agent->config.local_port_range_begin;
	socket_config.port_end = agent->config.local_port_range_end;
	agent->sock = udp_create_socket(&socket_config);
	if (agent->sock == INVALID_SOCKET) {
		JLOG_FATAL("UDP socket creation for agent failed");
		mutex_unlock(&agent->mutex);
		return -1;
	}
	agent_change_state(agent, JUICE_STATE_GATHERING);

	addr_record_t records[ICE_MAX_CANDIDATES_COUNT - 1];
	int records_count = udp_get_addrs(agent->sock, records, ICE_MAX_CANDIDATES_COUNT - 1);
	if (records_count < 0) {
		JLOG_ERROR("Failed to gather local host candidates");
		records_count = 0;
	} else if (records_count == 0) {
		JLOG_WARN("No local host candidates gathered");
	} else if (records_count > ICE_MAX_CANDIDATES_COUNT - 1)
		records_count = ICE_MAX_CANDIDATES_COUNT - 1;

	JLOG_VERBOSE("Adding %d local host candidates", records_count);
	for (int i = 0; i < records_count; ++i) {
		ice_candidate_t candidate;
		if (ice_create_local_candidate(ICE_CANDIDATE_TYPE_HOST, 1, records + i, &candidate)) {
			JLOG_ERROR("Failed to create host candidate");
			continue;
		}
		if (agent->local.candidates_count >= MAX_HOST_CANDIDATES_COUNT) {
			JLOG_WARN("Local description already has the maximum number of host candidates");
			break;
		}
		if (ice_add_candidate(&candidate, &agent->local)) {
			JLOG_ERROR("Failed to add candidate to local description");
			continue;
		}
	}
	ice_sort_candidates(&agent->local);

	for (int i = 0; i < agent->entries_count; ++i)
		agent_translate_host_candidate_entry(agent, agent->entries + i);

	char buffer[BUFFER_SIZE];
	for (int i = 0; i < agent->local.candidates_count; ++i) {
		ice_candidate_t *candidate = agent->local.candidates + i;
		if (ice_generate_candidate_sdp(candidate, buffer, BUFFER_SIZE) < 0) {
			JLOG_ERROR("Failed to generate SDP for local candidate");
			continue;
		}

		JLOG_DEBUG("Gathered host candidate: %s", buffer);

		if (agent->config.cb_candidate)
			agent->config.cb_candidate(agent, buffer, agent->config.user_ptr);
	}

	if (agent->mode == AGENT_MODE_UNKNOWN) {
		JLOG_DEBUG("Assuming controlling mode");
		agent->mode = AGENT_MODE_CONTROLLING;
	}
	int ret = thread_init(&agent->thread, agent_thread_entry, agent);
	if (ret) {
		JLOG_FATAL("thread_create for agent failed, error=%d", ret);
		mutex_unlock(&agent->mutex);
		return -1;
	}
	agent->thread_started = true;
	mutex_unlock(&agent->mutex);
	return 0;
}

int agent_get_local_description(juice_agent_t *agent, char *buffer, size_t size) {
	mutex_lock(&agent->mutex);
	if (ice_generate_sdp(&agent->local, buffer, size) < 0) {
		JLOG_ERROR("Failed to generate local SDP description");
		mutex_unlock(&agent->mutex);
		return -1;
	}
	JLOG_VERBOSE("Generated local SDP description: %s", buffer);

	if (agent->mode == AGENT_MODE_UNKNOWN) {
		JLOG_DEBUG("Assuming controlling mode");
		agent->mode = AGENT_MODE_CONTROLLING;
	}
	mutex_unlock(&agent->mutex);
	return 0;
}

int agent_set_remote_description(juice_agent_t *agent, const char *sdp) {
	mutex_lock(&agent->mutex);
	JLOG_VERBOSE("Setting remote SDP description: %s", sdp);
	int ret = ice_parse_sdp(sdp, &agent->remote);
	if (ret < 0) {
		if (ret == ICE_PARSE_ERROR)
			JLOG_ERROR("Failed to parse remote SDP description");

		mutex_unlock(&agent->mutex);
		return -1;
	}
	if (!*agent->remote.ice_ufrag) {
		JLOG_ERROR("Missing ICE user fragment in remote description");
		mutex_unlock(&agent->mutex);
		return -1;
	}
	if (!*agent->remote.ice_pwd) {
		JLOG_ERROR("Missing ICE password in remote description");
		mutex_unlock(&agent->mutex);
		return -1;
	}
	// There is only one component, therefore we can unfreeze already existing pairs now
	JLOG_DEBUG("Unfreezing %d existing candidate pairs", (int)agent->candidate_pairs_count);
	for (int i = 0; i < agent->candidate_pairs_count; ++i) {
		agent_unfreeze_candidate_pair(agent, agent->candidate_pairs + i);
	}
	JLOG_DEBUG("Adding %d candidates from remote description", (int)agent->remote.candidates_count);
	for (int i = 0; i < agent->remote.candidates_count; ++i) {
		ice_candidate_t *remote = agent->remote.candidates + i;
		if (agent_add_candidate_pairs_for_remote(agent, remote))
			JLOG_WARN("Failed to add candidate pair from remote description");
	}
	if (agent->mode == AGENT_MODE_UNKNOWN) {
		JLOG_DEBUG("Assuming controlled mode");
		agent->mode = AGENT_MODE_CONTROLLED;
	}
	mutex_unlock(&agent->mutex);
	agent_interrupt(agent);
	return 0;
}

int agent_add_remote_candidate(juice_agent_t *agent, const char *sdp) {
	mutex_lock(&agent->mutex);
	JLOG_VERBOSE("Adding remote candidate: %s", sdp);
	ice_candidate_t candidate;
	int ret = ice_parse_candidate_sdp(sdp, &candidate);
	if (ret < 0) {
		if (ret == ICE_PARSE_IGNORED)
			JLOG_DEBUG("Ignored SDP candidate: %s", sdp);
		else if (ret == ICE_PARSE_ERROR)
			JLOG_ERROR("Failed to parse remote SDP candidate: %s", sdp);

		mutex_unlock(&agent->mutex);
		return -1;
	}
	if (ice_add_candidate(&candidate, &agent->remote)) {
		JLOG_ERROR("Failed to add candidate to remote description");
		mutex_unlock(&agent->mutex);
		return -1;
	}
	ice_candidate_t *remote = agent->remote.candidates + agent->remote.candidates_count - 1;
	ret = agent_add_candidate_pairs_for_remote(agent, remote);
	mutex_unlock(&agent->mutex);
	agent_interrupt(agent);
	return ret;
}

int agent_set_remote_gathering_done(juice_agent_t *agent) {
	mutex_lock(&agent->mutex);
	agent->remote.finished = true;
	agent->fail_timestamp = 0; // So the bookkeeping will recompute it and fail
	mutex_unlock(&agent->mutex);
	return 0;
}

int agent_send(juice_agent_t *agent, const char *data, size_t size, int ds) {
	// For performance reasons, try not to lock the global mutex if the platform has atomics
#ifdef NO_ATOMICS
	mutex_lock(&agent->mutex);
	agent_stun_entry_t *selected_entry = agent->selected_entry;
	if (selected_entry)
		selected_entry->armed = false; // so keepalive will be rescheduled
	mutex_unlock(&agent->mutex);
#else
	agent_stun_entry_t *selected_entry = atomic_load(&agent->selected_entry);
	if (selected_entry)
		atomic_flag_clear(&selected_entry->armed); // so keepalive will be rescheduled
#endif

	if (!selected_entry) {
		JLOG_ERROR("Send called before ICE is connected");
		return -1;
	}

	if (selected_entry->relay_entry) {
		// The datagram should be sent through the relay, use a channel to minimize overhead
		mutex_lock(&agent->mutex); // We have to lock the mutex
		int ret = agent_channel_send(agent, selected_entry->relay_entry, &selected_entry->record,
		                             data, size, ds);
		mutex_unlock(&agent->mutex);
		return ret;
	}

	return agent_direct_send2(agent, selected_entry, data, size, ds);
}

int agent_direct_send(juice_agent_t *agent, const addr_record_t *dst, const char *data, size_t size,
                      int ds) {
	mutex_lock(&agent->send_mutex);

	if (agent->send_ds >= 0 && agent->send_ds != ds) {
		JLOG_VERBOSE("Setting Differentiated Services field to 0x%X", ds);
		if (udp_set_diffserv(agent->sock, ds) == 0)
			agent->send_ds = ds;
		else
			agent->send_ds = -1; // disable for next time
	}

	JLOG_VERBOSE("Sending datagram, size=%d", size);

	int ret = udp_sendto(agent->sock, data, size, dst);
	if (ret < 0) {
		if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK)
			JLOG_INFO("Send failed, buffer is full");
		else
			JLOG_WARN("Send failed, errno=%d", sockerrno);
	}
	mutex_unlock(&agent->send_mutex);
	return ret;
}

int agent_direct_send2(juice_agent_t *agent, const agent_stun_entry_t *entry, const char *data,
                       size_t size, int ds) {
	mutex_lock(&agent->send_mutex);

	if (agent->send_ds >= 0 && agent->send_ds != ds) {
		JLOG_VERBOSE("Setting Differentiated Services field to 0x%X", ds);
		if (udp_set_diffserv(agent->sock, ds) == 0)
			agent->send_ds = ds;
		else
			agent->send_ds = -1; // disable for next time
	}

	JLOG_VERBOSE("Sending datagram, size=%d", size);

	int ret;
	if (entry->sock == INVALID_SOCKET) {
		ret = udp_sendto(agent->sock, data, size, &entry->record);
	}
	else {
		ret = transport_sendto(entry->sock, data, size, &entry->record);
	}

	if (ret < 0 && sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK)
		JLOG_WARN("Send failed, errno=%d", sockerrno);

	mutex_unlock(&agent->send_mutex);
	return ret;
}

int agent_relay_send(juice_agent_t *agent, agent_stun_entry_t *entry, const addr_record_t *dst,
                     const char *data, size_t size, int ds) {
	if (!entry->turn) {
		JLOG_ERROR("Missing TURN state on relay entry");
		return -1;
	}

	JLOG_VERBOSE("Sending datagram via relay, size=%d", size);

	// Send CreatePermission if necessary
	if (!turn_has_permission(&entry->turn->map, dst))
		if (agent_send_turn_create_permission_request(agent, entry, dst, ds))
			return -1;

	// Send the data in a TURN Send indication
	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_class = STUN_CLASS_INDICATION;
	msg.msg_method = STUN_METHOD_SEND;
	juice_random(msg.transaction_id, STUN_TRANSACTION_ID_SIZE);
	msg.peer = *dst;
	msg.data = data;
	msg.data_size = size;
	msg.dont_fragment = true;

	char buffer[BUFFER_SIZE];
	size = stun_write(buffer, BUFFER_SIZE, &msg, NULL); // no password
	if (size <= 0) {
		JLOG_ERROR("STUN message write failed");
		return -1;
	}
	if (agent_direct_send2(agent, entry, buffer, size, ds) < 0) {
		JLOG_WARN("STUN message send failed, errno=%d", sockerrno);
		return -1;
	}
	return 0;
}

int agent_channel_send(juice_agent_t *agent, agent_stun_entry_t *entry, const addr_record_t *record,
                       const char *data, size_t size, int ds) {
	if (!entry->turn) {
		JLOG_ERROR("Missing TURN state on relay entry");
		return -1;
	}

	// Send ChannelBind if necessary
	uint16_t channel;
	if (!turn_get_bound_channel(&entry->turn->map, record, &channel))
		if (agent_send_turn_channel_bind_request(agent, entry, record, ds, &channel) < 0)
			return -1;

	JLOG_VERBOSE("Sending datagram via channel 0x%hX, size=%d", channel, size);

	// Send the data wrapped as ChannelData
	char buffer[BUFFER_SIZE];
	int len = turn_wrap_channel_data(buffer, BUFFER_SIZE, data, size, channel);
	if (len <= 0) {
		JLOG_ERROR("TURN ChannelData wrapping failed");
		return -1;
	}
	if (agent_direct_send2(agent, entry, buffer, len, ds) < 0) {
		JLOG_WARN("ChannelData message send failed, errno=%d", sockerrno);
		return -1;
	}
	return 0;
}

juice_state_t agent_get_state(juice_agent_t *agent) {
	mutex_lock(&agent->mutex);
	juice_state_t state = agent->state;
	mutex_unlock(&agent->mutex);
	return state;
}

int agent_get_selected_candidate_pair(juice_agent_t *agent, ice_candidate_t *local,
                                      ice_candidate_t *remote) {
	mutex_lock(&agent->mutex);
	ice_candidate_pair_t *pair = agent->selected_pair;
	if (!pair) {
		mutex_unlock(&agent->mutex);
		return -1;
	}

	if (local)
		*local = pair->local ? *pair->local : agent->local.candidates[0];
	if (remote)
		*remote = *pair->remote;

	mutex_unlock(&agent->mutex);
	return 0;
}

void agent_run(juice_agent_t *agent) {
	mutex_lock(&agent->mutex);
	agent_change_state(agent, JUICE_STATE_CONNECTING);

	// TURN server resolution
	if (agent->config.turn_servers_count > 0) {
		int count = 0;
		for (int i = 0; i < agent->config.turn_servers_count; ++i) {
			if (count >= MAX_RELAY_ENTRIES_COUNT)
				break;

			juice_turn_server_t *turn_server = agent->config.turn_servers + i;
			if (!turn_server->port)
				turn_server->port = 3478; // default TURN port

			char service[8];
			snprintf(service, 8, "%hu", turn_server->port);

			addr_record_t records[DEFAULT_MAX_RECORDS_COUNT];
			int records_count =
			    addr_resolve(turn_server->host, service, records, DEFAULT_MAX_RECORDS_COUNT);
			if (records_count > 0) {
				if (records_count > DEFAULT_MAX_RECORDS_COUNT)
					records_count = DEFAULT_MAX_RECORDS_COUNT;

				JLOG_INFO("Using TURN server %s:%s", turn_server->host, service);

				addr_record_t *record = NULL;
				for (int j = 0; j < records_count; ++j) {
					int family = records[j].addr.ss_family;
					// Prefer IPv4 for TURN
					if (family == AF_INET) {
						record = records + j;
						break;
					}
					if (family == AF_INET6 && !record)
						record = records + j;
				}
				if (record) {
					JLOG_VERBOSE("Registering STUN entry %d for relay request",
					             agent->entries_count);
					agent_stun_entry_t *entry = agent->entries + agent->entries_count;
					entry->type = AGENT_STUN_ENTRY_TYPE_RELAY;
					entry->state = AGENT_STUN_ENTRY_STATE_PENDING;
					entry->pair = NULL;
					entry->record = *record;
					entry->turn = calloc(1, sizeof(agent_turn_state_t));
					if (!entry->turn) {
						JLOG_ERROR("calloc for TURN state failed");
						break;
					}
					if (turn_init_map(&entry->turn->map, AGENT_TURN_MAP_SIZE) < 0) {
						free(entry->turn);
						break;
					}
					snprintf(entry->turn->credentials.username, STUN_MAX_USERNAME_LEN, "%s",
					         turn_server->username);
					entry->turn->password = turn_server->password;

					transport_socket_config_t socket_config;
					memset(&socket_config, 0, sizeof(socket_config));

					entry->transport = turn_server->transport;
				    if (entry->transport) {
						socket_config.bind_address = agent->config.bind_address;
						socket_config.port_begin = agent->config.local_port_range_begin;
						socket_config.port_end = agent->config.local_port_range_end;
						switch (turn_server->transport) {
							case JUICE_TRANSPORT_UDP:
								socket_config.type = SOCKET_UDP;
								break;
							case JUICE_TRANSPORT_TCP:
								socket_config.type = SOCKET_TCP;
								break;
							default:
								JLOG_ERROR("Unknown transport type");
						}

						socket_config.family = record->addr.ss_family;
						entry->sock = transport_create_socket(&socket_config);
						transport_connect(entry->sock, record);
					}
					else {
						entry->sock = INVALID_SOCKET;
					}

					juice_random(entry->transaction_id, STUN_TRANSACTION_ID_SIZE);
					++agent->entries_count;

					agent_arm_transmission(agent, entry, STUN_PACING_TIME * i);

					++count;
				}
			} else {
				JLOG_ERROR("TURN address resolution failed");
			}
		}
	}

	// STUN server resolution
	// The entry is added after so the TURN server address will be matched in priority
	if (agent->config.stun_server_host) {
		if (!agent->config.stun_server_port)
			agent->config.stun_server_port = 3478; // default STUN port

		char service[8];
		snprintf(service, 8, "%hu", agent->config.stun_server_port);
		addr_record_t records[MAX_STUN_SERVER_RECORDS_COUNT];
		int records_count = addr_resolve(agent->config.stun_server_host, service, records,
		                                 MAX_STUN_SERVER_RECORDS_COUNT);
		if (records_count > 0) {
			if (records_count > MAX_STUN_SERVER_RECORDS_COUNT)
				records_count = MAX_STUN_SERVER_RECORDS_COUNT;

			JLOG_INFO("Using STUN server %s:%s", agent->config.stun_server_host, service);

			for (int i = 0; i < records_count; ++i) {
				if (i >= MAX_SERVER_ENTRIES_COUNT)
					break;
				JLOG_VERBOSE("Registering STUN entry %d for server request", agent->entries_count);
				agent_stun_entry_t *entry = agent->entries + agent->entries_count;
				entry->type = AGENT_STUN_ENTRY_TYPE_SERVER;
				entry->state = AGENT_STUN_ENTRY_STATE_PENDING;
				entry->pair = NULL;
				entry->record = records[i];
				entry->transport = JUICE_TRANSPORT_NONE;
				entry->sock = INVALID_SOCKET;
				juice_random(entry->transaction_id, STUN_TRANSACTION_ID_SIZE);
				++agent->entries_count;
				entry->sock = INVALID_SOCKET;

				agent_arm_transmission(agent, entry, STUN_PACING_TIME * i);
			}
		} else {
			JLOG_ERROR("STUN server address resolution failed");
		}
	}

	agent_update_gathering_done(agent);

	// Main loop
	timestamp_t next_timestamp;
	while (agent_bookkeeping(agent, &next_timestamp) == 0) {
		timediff_t timediff = next_timestamp - current_timestamp();
		if (timediff < 0)
			timediff = 0;

		JLOG_VERBOSE("Setting select timeout to %ld ms", (long)timediff);
		struct timeval timeout;
		timeout.tv_sec = (long)(timediff / 1000);
		timeout.tv_usec = (long)((timediff % 1000) * 1000);

		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(agent->sock, &readfds);
		int n = SOCKET_TO_INT(agent->sock) + 1;
		for (int i = 0; i < agent->entries_count; ++i) {
			agent_stun_entry_t *entry = agent->entries + i;
			if (entry->sock == INVALID_SOCKET) continue;

			int n2 = SOCKET_TO_INT(entry->sock) + 1;
			if (n2 > n) n = n2;
			FD_SET(entry->sock, &readfds);
		}

		JLOG_VERBOSE("Entering select");
		mutex_unlock(&agent->mutex);
		int ret = select(n, &readfds, NULL, NULL, &timeout);
		mutex_lock(&agent->mutex);
		JLOG_VERBOSE("Leaving select");
		if (ret < 0) {
			if (sockerrno == SEINTR || sockerrno == SEAGAIN) {
				JLOG_VERBOSE("select interrupted");
				continue;
			} else {
				JLOG_FATAL("select failed, errno=%d", sockerrno);
				break;
			}
		}

		if (agent->thread_stopped) {
			JLOG_VERBOSE("Agent destruction requested");
			break;
		}

		if (FD_ISSET(agent->sock, &readfds)) {
			if (agent_recv(agent, (agent_stun_entry_t *)NULL) < 0)
				break;
		}

		for (int i = 0; i < agent->entries_count; ++i) {
			agent_stun_entry_t *entry = agent->entries + i;
			if (entry->sock == INVALID_SOCKET) continue;
			if (FD_ISSET(entry->sock, &readfds)) {
				if (agent_recv(agent, entry) < 0)
					entry->sock = INVALID_SOCKET;
			}
		}
	}
	JLOG_DEBUG("Leaving agent thread");
	agent_change_state(agent, JUICE_STATE_DISCONNECTED);
	mutex_unlock(&agent->mutex);
}

int agent_recv(juice_agent_t *agent, agent_stun_entry_t *entry) {
	JLOG_VERBOSE("Receiving datagrams");

	addr_record_t record;
	if (entry && entry->transport == JUICE_TRANSPORT_TCP) {
		// len should be initialized to indicate the amount of space
		record.len = sizeof(struct sockaddr_storage);
		transport_getpeername(entry->sock, &record);
	}

	while (true) {
		char buffer[BUFFER_SIZE];
		int len;

		if (!entry) {
			len = udp_recvfrom(agent->sock, buffer, BUFFER_SIZE, &record);
		}
		else {
			if (entry->transport == JUICE_TRANSPORT_TCP) {
				len = transport_recv(entry->sock, buffer, BUFFER_SIZE);
			}
			else {
				len = transport_recvfrom(entry->sock, buffer, BUFFER_SIZE, &record);
			}
		}

		if (len < 0) {
			if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK) {
				JLOG_VERBOSE("No more datagrams to receive");
				break;
			}
			JLOG_ERROR("recvfrom failed, errno=%d", sockerrno);
			return -1;
		}
		if (len == 0) {
			// Empty datagram (used to interrupt)
			continue;
		}

		addr_unmap_inet6_v4mapped((struct sockaddr *)&record.addr, &record.len);
		agent_input(agent, buffer, len, &record, NULL);
	}

	return 0;
}

int agent_input(juice_agent_t *agent, char *buf, size_t len, const addr_record_t *src,
                const addr_record_t *relayed) {
	JLOG_VERBOSE("Received datagram, size=%d", len);

	for (;;) {
		if (!is_stun_datagram2(buf, len)) break;
		if (JLOG_DEBUG_ENABLED) {
			char src_str[ADDR_MAX_STRING_LEN];
			addr_record_to_string(src, src_str, ADDR_MAX_STRING_LEN);
			if (relayed) {
				char relayed_str[ADDR_MAX_STRING_LEN];
				addr_record_to_string(relayed, relayed_str, ADDR_MAX_STRING_LEN);
				JLOG_DEBUG("Received STUN datagram from %s relayed via %s", src_str, relayed_str);
			} else {
				JLOG_DEBUG("Received STUN datagram from %s", src_str);
			}
		}
		stun_message_t msg;
		int msg_size = stun_read(buf, len, &msg);
		if (msg_size < 0) {
			JLOG_ERROR("STUN message reading failed");
			return -1;
		}
		int ret = agent_dispatch_stun(agent, buf, len, &msg, src, relayed);
		if (ret != 0) return ret;

		buf = buf + msg_size;
		len = len - msg_size;
		if (len == 0) return 0;
	}

	if (JLOG_DEBUG_ENABLED) {
		char src_str[ADDR_MAX_STRING_LEN];
		addr_record_to_string(src, src_str, ADDR_MAX_STRING_LEN);
		if (relayed) {
			char relayed_str[ADDR_MAX_STRING_LEN];
			addr_record_to_string(relayed, relayed_str, ADDR_MAX_STRING_LEN);
			JLOG_DEBUG("Received non-STUN datagram from %s relayed via %s", src_str, relayed_str);
		} else {
			JLOG_DEBUG("Received non-STUN datagram from %s", src_str);
		}
	}
	agent_stun_entry_t *entry = agent_find_entry_from_record(agent, src, relayed);
	if (!entry) {
		JLOG_WARN("Received a datagram from unknown address, ignoring");
		return -1;
	}
	switch (entry->type) {
	case AGENT_STUN_ENTRY_TYPE_CHECK:
		JLOG_DEBUG("Received application datagram");
		if (agent->config.cb_recv)
			agent->config.cb_recv(agent, buf, len, agent->config.user_ptr);
		return 0;

	case AGENT_STUN_ENTRY_TYPE_RELAY:
		if (is_channel_data(buf, len)) {
			JLOG_DEBUG("Received ChannelData datagram");
			return agent_process_channel_data(agent, entry, buf, len);
		}
		break;

	default:
		break;
	}

	JLOG_WARN("Received unexpected non-STUN datagram, ignoring");
	return -1;
}

int agent_interrupt(juice_agent_t *agent) {
	JLOG_VERBOSE("Interrupting agent thread");
	mutex_lock(&agent->mutex);
	if (agent->sock == INVALID_SOCKET) {
		mutex_unlock(&agent->mutex);
		return -1;
	}

	addr_record_t local;
	if (udp_get_local_addr(agent->sock, AF_INET, &local) < 0) {
		mutex_unlock(&agent->mutex);
		return -1;
	}

	if (agent_direct_send(agent, &local, NULL, 0, 0) < 0) {
		JLOG_WARN("Failed to interrupt thread by triggering socket");
		mutex_unlock(&agent->mutex);
		return -1;
	}

	mutex_unlock(&agent->mutex);
	return 0;
}

void agent_change_state(juice_agent_t *agent, juice_state_t state) {
	if (state != agent->state) {
		JLOG_INFO("Changing state to %s", juice_state_to_string(state));
		agent->state = state;
		if (agent->config.cb_state_changed)
			agent->config.cb_state_changed(agent, state, agent->config.user_ptr);
	}
}

int agent_bookkeeping(juice_agent_t *agent, timestamp_t *next_timestamp) {
	timestamp_t now = current_timestamp();
	*next_timestamp = now + 10000; // We need at least to rearm keepalives

	if (agent->state == JUICE_STATE_DISCONNECTED)
		return 0;

	for (int i = 0; i < agent->entries_count; ++i) {
		agent_stun_entry_t *entry = agent->entries + i;

		// STUN requests transmission or retransmission
		if (entry->state == AGENT_STUN_ENTRY_STATE_PENDING) {
			if (entry->next_transmission > now)
				continue;

			if (entry->retransmissions >= 0) {
                if (entry->sock != INVALID_SOCKET && entry->transport == JUICE_TRANSPORT_TCP)
                    transport_wait_for_connected(entry->sock, NULL);

				if (JLOG_DEBUG_ENABLED) {
					char record_str[ADDR_MAX_STRING_LEN];
					addr_record_to_string(&entry->record, record_str, ADDR_MAX_STRING_LEN);
					JLOG_DEBUG("STUN entry %d: Sending request to %s (%d retransmissions left)", i,
					           record_str, entry->retransmissions);
				}
				int ret;
				switch (entry->type) {
				case AGENT_STUN_ENTRY_TYPE_RELAY:
					ret = agent_send_turn_allocate_request(agent, entry, STUN_METHOD_ALLOCATE);
					break;

				default:
					ret = agent_send_stun_binding(agent, entry, STUN_CLASS_REQUEST, 0, NULL, NULL);
					break;
				}

				if (ret >= 0) {
					--entry->retransmissions;
					entry->next_transmission = now + entry->retransmission_timeout;
					entry->retransmission_timeout *= 2;
					continue;
				}
			}

			// Failure sending or end of retransmissions
			JLOG_DEBUG("STUN entry %d: Failed", i);
			entry->state = AGENT_STUN_ENTRY_STATE_FAILED;
			entry->next_transmission = 0;

			switch (entry->type) {
			case AGENT_STUN_ENTRY_TYPE_RELAY:
				JLOG_INFO("TURN allocation failed");
				agent_update_gathering_done(agent);
				break;

			case AGENT_STUN_ENTRY_TYPE_SERVER:
				JLOG_INFO("STUN server binding failed");
				agent_update_gathering_done(agent);
				break;

			default:
				if (entry->pair) {
					JLOG_INFO("Candidate pair check failed");
					entry->pair->state = ICE_CANDIDATE_PAIR_STATE_FAILED;
				}
				break;
			}
		}
		// STUN keepalives
		else if (entry->state == AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE) {
#ifdef NO_ATOMICS
			bool must_arm = !entry->armed;
#else
			bool must_arm = !atomic_flag_test_and_set(&entry->armed);
#endif
			if (must_arm) {
				JLOG_VERBOSE("STUN entry %d: Must be rearmed", i);
				agent_arm_transmission(agent, entry, STUN_KEEPALIVE_PERIOD);
			}

			if (entry->next_transmission > now)
				continue;

			JLOG_DEBUG("STUN entry %d: Sending keepalive", i);
			int ret;
			switch (entry->type) {
			case AGENT_STUN_ENTRY_TYPE_RELAY:
				// RFC 8445 5.1.1.4. Keeping Candidates Alive:
				// Refreshes for allocations are done using the Refresh transaction, as described in
				// [RFC5766]
				ret = agent_send_turn_allocate_request(agent, entry, STUN_METHOD_REFRESH);
				break;
			case AGENT_STUN_ENTRY_TYPE_SERVER:
				// RFC 8445 5.1.1.4. Keeping Candidates Alive:
				// For server-reflexive candidates learned through a Binding request, the bindings
				// MUST be kept alive by additional Binding requests to the server.
				ret = agent_send_stun_binding(agent, entry, STUN_CLASS_REQUEST, 0, NULL, NULL);
				break;
			default:
				// RFC 8445 11. Keepalives:
				// All endpoints MUST send keepalives for each data session. [...] STUN keepalives
				// MUST be used when an ICE agent is a full ICE implementation and is communicating
				// with a peer that supports ICE (lite or full). [...] When STUN is being used for
				// keepalives, a STUN Binding Indication is used [RFC5389].
				ret = agent_send_stun_binding(agent, entry, STUN_CLASS_INDICATION, 0, NULL, NULL);
				break;
			}

			if (ret < 0)
				JLOG_WARN("Sending keepalive failed");

			agent_arm_transmission(agent, entry,
			                       entry->type == AGENT_STUN_ENTRY_TYPE_RELAY && ret >= 0
			                           ? TURN_REFRESH_PERIOD
			                           : STUN_KEEPALIVE_PERIOD);

		} else {
			// Entry does not transmit, unset next transmission
			entry->next_transmission = 0;
		}
	}

	if (agent->candidate_pairs_count == 0)
		goto finally;

	int pending_count = 0;
	ice_candidate_pair_t *nominated_pair = NULL;
	ice_candidate_pair_t *selected_pair = NULL;
	for (int i = 0; i < agent->candidate_pairs_count; ++i) {
		ice_candidate_pair_t *pair = *(agent->ordered_pairs + i);
		if (pair->nominated) {
			if (!nominated_pair) {
				nominated_pair = pair;
				selected_pair = pair;
			}
		} else if (pair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
			if (!selected_pair)
				selected_pair = pair;
		} else if (pair->state == ICE_CANDIDATE_PAIR_STATE_PENDING) {
			if (agent->mode == AGENT_MODE_CONTROLLING && selected_pair) {
				// A higher-priority pair will be used, we can stop checking
				// Entries will be synchronized after the current loop
				JLOG_VERBOSE("Cancelling check for lower-priority pair");
				pair->state = ICE_CANDIDATE_PAIR_STATE_FROZEN;
			} else {
				++pending_count;
			}
		}
	}

	// Cancel entries of frozen pairs
	for (int i = 0; i < agent->entries_count; ++i) {
		agent_stun_entry_t *entry = agent->entries + i;
		if (entry->pair && entry->pair->state == ICE_CANDIDATE_PAIR_STATE_FROZEN &&
		    entry->state != AGENT_STUN_ENTRY_STATE_IDLE &&
		    entry->state != AGENT_STUN_ENTRY_STATE_CANCELLED) {
			JLOG_DEBUG("STUN entry %d: Cancelled", i);
			entry->state = AGENT_STUN_ENTRY_STATE_CANCELLED;
			entry->next_transmission = 0;
		}
	}

	if (selected_pair) {
		// Succeeded
		// Change selected entry if this is a new selected pair
		if (agent->selected_pair != selected_pair) {
			JLOG_DEBUG(selected_pair->nominated ? "New selected and nominated pair"
			                                    : "New selected pair");
			agent->selected_pair = selected_pair;

			for (int i = 0; i < agent->entries_count; ++i) {
				agent_stun_entry_t *entry = agent->entries + i;
				if (entry->pair == selected_pair) {
#ifdef NO_ATOMICS
					agent->selected_entry = entry;
#else
					atomic_store(&agent->selected_entry, entry);
#endif
					break;
				}
			}
		}

		if (selected_pair->nominated || agent->mode == AGENT_MODE_CONTROLLING) {
			// Limit retransmissions of still pending entries
			for (int i = 0; i < agent->entries_count; ++i) {
				agent_stun_entry_t *entry = agent->entries + i;
				if (entry->state == AGENT_STUN_ENTRY_STATE_PENDING && entry->retransmissions > 1)
					entry->retransmissions = 1;
			}
		}

		if (nominated_pair) {
			// Completed
			// Do not allow direct transition from connecting to completed
			if (agent->state == JUICE_STATE_CONNECTING)
				agent_change_state(agent, JUICE_STATE_CONNECTED);

			// Actually transition to finished only if controlled or if nothing is pending anymore
			if (agent->mode == AGENT_MODE_CONTROLLED || pending_count == 0)
				agent_change_state(agent, JUICE_STATE_COMPLETED);

			agent_stun_entry_t *nominated_entry = NULL;
			agent_stun_entry_t *relay_entry = NULL;
			for (int i = 0; i < agent->entries_count; ++i) {
				agent_stun_entry_t *entry = agent->entries + i;
				if (entry->pair && entry->pair == nominated_pair) {
					nominated_entry = entry;
					relay_entry = nominated_entry->relay_entry;
					break;
				}
			}

			// Enable keepalive for the entry of the nominated pair
			if (nominated_entry &&
			    nominated_entry->state != AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE) {
				nominated_entry->state = AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE;
				agent_arm_transmission(agent, nominated_entry, STUN_KEEPALIVE_PERIOD);
			}

			// If the entry of the nominated candidate is relayed locally, we need also to
			// refresh the corresponding TURN session regularly
			if (relay_entry && relay_entry->state != AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE) {
				relay_entry->state = AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE;
				agent_arm_transmission(agent, relay_entry, TURN_REFRESH_PERIOD);
			}

			// Disable keepalives for other entries
			for (int i = 0; i < agent->entries_count; ++i) {
				agent_stun_entry_t *entry = agent->entries + i;
				if (entry != nominated_entry && entry != relay_entry &&
				    entry->state == AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE)
					entry->state = AGENT_STUN_ENTRY_STATE_SUCCEEDED;
			}

		} else {
			// Connected
			agent_change_state(agent, JUICE_STATE_CONNECTED);

			if (agent->mode == AGENT_MODE_CONTROLLING && selected_pair &&
			    !selected_pair->nomination_requested) {
				// Nominate selected
				JLOG_DEBUG("Requesting pair nomination (controlling)");
				selected_pair->nomination_requested = true;
				for (int i = 0; i < agent->entries_count; ++i) {
					agent_stun_entry_t *entry = agent->entries + i;
					if (entry->pair && entry->pair == selected_pair) {
						entry->state = AGENT_STUN_ENTRY_STATE_PENDING; // we don't want keepalives
						agent_arm_transmission(agent, entry, 0);       // transmit now
						break;
					}
				}
			}
		}
	} else if (pending_count == 0) {
		// Failed
		if (!agent->fail_timestamp)
			agent->fail_timestamp = now + (agent->remote.finished ? 0 : ICE_FAIL_TIMEOUT);

		if (agent->fail_timestamp && now >= agent->fail_timestamp)
			agent_change_state(agent, JUICE_STATE_FAILED);
		else if (*next_timestamp > agent->fail_timestamp)
			*next_timestamp = agent->fail_timestamp;
	}

finally:
	for (int i = 0; i < agent->entries_count; ++i) {
		agent_stun_entry_t *entry = agent->entries + i;
		if (entry->next_transmission && *next_timestamp > entry->next_transmission)
			*next_timestamp = entry->next_transmission;
	}
	return 0;
}

int agent_verify_stun_binding(juice_agent_t *agent, void *buf, size_t size,
                              const stun_message_t *msg) {
	if (msg->msg_method != STUN_METHOD_BINDING)
		return -1;

	if (msg->msg_class == STUN_CLASS_INDICATION || msg->msg_class == STUN_CLASS_RESP_ERROR)
		return 0;

	if (!msg->has_integrity) {
		JLOG_WARN("Missing integrity in STUN message");
		return -1;
	}

	// Check username (The USERNAME attribute is not present in responses)
	if (msg->msg_class == STUN_CLASS_REQUEST) {
		char username[STUN_MAX_USERNAME_LEN];
		strcpy(username, msg->credentials.username);
		char *separator = strchr(username, ':');
		if (!separator) {
			JLOG_WARN("STUN username invalid, username=\"%s\"", username);
			return -1;
		}
		*separator = '\0';
		const char *first_ufrag = username;
		const char *second_ufrag = separator + 1;
		const char *local_ufrag, *remote_ufrag;
		if (STUN_IS_RESPONSE(msg->msg_class)) {
			local_ufrag = second_ufrag;
			remote_ufrag = first_ufrag;
		} else {
			local_ufrag = first_ufrag;
			remote_ufrag = second_ufrag;
		}
		if (strcmp(local_ufrag, agent->local.ice_ufrag) != 0) {
			JLOG_WARN("STUN local ufrag check failed, expected=\"%s\", actual=\"%s\"",
			          agent->local.ice_ufrag, local_ufrag);
			return -1;
		}
		// RFC 8445 7.3. STUN Server Procedures:
		// It is possible (and in fact very likely) that the initiating agent will receive a Binding
		// request prior to receiving the candidates from its peer.  If this happens, the agent MUST
		// immediately generate a response.
		if (*agent->remote.ice_ufrag != '\0' &&
		    strcmp(remote_ufrag, agent->remote.ice_ufrag) != 0) {
			JLOG_WARN("STUN remote ufrag check failed, expected=\"%s\", actual=\"%s\"",
			          agent->remote.ice_ufrag, remote_ufrag);
			return -1;
		}
	}
	// Check password
	const char *password =
	    msg->msg_class == STUN_CLASS_REQUEST ? agent->local.ice_pwd : agent->remote.ice_pwd;
	if (*password == '\0') {
		JLOG_WARN("STUN integrity check failed, unknown password");
		return -1;
	}
	if (!stun_check_integrity(buf, size, msg, password)) {
		JLOG_WARN("STUN integrity check failed, password=\"%s\"", password);
		return -1;
	}
	return 0;
}

int agent_verify_credentials(juice_agent_t *agent, const agent_stun_entry_t *entry, void *buf,
                             size_t size, stun_message_t *msg) {
	(void)agent;

	// RFC 8489: If the response is an error response with an error code of 400 (Bad Request) and
	// does not contain either the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256 attribute, then the
	// response MUST be discarded, as if it were never received.  This means that retransmits, if
	// applicable, will continue.
	if (msg->msg_class == STUN_CLASS_INDICATION ||
	    (msg->msg_class == STUN_CLASS_RESP_ERROR && msg->error_code != 400))
		return 0;

	if (!msg->has_integrity) {
		JLOG_WARN("Missing integrity in STUN message");
		return -1;
	}
	if (!entry->turn) {
		JLOG_WARN("No credentials for entry");
		return -1;
	}
	stun_credentials_t *credentials = &entry->turn->credentials;
	const char *password = entry->turn->password;

	// Prepare credentials
	strcpy(msg->credentials.realm, credentials->realm);
	strcpy(msg->credentials.nonce, credentials->nonce);
	strcpy(msg->credentials.username, credentials->username);

	// Check credentials
	if (!stun_check_integrity(buf, size, msg, password)) {
		JLOG_WARN("STUN integrity check failed");
		return -1;
	}
	return 0;
}

int agent_dispatch_stun(juice_agent_t *agent, void *buf, size_t size, stun_message_t *msg,
                        const addr_record_t *src, const addr_record_t *relayed) {
	if (msg->msg_method == STUN_METHOD_BINDING && msg->has_integrity) {
		JLOG_VERBOSE("STUN message is from the remote peer");
		// Verify the message now
		if (agent_verify_stun_binding(agent, buf, size, msg)) {
			JLOG_WARN("STUN message verification failed");
			return -1;
		}
		if (!relayed) {
			if (agent_add_remote_reflexive_candidate(agent, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE,
			                                         msg->priority, src)) {
				JLOG_WARN("Failed to add remote peer reflexive candidate from STUN message");
			}
		}
	}

	agent_stun_entry_t *entry = NULL;
	if (STUN_IS_RESPONSE(msg->msg_class)) {
		JLOG_VERBOSE("STUN message is a response, looking for transaction ID");
		for (int i = 0; i < agent->entries_count; ++i) {
			if (memcmp(msg->transaction_id, agent->entries[i].transaction_id,
			           STUN_TRANSACTION_ID_SIZE) == 0) {
				JLOG_VERBOSE("STUN entry %d matching incoming transaction ID", i);
				entry = &agent->entries[i];
				break;
			}
			if (agent->entries[i].turn) {
				if (turn_retrieve_transaction_id(&agent->entries[i].turn->map, msg->transaction_id,
				                                 NULL)) {
					JLOG_VERBOSE("STUN entry %d matching incoming transaction ID (TURN)", i);
					entry = &agent->entries[i];
					break;
				}
			}
		}
		if (!entry) {
			JLOG_WARN("No STUN entry matching transaction ID, ignoring");
			return -1;
		}
	} else {
		JLOG_VERBOSE("STUN message is a request or indication, looking for remote address");
		entry = agent_find_entry_from_record(agent, src, relayed);
		if (entry) {
			JLOG_VERBOSE("Found STUN entry matching remote address");
		} else {
			// This may happen normally, for instance when there is no space left for reflexive
			// candidates
			JLOG_DEBUG("No STUN entry matching remote address, ignoring");
			return 0;
		}
	}

	switch (msg->msg_method) {
	case STUN_METHOD_BINDING:
		// Message was verified earlier, no need to re-verify
		if (entry->type == AGENT_STUN_ENTRY_TYPE_CHECK && !msg->has_integrity &&
		    (msg->msg_class == STUN_CLASS_REQUEST || msg->msg_class == STUN_CLASS_RESP_SUCCESS)) {
			JLOG_WARN("Missing integrity in STUN Binding message from remote peer, ignoring");
			return -1;
		}
		return agent_process_stun_binding(agent, msg, entry, src, relayed);

	case STUN_METHOD_ALLOCATE:
	case STUN_METHOD_REFRESH:
		if (agent_verify_credentials(agent, entry, buf, size, msg)) {
			JLOG_WARN("Ignoring invalid TURN Allocate message");
			return -1;
		}
		return agent_process_turn_allocate(agent, msg, entry);

	case STUN_METHOD_CREATE_PERMISSION:
		if (agent_verify_credentials(agent, entry, buf, size, msg)) {
			JLOG_WARN("Ignoring invalid TURN CreatePermission message");
			return -1;
		}
		return agent_process_turn_create_permission(agent, msg, entry);

	case STUN_METHOD_CHANNEL_BIND:
		if (agent_verify_credentials(agent, entry, buf, size, msg)) {
			JLOG_WARN("Ignoring invalid TURN ChannelBind message");
			return -1;
		}
		return agent_process_turn_channel_bind(agent, msg, entry);

	case STUN_METHOD_DATA:
		return agent_process_turn_data(agent, msg, entry);

	default:
		JLOG_WARN("Unknown STUN method 0x%X, ignoring", msg->msg_method);
		return -1;
	}
}

int agent_process_stun_binding(juice_agent_t *agent, const stun_message_t *msg,
                               agent_stun_entry_t *entry, const addr_record_t *src,
                               const addr_record_t *relayed) {
	switch (msg->msg_class) {
	case STUN_CLASS_REQUEST: {
		JLOG_DEBUG("Received STUN Binding request");
		if (entry->type != AGENT_STUN_ENTRY_TYPE_CHECK)
			return -1;

		ice_candidate_pair_t *pair = entry->pair;
		if (msg->ice_controlling == msg->ice_controlled) {
			JLOG_WARN("Controlling and controlled attributes mismatch in request");
			agent_send_stun_binding(agent, entry, STUN_CLASS_RESP_ERROR, 400, msg->transaction_id,
			                        NULL);
			return -1;
		}
		// RFC8445 7.3.1.1. Detecting and Repairing Role Conflicts:
		// If the agent is in the controlling role, and the ICE-CONTROLLING attribute is present in
		// the request:
		//  * If the agent's tiebreaker value is larger than or equal to the contents of the
		//  ICE-CONTROLLING attribute, the agent generates a Binding error response and includes an
		//  ERROR-CODE attribute with a value of 487 (Role Conflict) but retains its role.
		//  * If the agent's tiebreaker value is less than the contents of the ICE-CONTROLLING
		//  attribute, the agent switches to the controlled role.
		if (agent->mode == AGENT_MODE_CONTROLLING && msg->ice_controlling) {
			JLOG_WARN("ICE role conflict (both controlling)");
			if (agent->ice_tiebreaker >= msg->ice_controlling) {
				JLOG_DEBUG("Asking remote peer to switch roles");
				agent_send_stun_binding(agent, entry, STUN_CLASS_RESP_ERROR, 487,
				                        msg->transaction_id, NULL);
			} else {
				JLOG_DEBUG("Switching to controlled role");
				agent->mode = AGENT_MODE_CONTROLLED;
				agent_update_candidate_pairs(agent);
			}
			break;
		}
		// If the agent is in the controlled role, and the ICE-CONTROLLED attribute is present in
		// the request:
		//  * If the agent's tiebreaker value is larger than or equal to the contents of the
		//  ICE-CONTROLLED attribute, the agent switches to the controlling role.
		//  * If the agent's tiebreaker value is less than the contents of the ICE-CONTROLLED
		//  attribute, the agent generates a Binding error response and includes an ERROR-CODE
		//  attribute with a value of 487 (Role Conflict) but retains its role.
		if (msg->ice_controlled && agent->mode == AGENT_MODE_CONTROLLED) {
			JLOG_WARN("ICE role conflict (both controlled)");
			if (agent->ice_tiebreaker >= msg->ice_controlling) {
				JLOG_DEBUG("Switching to controlling role");
				agent->mode = AGENT_MODE_CONTROLLING;
				agent_update_candidate_pairs(agent);
			} else {
				JLOG_DEBUG("Asking remote peer to switch roles");
				agent_send_stun_binding(agent, entry, STUN_CLASS_RESP_ERROR, 487,
				                        msg->transaction_id, NULL);
			}
			break;
		}
		if (msg->use_candidate) {
			if (!msg->ice_controlling) {
				JLOG_WARN("STUN message use_candidate missing ice_controlling attribute");
				agent_send_stun_binding(agent, entry, STUN_CLASS_RESP_ERROR, 400,
				                        msg->transaction_id, NULL);
				return -1;
			}
			// RFC 8445 7.3.1.5. Updating the Nominated Flag:
			// If the state of this pair is Succeeded, it means that the check previously sent by
			// this pair produced a successful response and generated a valid pair. The agent sets
			// the nominated flag value of the valid pair to true.
			if (pair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
				JLOG_DEBUG("Got a nominated pair (controlled)");
				pair->nominated = true;
			} else if (!pair->nomination_requested) {
				pair->nomination_requested = true;
				pair->state = ICE_CANDIDATE_PAIR_STATE_PENDING;
				entry->state = AGENT_STUN_ENTRY_STATE_PENDING;
				agent_arm_transmission(agent, entry, STUN_PACING_TIME); // transmit after response
			}
		}
		if (agent_send_stun_binding(agent, entry, STUN_CLASS_RESP_SUCCESS, 0, msg->transaction_id,
		                            src)) {
			JLOG_ERROR("Failed to send STUN Binding response");
			return -1;
		}
		break;
	}
	case STUN_CLASS_RESP_SUCCESS: {
		JLOG_DEBUG("Received STUN Binding success response from %s",
		           entry->type == AGENT_STUN_ENTRY_TYPE_CHECK ? "peer" : "server");

		if (entry->type == AGENT_STUN_ENTRY_TYPE_SERVER)
			JLOG_INFO("STUN server binding successful");

		if (entry->state != AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE) {
			entry->state = AGENT_STUN_ENTRY_STATE_SUCCEEDED;
			entry->next_transmission = 0;
		}

		if (!agent->selected_pair || !agent->selected_pair->nominated) {
			// We want to send keepalives now
			entry->state = AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE;
			agent_arm_transmission(agent, entry, STUN_KEEPALIVE_PERIOD);
		}

		if (msg->mapped.len && !relayed) {
			JLOG_VERBOSE("Response has mapped address");

			if (JLOG_INFO_ENABLED && entry->type != AGENT_STUN_ENTRY_TYPE_CHECK) {
				char mapped_str[ADDR_MAX_STRING_LEN];
				addr_record_to_string(&msg->mapped, mapped_str, ADDR_MAX_STRING_LEN);
				JLOG_INFO("Got STUN mapped address %s from server", mapped_str);
			}

			ice_candidate_type_t type = (entry->type == AGENT_STUN_ENTRY_TYPE_CHECK)
			                                ? ICE_CANDIDATE_TYPE_PEER_REFLEXIVE
			                                : ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
			if (agent_add_local_reflexive_candidate(agent, type, &msg->mapped)) {
				JLOG_WARN("Failed to add local peer reflexive candidate from STUN mapped address");
			}
		}
		if (entry->type == AGENT_STUN_ENTRY_TYPE_CHECK) {
			// 7.2.5.2.1. Non-Symmetric Transport Addresses:
			// The ICE agent MUST check that the source and destination transport addresses in the
			// Binding request and response are symmetric. [...] If the addresses are not symmetric,
			// the agent MUST set the candidate pair state to Failed.
			if (!addr_record_is_equal(src, &entry->record, true)) {
				JLOG_DEBUG(
				    "Candidate pair check failed (non-symmetric source address in response)");
				entry->state = AGENT_STUN_ENTRY_STATE_FAILED;
				break;
			}

			ice_candidate_pair_t *pair = entry->pair;
			if (!pair) {
				JLOG_ERROR("STUN entry for candidate pair checking has no candidate pair");
				return -1;
			}

			if (pair->state != ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
				JLOG_DEBUG("Candidate pair check succeeded");
				pair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
			}

			if (!pair->local && msg->mapped.len)
				pair->local = ice_find_candidate_from_addr(&agent->local, &msg->mapped,
				                                           ICE_CANDIDATE_TYPE_UNKNOWN);

			// RFC 8445 7.3.1.5. Updating the Nominated Flag:
			// [...] once the check is sent and if it generates a successful response, and
			// generates a valid pair, the agent sets the nominated flag of the pair to true.
			if (pair->nomination_requested) {
				JLOG_DEBUG("Got a nominated pair (%s)",
				           agent->mode == AGENT_MODE_CONTROLLING ? "controlling" : "controlled");
				pair->nominated = true;
			}
		} else { // entry->type == AGENT_STUN_ENTRY_TYPE_SERVER
			agent_update_gathering_done(agent);
		}
		break;
	}
	case STUN_CLASS_RESP_ERROR: {
		if (msg->error_code != STUN_ERROR_INTERNAL_VALIDATION_FAILED)
			JLOG_WARN("Got STUN Binding error response, code=%u", (unsigned int)msg->error_code);

		if (entry->type == AGENT_STUN_ENTRY_TYPE_CHECK) {
			if (msg->error_code == 487) {
				if (entry->mode == agent->mode) {
					// RFC 8445 7.2.5.1. Role Conflict:
					// If the Binding request generates a 487 (Role Conflict) error response, and if
					// the ICE agent included an ICE-CONTROLLED attribute in the request, the agent
					// MUST switch to the controlling role. If the agent included an ICE-CONTROLLING
					// attribute in the request, the agent MUST switch to the controlled role. Once
					// the agent has switched its role, the agent MUST [...] set the candidate pair
					// state to Waiting [and] change the tiebreaker value.
					JLOG_WARN("ICE role conflit");
					JLOG_DEBUG("Switching roles to %s as requested",
					           entry->mode == AGENT_MODE_CONTROLLING ? "controlled"
					                                                 : "controlling");
					agent->mode = entry->mode == AGENT_MODE_CONTROLLING ? AGENT_MODE_CONTROLLED
					                                                    : AGENT_MODE_CONTROLLING;
					agent_update_candidate_pairs(agent);

					juice_random(&agent->ice_tiebreaker, sizeof(agent->ice_tiebreaker));
				} else {
					JLOG_DEBUG("Already switched roles to %s as requested",
					           agent->mode == AGENT_MODE_CONTROLLING ? "controlling"
					                                                 : "controlled");
				}

				entry->state = AGENT_STUN_ENTRY_STATE_PENDING;
				agent_arm_transmission(agent, entry, 0);

			} else {
				// 7.2.5.2.4. Unrecoverable STUN Response:
				// If the Binding request generates a STUN error response that is unrecoverable
				// [RFC5389], the ICE agent SHOULD set the candidate pair state to Failed.
				JLOG_DEBUG("Chandidate pair check failed (unrecoverable error)");
				entry->state = AGENT_STUN_ENTRY_STATE_FAILED;
			}
		} else { // entry->type == AGENT_STUN_ENTRY_TYPE_SERVER
			JLOG_INFO("STUN server binding failed (unrecoverable error)");
			entry->state = AGENT_STUN_ENTRY_STATE_FAILED;
			agent_update_gathering_done(agent);
		}
		break;
	}
	case STUN_CLASS_INDICATION: {
		JLOG_VERBOSE("Received STUN Binding indication");
		break;
	}
	default: {
		JLOG_WARN("Got STUN unexpected binding message, class=%u", (unsigned int)msg->msg_class);
		return -1;
	}
	}
	return 0;
}

int agent_send_stun_binding(juice_agent_t *agent, agent_stun_entry_t *entry, stun_class_t msg_class,
                            unsigned int error_code, const uint8_t *transaction_id,
                            const addr_record_t *mapped) {
	// Send STUN Binding
	JLOG_DEBUG("Sending STUN Binding %s",
	           msg_class == STUN_CLASS_REQUEST
	               ? "request"
	               : (msg_class == STUN_CLASS_INDICATION ? "indication" : "response"));

	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_class = msg_class;
	msg.msg_method = STUN_METHOD_BINDING;

	if (transaction_id)
		memcpy(msg.transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE);
	else if (msg_class == STUN_CLASS_INDICATION)
		juice_random(msg.transaction_id, STUN_TRANSACTION_ID_SIZE);
	else
		memcpy(msg.transaction_id, entry->transaction_id, STUN_TRANSACTION_ID_SIZE);

	const char *password = NULL;
	if (entry->type == AGENT_STUN_ENTRY_TYPE_CHECK) {
		// RFC 8445 7.2.2. Forming Credentials:
		// A connectivity-check Binding request MUST utilize the STUN short-term credential
		// mechanism. The username for the credential is formed by concatenating the username
		// fragment provided by the peer with the username fragment of the ICE agent sending the
		// request, separated by a colon (":"). The password is equal to the password provided by
		// the peer.
		switch (msg_class) {
		case STUN_CLASS_REQUEST: {
			if (*agent->remote.ice_ufrag == '\0' || *agent->remote.ice_pwd == '\0') {
				JLOG_ERROR("Attempted to send STUN Binding to peer without remote ICE credentials");
				return -1;
			}
			snprintf(msg.credentials.username, STUN_MAX_USERNAME_LEN, "%s:%s",
			         agent->remote.ice_ufrag, agent->local.ice_ufrag);
			password = agent->remote.ice_pwd;
			msg.ice_controlling = agent->mode == AGENT_MODE_CONTROLLING ? agent->ice_tiebreaker : 0;
			msg.ice_controlled = agent->mode == AGENT_MODE_CONTROLLED ? agent->ice_tiebreaker : 0;

			// RFC 8445 7.1.1. PRIORITY
			// The PRIORITY attribute MUST be included in a Binding request and be set to the value
			// computed by the algorithm in Section 5.1.2 for the local candidate, but with the
			// candidate type preference of peer-reflexive candidates.
			int family = entry->record.addr.ss_family;
			msg.priority = ice_compute_priority(ICE_CANDIDATE_TYPE_PEER_REFLEXIVE, family, 1);

			// RFC 8445 8.1.1. Nominating Pairs:
			// Once the controlling agent has picked a valid pair for nomination, it repeats the
			// connectivity check that produced this valid pair [...], this time with the
			// USE-CANDIDATE attribute.
			msg.use_candidate = agent->mode == AGENT_MODE_CONTROLLING && entry->pair &&
			                    entry->pair->nomination_requested;

			entry->mode = agent->mode; // save current mode in case of conflict
			break;
		}
		case STUN_CLASS_RESP_SUCCESS:
		case STUN_CLASS_RESP_ERROR: {
			password = agent->local.ice_pwd;
			msg.error_code = error_code;
			if (mapped)
				msg.mapped = *mapped;

			break;
		}
		case STUN_CLASS_INDICATION: {
			// RFC8445 11. Keepalives:
			// When STUN is being used for keepalives, a STUN Binding Indication is used. The
			// Indication MUST NOT utilize any authentication mechanism. It SHOULD contain the
			// FINGERPRINT attribute to aid in demultiplexing, but it SHOULD NOT contain any other
			// attributes.
		}
		}
	}

	char buffer[BUFFER_SIZE];
	int size = stun_write(buffer, BUFFER_SIZE, &msg, password);
	if (size <= 0) {
		JLOG_ERROR("STUN message write failed");
		return -1;
	}

	if (entry->relay_entry) {
		// The datagram must be sent through the relay
		JLOG_DEBUG("Sending STUN message via relay");
		if (agent_relay_send(agent, entry->relay_entry, &entry->record, buffer, size, 0) < 0) {
			JLOG_WARN("STUN message send via relay failed");
			return -1;
		}
		return 0;
	}

	// Direct send
	if (agent_direct_send2(agent, entry, buffer, size, 0) < 0) {
		JLOG_WARN("STUN message send failed, errno=%d", sockerrno);
		return -1;
	}
	return 0;
}

int agent_process_turn_allocate(juice_agent_t *agent, const stun_message_t *msg,
                                agent_stun_entry_t *entry) {
	if (msg->msg_method != STUN_METHOD_ALLOCATE && msg->msg_method != STUN_METHOD_REFRESH)
		return -1;
	if (entry->type != AGENT_STUN_ENTRY_TYPE_RELAY) {
		JLOG_WARN("Received TURN %s message for a non-relay entry, ignoring",
		          msg->msg_method == STUN_METHOD_ALLOCATE ? "Allocate" : "Refresh");
		return -1;
	}
	if (!entry->turn) {
		JLOG_ERROR("Missing TURN state on relay entry");
		return -1;
	}

	switch (msg->msg_class) {
	case STUN_CLASS_RESP_SUCCESS: {
		JLOG_DEBUG("Received TURN %s success response",
		           msg->msg_method == STUN_METHOD_ALLOCATE ? "Allocate" : "Refresh");

		if (msg->msg_method == STUN_METHOD_REFRESH) {
			JLOG_DEBUG("TURN refresh successful");
			// There is nothing to do other than rearm
			if (entry->state == AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE) {
				juice_random(entry->transaction_id, STUN_TRANSACTION_ID_SIZE);
				agent_arm_transmission(agent, entry, TURN_REFRESH_PERIOD);
			}
			break;
		}

		if (entry->state != AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE) {
			entry->state = AGENT_STUN_ENTRY_STATE_SUCCEEDED;
			entry->next_transmission = 0;
		}

		if (!agent->selected_pair || !agent->selected_pair->nominated) {
			// We want to send refresh requests now
			entry->state = AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE;
			juice_random(entry->transaction_id, STUN_TRANSACTION_ID_SIZE);
			agent_arm_transmission(agent, entry, TURN_REFRESH_PERIOD);
		}

		if (msg->mapped.len) {
			JLOG_VERBOSE("Response has mapped address");

			if (JLOG_INFO_ENABLED) {
				char mapped_str[ADDR_MAX_STRING_LEN];
				addr_record_to_string(&msg->mapped, mapped_str, ADDR_MAX_STRING_LEN);
				JLOG_INFO("Got STUN mapped address %s from TURN server", mapped_str);
			}

			if (entry->transport != JUICE_TRANSPORT_TCP) {
				if (agent_add_local_reflexive_candidate(agent, ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE,
														&msg->mapped)) {
					JLOG_WARN("Failed to add local peer reflexive candidate from",
							  "TURN mapped address");
				}
			}
		}

		if (!msg->relayed.len) {
			JLOG_ERROR("Expected relayed address in TURN %s response",
			           msg->msg_method == STUN_METHOD_ALLOCATE ? "Allocate" : "Refresh");
			entry->state = AGENT_STUN_ENTRY_STATE_FAILED;
			return -1;
		}

		entry->relayed = msg->relayed;
		if (agent_add_local_relayed_candidate(agent, &msg->relayed)) {
			JLOG_WARN("Failed to add local relayed candidate from TURN relayed address");
			return -1;
		}

		if (JLOG_INFO_ENABLED) {
			char relayed_str[ADDR_MAX_STRING_LEN];
			addr_record_to_string(&entry->relayed, relayed_str, ADDR_MAX_STRING_LEN);
			JLOG_INFO("Allocated TURN relayed address %s", relayed_str);
		}

		agent_update_gathering_done(agent);
		break;
	}
	case STUN_CLASS_RESP_ERROR: {
		if (msg->error_code == 401) { // Unauthorized
			JLOG_DEBUG("Got TURN %s Unauthorized response",
			           msg->msg_method == STUN_METHOD_ALLOCATE ? "Allocate" : "Refresh");
			if (*entry->turn->credentials.realm != '\0') {
				JLOG_ERROR("TURN authentication failed");
				entry->state = AGENT_STUN_ENTRY_STATE_FAILED;
				return -1;
			}
			if (*msg->credentials.realm == '\0' || *msg->credentials.nonce == '\0') {
				JLOG_ERROR("Expected realm and nonce in TURN error response");
				entry->state = AGENT_STUN_ENTRY_STATE_FAILED;
				return -1;
			}

			stun_process_credentials(&msg->credentials, &entry->turn->credentials);

			// Resend request when possible
			agent_arm_transmission(agent, entry, 0);

		} else if (msg->error_code == 438) { // Stale Nonce
			JLOG_DEBUG("Got TURN %s Stale Nonce response",
			           msg->msg_method == STUN_METHOD_ALLOCATE ? "Allocate" : "Refresh");
			if (*msg->credentials.realm == '\0' || *msg->credentials.nonce == '\0') {
				JLOG_ERROR("Expected realm and nonce in TURN error response");
				entry->state = AGENT_STUN_ENTRY_STATE_FAILED;
				return -1;
			}

			stun_process_credentials(&msg->credentials, &entry->turn->credentials);

			// Resend request when possible
			agent_arm_transmission(agent, entry, 0);

		} else {
			if (msg->error_code != STUN_ERROR_INTERNAL_VALIDATION_FAILED)
				JLOG_WARN("Got TURN %s error response, code=%u",
				          msg->msg_method == STUN_METHOD_ALLOCATE ? "Allocate" : "Refresh",
				          (unsigned int)msg->error_code);

			JLOG_INFO("TURN allocation failed");
			entry->state = AGENT_STUN_ENTRY_STATE_FAILED;
			agent_update_gathering_done(agent);
		}
		break;
	}
	default: {
		JLOG_WARN("Got unexpected TURN %s message, class=%u",
		          msg->msg_method == STUN_METHOD_ALLOCATE ? "Allocate" : "Refresh",
		          (unsigned int)msg->msg_class);
		return -1;
	}
	}
	return 0;
}

int agent_send_turn_allocate_request(juice_agent_t *agent, const agent_stun_entry_t *entry,
                                     stun_method_t method) {
	if (method != STUN_METHOD_ALLOCATE && method != STUN_METHOD_REFRESH)
		return -1;

	JLOG_DEBUG("Sending TURN %s request", method == STUN_METHOD_ALLOCATE ? "Allocate" : "Refresh");

	if (entry->type != AGENT_STUN_ENTRY_TYPE_RELAY) {
		JLOG_ERROR("Attempted to send a TURN %s request for a non-relay entry",
		           method == STUN_METHOD_ALLOCATE ? "Allocate" : "Refresh");
		return -1;
	}
	if (!entry->turn) {
		JLOG_ERROR("Missing TURN state on relay entry");
		return -1;
	}

	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_class = STUN_CLASS_REQUEST;
	msg.msg_method = method;
	memcpy(msg.transaction_id, entry->transaction_id, STUN_TRANSACTION_ID_SIZE);

	msg.credentials = entry->turn->credentials;
	msg.lifetime = TURN_LIFETIME / 1000; // seconds

	// Include allocation attributes in Allocate request only
	if (method == STUN_METHOD_ALLOCATE) {
		msg.requested_transport = true;
		msg.dont_fragment = true;
	}

	const char *password = *msg.credentials.nonce != '\0' ? entry->turn->password : NULL;

	char buffer[BUFFER_SIZE];
	int size = stun_write(buffer, BUFFER_SIZE, &msg, password);
	if (size <= 0) {
		JLOG_ERROR("STUN message write failed");
		return -1;
	}
	if (agent_direct_send2(agent, entry, buffer, size, 0) < 0) {
		JLOG_WARN("STUN message send failed, errno=%d", sockerrno);
		return -1;
	}
	return 0;
}

int agent_process_turn_create_permission(juice_agent_t *agent, const stun_message_t *msg,
                                         agent_stun_entry_t *entry) {
	(void)(agent);
	if (entry->type != AGENT_STUN_ENTRY_TYPE_RELAY) {
		JLOG_WARN("Received TURN CreatePermission message for a non-relay entry, ignoring");
		return -1;
	}
	if (!entry->turn) {
		JLOG_ERROR("Missing TURN state on relay entry");
		return -1;
	}

	switch (msg->msg_class) {
	case STUN_CLASS_RESP_SUCCESS: {
		JLOG_DEBUG("Received TURN CreatePermission success response");
		if (!turn_set_permission(&entry->turn->map, msg->transaction_id, NULL,
		                         PERMISSION_LIFETIME / 2))
			JLOG_WARN("Transaction ID from TURN CreatePermission response does not match");
		break;
	}
	case STUN_CLASS_RESP_ERROR: {
		if (msg->error_code == 438) { // Stale Nonce
			JLOG_DEBUG("Got TURN CreatePermission Stale Nonce response");
			if (*msg->credentials.realm == '\0' || *msg->credentials.nonce == '\0') {
				JLOG_ERROR("Expected realm and nonce in TURN error response");
				return -1;
			}

			stun_process_credentials(&msg->credentials, &entry->turn->credentials);

			// Resend
			addr_record_t record;
			if (turn_retrieve_transaction_id(&entry->turn->map, msg->transaction_id, &record))
				agent_send_turn_create_permission_request(agent, entry, &record, 0);

		} else if (msg->error_code != STUN_ERROR_INTERNAL_VALIDATION_FAILED) {
			JLOG_WARN("Got TURN CreatePermission error response, code=%u",
			          (unsigned int)msg->error_code);
		}
		break;
	}
	default: {
		JLOG_WARN("Got unexpected TURN CreatePermission message, class=%u",
		          (unsigned int)msg->msg_class);
		return -1;
	}
	}
	return 0;
}

int agent_send_turn_create_permission_request(juice_agent_t *agent, agent_stun_entry_t *entry,
                                              const addr_record_t *record, int ds) {
	if (JLOG_DEBUG_ENABLED) {
		char record_str[ADDR_MAX_STRING_LEN];
		addr_record_to_string(record, record_str, ADDR_MAX_STRING_LEN);
		JLOG_DEBUG("Sending TURN CreatePermission request for %s", record_str);
	}

	if (entry->type != AGENT_STUN_ENTRY_TYPE_RELAY) {
		JLOG_ERROR("Attempted to send a TURN CreatePermission request for a non-relay entry");
		return -1;
	}
	if (!entry->turn) {
		JLOG_ERROR("Missing TURN state on relay entry");
		return -1;
	}
	const stun_credentials_t *credentials = &entry->turn->credentials;

	if (*credentials->realm == '\0' || *credentials->nonce == '\0') {
		JLOG_ERROR("Missing realm and nonce to send TURN CreatePermission request");
		return -1;
	}

	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_class = STUN_CLASS_REQUEST;
	msg.msg_method = STUN_METHOD_CREATE_PERMISSION;
	if (!turn_set_random_permission_transaction_id(&entry->turn->map, record, msg.transaction_id))
		return -1;

	msg.credentials = entry->turn->credentials;
	msg.peer = *record;

	char buffer[BUFFER_SIZE];
	int size = stun_write(buffer, BUFFER_SIZE, &msg, entry->turn->password);
	if (size <= 0) {
		JLOG_ERROR("STUN message write failed");
		return -1;
	}
	if (agent_direct_send2(agent, entry, buffer, size, ds) < 0) {
		JLOG_WARN("STUN message send failed, errno=%d", sockerrno);
		return -1;
	}
	return 0;
}

int agent_process_turn_channel_bind(juice_agent_t *agent, const stun_message_t *msg,
                                    agent_stun_entry_t *entry) {
	(void)agent;
	if (entry->type != AGENT_STUN_ENTRY_TYPE_RELAY) {
		JLOG_WARN("Received TURN ChannelBind message for a non-relay entry, ignoring");
		return -1;
	}
	if (!entry->turn) {
		JLOG_ERROR("Missing TURN state on relay entry");
		return -1;
	}

	switch (msg->msg_class) {
	case STUN_CLASS_RESP_SUCCESS: {
		JLOG_DEBUG("Received TURN ChannelBind success response");
		if (!turn_bind_current_channel(&entry->turn->map, msg->transaction_id, NULL,
		                               BIND_LIFETIME / 2))
			JLOG_WARN("Transaction ID from TURN ChannelBind response does not match");
		break;
	}
	case STUN_CLASS_RESP_ERROR: {
		if (msg->error_code == 438) { // Stale Nonce
			JLOG_DEBUG("Got TURN ChannelBind Stale Nonce response");
			if (*msg->credentials.realm == '\0' || *msg->credentials.nonce == '\0') {
				JLOG_ERROR("Expected realm and nonce in TURN error response");
				return -1;
			}

			stun_process_credentials(&msg->credentials, &entry->turn->credentials);

			// Resend
			addr_record_t record;
			if (turn_retrieve_transaction_id(&entry->turn->map, msg->transaction_id, &record))
				agent_send_turn_channel_bind_request(agent, entry, &record, 0, NULL);

		} else if (msg->error_code != STUN_ERROR_INTERNAL_VALIDATION_FAILED) {
			JLOG_WARN("Got TURN ChannelBind error response, code=%u",
			          (unsigned int)msg->error_code);
		}
		break;
	}
	default: {
		JLOG_WARN("Got STUN unexpected ChannelBind message, class=%u",
		          (unsigned int)msg->msg_class);
		return -1;
	}
	}
	return 0;
}

int agent_send_turn_channel_bind_request(juice_agent_t *agent, agent_stun_entry_t *entry,
                                         const addr_record_t *record, int ds,
                                         uint16_t *out_channel) {
	if (JLOG_DEBUG_ENABLED) {
		char record_str[ADDR_MAX_STRING_LEN];
		addr_record_to_string(record, record_str, ADDR_MAX_STRING_LEN);
		JLOG_DEBUG("Sending TURN ChannelBind request for %s", record_str);
	}

	if (entry->type != AGENT_STUN_ENTRY_TYPE_RELAY) {
		JLOG_ERROR("Attempted to send a TURN ChannelBind request for a non-relay entry");
		return -1;
	}
	if (!entry->turn) {
		JLOG_ERROR("Missing TURN state on relay entry");
		return -1;
	}
	const stun_credentials_t *credentials = &entry->turn->credentials;
	const char *password = entry->turn->password;

	if (*credentials->realm == '\0' || *credentials->nonce == '\0') {
		JLOG_ERROR("Missing realm and nonce to send TURN ChannelBind request");
		return -1;
	}

	uint16_t channel;
	if (!turn_get_channel(&entry->turn->map, record, &channel))
		if (!turn_bind_random_channel(&entry->turn->map, record, &channel, 0))
			return -1;

	stun_message_t msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_class = STUN_CLASS_REQUEST;
	msg.msg_method = STUN_METHOD_CHANNEL_BIND;
	if (!turn_set_random_channel_transaction_id(&entry->turn->map, record, msg.transaction_id))
		return -1;

	msg.credentials = entry->turn->credentials;
	msg.channel_number = channel;
	msg.peer = *record;

	if (out_channel)
		*out_channel = channel;

	char buffer[BUFFER_SIZE];
	int size = stun_write(buffer, BUFFER_SIZE, &msg, password);
	if (size <= 0) {
		JLOG_ERROR("STUN message write failed");
		return -1;
	}
	if (agent_direct_send2(agent, entry, buffer, size, ds) < 0) {
		JLOG_WARN("STUN message send failed, errno=%d", sockerrno);
		return -1;
	}
	return 0;
}

int agent_process_turn_data(juice_agent_t *agent, const stun_message_t *msg,
                            agent_stun_entry_t *entry) {
	if (entry->type != AGENT_STUN_ENTRY_TYPE_RELAY) {
		JLOG_WARN("Received TURN Data message for a non-relay entry, ignoring");
		return -1;
	}
	if (msg->msg_class != STUN_CLASS_INDICATION) {
		JLOG_WARN("Received non-indication TURN Data message, ignoring");
		return -1;
	}

	JLOG_DEBUG("Received TURN Data indication");
	if (!msg->data) {
		JLOG_WARN("Missing data in TURN Data indication");
		return -1;
	}
	if (!msg->peer.len) {
		JLOG_WARN("Missing peer address in TURN Data indication");
		return -1;
	}
	return agent_input(agent, (char *)msg->data, msg->data_size, &msg->peer, &entry->relayed);
}

int agent_process_channel_data(juice_agent_t *agent, agent_stun_entry_t *entry, char *buf,
                               size_t len) {
	if (len < sizeof(struct channel_data_header)) {
		JLOG_WARN("ChannelData is too short");
		return -1;
	}

	const struct channel_data_header *header = (const struct channel_data_header *)buf;
	buf += sizeof(struct channel_data_header);
	len -= sizeof(struct channel_data_header);
	uint16_t channel = ntohs(header->channel_number);
	uint16_t length = ntohs(header->length);
	JLOG_VERBOSE("Received ChannelData, channel=0x%hX, length=%hu", channel, length);
	if (length > len) {
		JLOG_WARN("ChannelData has invalid length");
		return -1;
	}

	addr_record_t src;
	if (!turn_find_channel(&entry->turn->map, channel, &src)) {
		JLOG_WARN("Channel not found");
		return -1;
	}

	return agent_input(agent, buf, length, &src, &entry->relayed);
}

int agent_add_local_relayed_candidate(juice_agent_t *agent, const addr_record_t *record) {
	if (ice_find_candidate_from_addr(&agent->local, record, ICE_CANDIDATE_TYPE_RELAYED)) {
		JLOG_VERBOSE("The relayed local candidate already exists");
		return 0;
	}
	ice_candidate_t candidate;
	if (ice_create_local_candidate(ICE_CANDIDATE_TYPE_RELAYED, 1, record, &candidate)) {
		JLOG_ERROR("Failed to create relayed candidate");
		return -1;
	}
	if (ice_add_candidate(&candidate, &agent->local)) {
		JLOG_ERROR("Failed to add candidate to local description");
		return -1;
	}

	char buffer[BUFFER_SIZE];
	if (ice_generate_candidate_sdp(&candidate, buffer, BUFFER_SIZE) < 0) {
		JLOG_ERROR("Failed to generate SDP for local candidate");
		return -1;
	}
	JLOG_DEBUG("Gathered relayed candidate: %s", buffer);

	// Relayed candidates must be differenciated, so match them with already known remote candidates
	ice_candidate_t *local = agent->local.candidates + agent->local.candidates_count - 1;
	for (int i = 0; i < agent->remote.candidates_count; ++i) {
		ice_candidate_t *remote = agent->remote.candidates + i;
		if (local->resolved.addr.ss_family == remote->resolved.addr.ss_family)
			agent_add_candidate_pair(agent, local, remote);
	}

	if (agent->config.cb_candidate)
		agent->config.cb_candidate(agent, buffer, agent->config.user_ptr);

	return 0;
}

int agent_add_local_reflexive_candidate(juice_agent_t *agent, ice_candidate_type_t type,
                                        const addr_record_t *record) {
	if (type != ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE && type != ICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
		JLOG_ERROR("Invalid type for local reflexive candidate");
		return -1;
	}
	int family = record->addr.ss_family;
	if (ice_find_candidate_from_addr(&agent->local, record,
	                                 family == AF_INET6 ? ICE_CANDIDATE_TYPE_UNKNOWN : type)) {
		JLOG_VERBOSE("A local candidate exists for the mapped address");
		return 0;
	}
	ice_candidate_t candidate;
	if (ice_create_local_candidate(type, 1, record, &candidate)) {
		JLOG_ERROR("Failed to create reflexive candidate");
		return -1;
	}
	if (candidate.type == ICE_CANDIDATE_TYPE_PEER_REFLEXIVE &&
	    ice_candidates_count(&agent->local, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE) >=
	        MAX_PEER_REFLEXIVE_CANDIDATES_COUNT) {
		JLOG_INFO(
		    "Local description has the maximum number of peer reflexive candidates, ignoring");
		return 0;
	}
	if (ice_add_candidate(&candidate, &agent->local)) {
		JLOG_ERROR("Failed to add candidate to local description");
		return -1;
	}

	char buffer[BUFFER_SIZE];
	if (ice_generate_candidate_sdp(&candidate, buffer, BUFFER_SIZE) < 0) {
		JLOG_ERROR("Failed to generate SDP for local candidate");
		return -1;
	}
	JLOG_DEBUG("Gathered reflexive candidate: %s", buffer);

	if (type != ICE_CANDIDATE_TYPE_PEER_REFLEXIVE && agent->config.cb_candidate)
		agent->config.cb_candidate(agent, buffer, agent->config.user_ptr);

	return 0;
}

int agent_add_remote_reflexive_candidate(juice_agent_t *agent, ice_candidate_type_t type,
                                         uint32_t priority, const addr_record_t *record) {
	if (type != ICE_CANDIDATE_TYPE_PEER_REFLEXIVE) {
		JLOG_ERROR("Invalid type for remote reflexive candidate");
		return -1;
	}
	int family = record->addr.ss_family;
	if (ice_find_candidate_from_addr(&agent->remote, record,
	                                 family == AF_INET6 ? ICE_CANDIDATE_TYPE_UNKNOWN : type)) {
		JLOG_VERBOSE("A remote candidate exists for the remote address");
		return 0;
	}
	ice_candidate_t candidate;
	if (ice_create_local_candidate(type, 1, record, &candidate)) {
		JLOG_ERROR("Failed to create reflexive candidate");
		return -1;
	}
	if (ice_candidates_count(&agent->remote, ICE_CANDIDATE_TYPE_PEER_REFLEXIVE) >=
	    MAX_PEER_REFLEXIVE_CANDIDATES_COUNT) {
		JLOG_INFO(
		    "Remote description has the maximum number of peer reflexive candidates, ignoring");
		return 0;
	}
	if (ice_add_candidate(&candidate, &agent->remote)) {
		JLOG_ERROR("Failed to add candidate to remote description");
		return -1;
	}

	JLOG_DEBUG("Obtained a new remote reflexive candidate, priority=%lu", (unsigned long)priority);

	ice_candidate_t *remote = agent->remote.candidates + agent->remote.candidates_count - 1;
	remote->priority = priority;

	return agent_add_candidate_pairs_for_remote(agent, remote);
}

int agent_add_candidate_pair(juice_agent_t *agent, ice_candidate_t *local, // local may be NULL
                             ice_candidate_t *remote) {
	ice_candidate_pair_t pair;
	bool is_controlling = agent->mode == AGENT_MODE_CONTROLLING;
	if (ice_create_candidate_pair(local, remote, is_controlling, &pair)) {
		JLOG_ERROR("Failed to create candidate pair");
		return -1;
	}

	if (agent->candidate_pairs_count >= MAX_CANDIDATE_PAIRS_COUNT) {
		JLOG_WARN("Session already has the maximum number of candidate pairs");
		return -1;
	}

	JLOG_VERBOSE("Adding new candidate pair, priority=%" PRIu64, pair.priority);

	// Add pair
	ice_candidate_pair_t *pos = agent->candidate_pairs + agent->candidate_pairs_count;
	*pos = pair;
	++agent->candidate_pairs_count;

	agent_update_ordered_pairs(agent);

	if (agent->entries_count == MAX_STUN_ENTRIES_COUNT) {
		JLOG_WARN("No free STUN entry left for candidate pair checking");
		return -1;
	}

	agent_stun_entry_t *relay_entry = NULL;
	if (local && local->type == ICE_CANDIDATE_TYPE_RELAYED) {
		for (int i = 0; i < agent->entries_count; ++i) {
			agent_stun_entry_t *other_entry = agent->entries + i;
			if (other_entry->type == AGENT_STUN_ENTRY_TYPE_RELAY &&
			    addr_record_is_equal(&other_entry->relayed, &local->resolved, true)) {
				relay_entry = other_entry;
				break;
			}
		}
		if (!relay_entry) {
			JLOG_ERROR("Relay entry not found");
			return -1;
		}
	}

	JLOG_VERBOSE("Registering STUN entry %d for candidate pair checking", agent->entries_count);
	agent_stun_entry_t *entry = agent->entries + agent->entries_count;
	entry->type = AGENT_STUN_ENTRY_TYPE_CHECK;
	entry->state = AGENT_STUN_ENTRY_STATE_IDLE;
	entry->mode = AGENT_MODE_UNKNOWN;
	entry->pair = pos;
	entry->record = pos->remote->resolved;
	entry->relay_entry = relay_entry;
	entry->transport = JUICE_TRANSPORT_NONE;
	entry->sock = INVALID_SOCKET;
	juice_random(entry->transaction_id, STUN_TRANSACTION_ID_SIZE);
	++agent->entries_count;

	if (remote->type == ICE_CANDIDATE_TYPE_HOST)
		agent_translate_host_candidate_entry(agent, entry);

	if (agent->mode == AGENT_MODE_CONTROLLING) {
		for (int i = 0; i < agent->candidate_pairs_count; ++i) {
			ice_candidate_pair_t *ordered_pair = agent->ordered_pairs[i];
			if (ordered_pair == pos) {
				JLOG_VERBOSE("Candidate pair has priority");
				break;
			}
			if (ordered_pair->state == ICE_CANDIDATE_PAIR_STATE_SUCCEEDED) {
				// We found a succeeded pair with higher priority, ignore this one
				JLOG_VERBOSE("Candidate pair doesn't have priority, keeping it frozen");
				return 0;
			}
		}
	}

	// There is only one component, therefore we can unfreeze the pair and schedule it when possible
	if (*agent->remote.ice_ufrag != '\0') {
		JLOG_VERBOSE("Unfreezing the new candidate pair");
		agent_unfreeze_candidate_pair(agent, pos);
	}

	return 0;
}

int agent_add_candidate_pairs_for_remote(juice_agent_t *agent, ice_candidate_t *remote) {
	// Here is the trick: local non-relayed candidates are undifferentiated for sending.
	// Therefore, we don't need to match remote candidates with local ones.
	if (agent_add_candidate_pair(agent, NULL, remote))
		return -1;

	// However, we need still to differenciate local relayed candidates
	for (int i = 0; i < agent->local.candidates_count; ++i) {
		ice_candidate_t *local = agent->local.candidates + i;
		if (local->type == ICE_CANDIDATE_TYPE_RELAYED &&
		    local->resolved.addr.ss_family == remote->resolved.addr.ss_family)
			if (agent_add_candidate_pair(agent, local, remote))
				return -1;
	}

	return 0;
}

int agent_unfreeze_candidate_pair(juice_agent_t *agent, ice_candidate_pair_t *pair) {
	if (pair->state != ICE_CANDIDATE_PAIR_STATE_FROZEN)
		return 0;

	for (int i = 0; i < agent->entries_count; ++i) {
		agent_stun_entry_t *entry = agent->entries + i;
		if (entry->pair == pair) {
			pair->state = ICE_CANDIDATE_PAIR_STATE_PENDING;
			entry->state = AGENT_STUN_ENTRY_STATE_PENDING;
			agent_arm_transmission(agent, entry, 0); // transmit now
			return 0;
		}
	}

	JLOG_WARN("Unable to unfreeze the pair: no matching entry");
	return -1;
}

void agent_arm_transmission(juice_agent_t *agent, agent_stun_entry_t *entry, timediff_t delay) {
#ifdef NO_ATOMICS
	entry->armed = true;
#else
	atomic_flag_test_and_set(&entry->armed);
#endif

	if (entry->state != AGENT_STUN_ENTRY_STATE_SUCCEEDED_KEEPALIVE)
		entry->state = AGENT_STUN_ENTRY_STATE_PENDING;

	// Arm transmission
	entry->next_transmission = current_timestamp() + delay;

	if (entry->state == AGENT_STUN_ENTRY_STATE_PENDING) {
		bool limit = agent->selected_pair &&
		             (agent->selected_pair->nominated || (agent->selected_pair != entry->pair &&
		                                                  agent->mode == AGENT_MODE_CONTROLLING));
		if (entry->sock != INVALID_SOCKET && entry->transport != JUICE_TRANSPORT_TCP) {
			entry->retransmissions = limit ? 1 : MAX_STUN_RETRANSMISSION_COUNT;
			entry->retransmission_timeout = MIN_STUN_RETRANSMISSION_TIMEOUT;
		}
		else {
			entry->retransmissions = 1;
			entry->retransmission_timeout = MIN_STUN_RETRANSMISSION_TIMEOUT *
											MAX_STUN_RETRANSMISSION_COUNT;
		}
	}

	// Find a time slot
	agent_stun_entry_t *other = agent->entries;
	while (other != agent->entries + agent->entries_count) {
		if (other != entry) {
			timestamp_t other_transmission = other->next_transmission;
			timediff_t timediff = entry->next_transmission - other_transmission;
			if (other_transmission && abs((int)timediff) < STUN_PACING_TIME) {
				entry->next_transmission = other_transmission + STUN_PACING_TIME;
				other = agent->entries;
				continue;
			}
		}
		++other;
	}
}

void agent_update_gathering_done(juice_agent_t *agent) {
	JLOG_VERBOSE("Updating gathering status");
	for (int i = 0; i < agent->entries_count; ++i) {
		agent_stun_entry_t *entry = agent->entries + i;
		if (entry->type != AGENT_STUN_ENTRY_TYPE_CHECK &&
		    entry->state == AGENT_STUN_ENTRY_STATE_PENDING) {
			JLOG_VERBOSE("STUN server or relay entry %d is still pending", i);
			return;
		}
	}
	if (!agent->gathering_done) {
		JLOG_INFO("Candidate gathering done");
		agent->local.finished = true;
		agent->gathering_done = true;

		if (agent->config.cb_gathering_done)
			agent->config.cb_gathering_done(agent, agent->config.user_ptr);
	}
}

void agent_update_candidate_pairs(juice_agent_t *agent) {
	bool is_controlling = agent->mode == AGENT_MODE_CONTROLLING;
	for (int i = 0; i < agent->candidate_pairs_count; ++i) {
		ice_candidate_pair_t *pair = agent->candidate_pairs + i;
		ice_update_candidate_pair(pair, is_controlling);
	}
	agent_update_ordered_pairs(agent);
}

void agent_update_ordered_pairs(juice_agent_t *agent) {
	JLOG_VERBOSE("Updating ordered candidate pairs");
	for (int i = 0; i < agent->candidate_pairs_count; ++i) {
		ice_candidate_pair_t **begin = agent->ordered_pairs;
		ice_candidate_pair_t **end = begin + i;
		ice_candidate_pair_t **prev = end;
		uint64_t priority = agent->candidate_pairs[i].priority;
		while (--prev >= begin && (*prev)->priority < priority)
			*(prev + 1) = *prev;

		*(prev + 1) = agent->candidate_pairs + i;
	}
}

static inline bool pair_is_relayed(const ice_candidate_pair_t *pair) {
	return pair->local && pair->local->type == ICE_CANDIDATE_TYPE_RELAYED;
}

static inline bool entry_is_relayed(const agent_stun_entry_t *entry) {
	return entry->pair && pair_is_relayed(entry->pair);
}

agent_stun_entry_t *agent_find_entry_from_record(juice_agent_t *agent, const addr_record_t *record,
                                                 const addr_record_t *relayed) {
#ifdef NO_ATOMICS
	agent_stun_entry_t *selected_entry = agent->selected_entry;
#else
	agent_stun_entry_t *selected_entry = atomic_load(&agent->selected_entry);
#endif

	if (agent->state == JUICE_STATE_COMPLETED && selected_entry) {
		// As an optimization, try to match the selected entry first
		if (relayed) {
			if (entry_is_relayed(selected_entry) &&
			    addr_record_is_equal(&selected_entry->pair->local->resolved, relayed, true) &&
			    addr_record_is_equal(&selected_entry->record, record, true)) {
				JLOG_DEBUG("STUN selected entry matching incoming relayed address");
				return selected_entry;
			}
		} else {
			if (!entry_is_relayed(selected_entry) &&
			    addr_record_is_equal(&selected_entry->record, record, true)) {
				JLOG_DEBUG("STUN selected entry matching incoming address");
				return selected_entry;
			}
		}
	}

	if (relayed) {
		for (int i = 0; i < agent->entries_count; ++i) {
			agent_stun_entry_t *entry = agent->entries + i;
			if (entry_is_relayed(entry) &&
			    addr_record_is_equal(&entry->pair->local->resolved, relayed, true) &&
			    addr_record_is_equal(&entry->record, record, true)) {
				JLOG_DEBUG("STUN entry %d matching incoming relayed address", i);
				return entry;
			}
		}
	} else {
		// Try to match pairs by priority first
		ice_candidate_pair_t *matching_pair = NULL;
		for (int i = 0; i < agent->candidate_pairs_count; ++i) {
			ice_candidate_pair_t *pair = agent->ordered_pairs[i];
			if (!pair_is_relayed(pair) &&
			    addr_record_is_equal(&pair->remote->resolved, record, true)) {
				matching_pair = pair;
				break;
			}
		}

		if (matching_pair) {
			// Just find the corresponding entry
			for (int i = 0; i < agent->entries_count; ++i) {
				agent_stun_entry_t *entry = agent->entries + i;
				if (entry->pair == matching_pair) {
					JLOG_DEBUG("STUN entry %d pair matching incoming address", i);
					return entry;
				}
			}
		}

		// Try to match entries directly
		for (int i = 0; i < agent->entries_count; ++i) {
			agent_stun_entry_t *entry = agent->entries + i;
			if (!entry_is_relayed(entry) && addr_record_is_equal(&entry->record, record, true)) {
				JLOG_DEBUG("STUN entry %d matching incoming address", i);
				return entry;
			}
		}
	}
	return NULL;
}

void agent_translate_host_candidate_entry(juice_agent_t *agent, agent_stun_entry_t *entry) {
	if (!entry->pair || entry->pair->remote->type != ICE_CANDIDATE_TYPE_HOST)
		return;

#if JUICE_ENABLE_LOCAL_ADDRESS_TRANSLATION
	for (int i = 0; i < agent->local.candidates_count; ++i) {
		ice_candidate_t *candidate = agent->local.candidates + i;
		if (candidate->type != ICE_CANDIDATE_TYPE_HOST)
			continue;

		if (addr_record_is_equal(&candidate->resolved, &entry->record, false)) {
			JLOG_DEBUG("Entry remote address matches local candidate, translating to localhost");
			struct sockaddr_storage *addr = &entry->record.addr;
			switch (addr->ss_family) {
			case AF_INET6: {
				struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
				memset(&sin6->sin6_addr, 0, 16);
				*((uint8_t *)&sin6->sin6_addr + 15) = 0x01;
				break;
			}
			case AF_INET: {
				struct sockaddr_in *sin = (struct sockaddr_in *)addr;
				const uint8_t localhost[4] = {127, 0, 0, 1};
				memcpy(&sin->sin_addr, localhost, 4);
				break;
			}
			default:
				// Ignore
				break;
			}
			break;
		}
	}
#else
	(void)agent;
#endif
}
