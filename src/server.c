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

#ifndef NO_SERVER

#include "server.h"
#include "const_time.h"
#include "hmac.h"
#include "ice.h"
#include "juice.h"
#include "log.h"
#include "random.h"
#include "stun.h"
#include "turn.h"
#include "udp.h"

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

#define ALLOCATION_LIFETIME 600000 // ms

// RFC 8656: The Permission Lifetime MUST be 300 seconds (= 5 minutes)
#define PERMISSION_LIFETIME 300000 // ms

// RFC 8656: Channel bindings last for 10 minutes unless refreshed
#define BIND_LIFETIME 600000 // ms

#define MAX_RELAYED_RECORDS_COUNT 8
#define BUFFER_SIZE 4096

static char *alloc_string_copy(const char *orig) {
	if (!orig)
		return NULL;

	char *copy = malloc(strlen(orig) + 1);
	if (!copy)
		return NULL;

	strcpy(copy, orig);
	return copy;
}

static void *alloc_copy(const void *orig, size_t size) {
	if (!orig || !size)
		return NULL;

	char *copy = malloc(size);
	if (!copy)
		return NULL;

	memcpy(copy, orig, size);
	return copy;
}

static server_turn_alloc_t *find_allocation(server_turn_alloc_t allocs[], int size,
                                            const addr_record_t *record, bool allow_deleted) {
	unsigned long key = addr_record_hash(record, true) % size;
	unsigned long pos = key;
	while (!(allocs[pos].state == SERVER_TURN_ALLOC_EMPTY ||
	         (allow_deleted && allocs[pos].state == SERVER_TURN_ALLOC_DELETED) ||
	         addr_record_is_equal(&allocs[pos].record, record, true))) {
		pos = (pos + 1) % size;
		if (pos == key) {
			JLOG_VERBOSE("TURN allocation map is full");
			return NULL;
		}
	}
	return allocs + pos;
}

static void delete_allocation(server_turn_alloc_t *alloc) {
	if (alloc->state != SERVER_TURN_ALLOC_FULL)
		return;

	++alloc->credentials->allocations_quota;

	alloc->state = SERVER_TURN_ALLOC_DELETED;
	turn_destroy_map(&alloc->map);
	closesocket(alloc->sock);
	alloc->sock = INVALID_SOCKET;
	alloc->credentials = NULL;
}

thread_return_t THREAD_CALL server_thread_entry(void *arg) {
	server_run((juice_server_t *)arg);
	return (thread_return_t)0;
}

juice_server_t *server_create(const juice_server_config_t *config) {
	JLOG_VERBOSE("Creating server");

#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData)) {
		JLOG_FATAL("WSAStartup failed");
		return NULL;
	}
#endif

	juice_server_t *server = calloc(1, sizeof(juice_server_t));
	if (!server) {
		JLOG_FATAL("Memory allocation for server data failed");
		return NULL;
	}

	udp_socket_config_t socket_config;
	memset(&socket_config, 0, sizeof(socket_config));
	socket_config.bind_address = config->bind_address;
	socket_config.port_begin = config->port;
	socket_config.port_end = config->port;

	server->sock = udp_create_socket(&socket_config);
	if (server->sock == INVALID_SOCKET) {
		JLOG_FATAL("Server socket opening failed");
		free(server);
		return NULL;
	}

	mutex_init(&server->mutex, MUTEX_RECURSIVE);

	server->config = *config;

	if (server->config.bind_address) {
		server->config.bind_address = alloc_string_copy(server->config.bind_address);
		if (!server->config.bind_address) {
			JLOG_FATAL("Memory allocation for bind address failed");
			goto error;
		}
	}

	if (server->config.external_address) {
		server->config.external_address = alloc_string_copy(server->config.external_address);
		if (!server->config.external_address) {
			JLOG_FATAL("Memory allocation for external address failed");
			goto error;
		}
	}

	const char *realm =
	    config->realm && *config->realm != '\0' ? config->realm : SERVER_DEFAULT_REALM;
	server->config.realm = alloc_string_copy(realm);
	if (!server->config.realm) {
		JLOG_FATAL("Memory allocation for realm failed");
		goto error;
	}

	if (server->config.credentials_count == 0) {
		// TURN disabled
		JLOG_INFO("TURN relaying disabled, STUN-only mode");
		server->config.max_allocations = 0;
		server->allocs_count = 0;
		server->allocs = NULL;

	} else {
		// TURN enabled
		if (server->config.max_allocations == 0)
			server->config.max_allocations = SERVER_DEFAULT_MAX_ALLOCATIONS;

		server->config.credentials =
		    alloc_copy(server->config.credentials,
		               server->config.credentials_count * sizeof(stun_credentials_t));
		server->credentials_userhash = calloc(server->config.credentials_count, sizeof(uint8_t *));
		if (!server->config.credentials || !server->credentials_userhash) {
			JLOG_FATAL("Memory allocation for TURN credentials array failed");
			goto error;
		}

		for (int i = 0; i < server->config.credentials_count; ++i) {
			juice_server_credentials_t *credentials = server->config.credentials + i;
			credentials->username =
			    alloc_string_copy(credentials->username ? credentials->username : "");
			credentials->password =
			    alloc_string_copy(credentials->password ? credentials->password : "");
			server->credentials_userhash[i] = malloc(HASH_SHA256_SIZE);
			if (!credentials->username || !credentials->password ||
			    !server->credentials_userhash[i]) {
				JLOG_FATAL("Memory allocation for TURN credentials failed");
				goto error;
			}

			stun_compute_userhash(credentials->username, realm, server->credentials_userhash[i]);

			if (server->config.max_allocations < credentials->allocations_quota)
				server->config.max_allocations = credentials->allocations_quota;
		}

		for (int i = 0; i < server->config.credentials_count; ++i) {
			juice_server_credentials_t *credentials = server->config.credentials + i;
			if (credentials->allocations_quota == 0) // unlimited
				credentials->allocations_quota = server->config.max_allocations;
		}

		server->allocs_count = (int)server->config.max_allocations;
		server->allocs = calloc(server->allocs_count, sizeof(server_turn_alloc_t));
		if (!server->allocs) {
			JLOG_FATAL("Memory allocation for TURN allocation table failed");
			goto error;
		}
	}

	server->config.port = udp_get_port(server->sock);
	server->nonce_key_timestamp = 0;
	if (server->config.max_peers == 0)
		server->config.max_peers = SERVER_DEFAULT_MAX_PEERS;

	if (server->config.bind_address)
		JLOG_INFO("Created server on %s:%hu", server->config.bind_address, server->config.port);
	else
		JLOG_INFO("Created server on port %hu", server->config.port);

	int ret = thread_init(&server->thread, server_thread_entry, server);
	if (ret) {
		JLOG_FATAL("thread_create for server failed, error=%d", ret);
		goto error;
	}

	return server;

error:
	server_do_destroy(server);
	return NULL;
}

void server_do_destroy(juice_server_t *server) {
	JLOG_DEBUG("Destroying server");

	closesocket(server->sock);
	mutex_destroy(&server->mutex);

	for (int i = 0; i < server->config.credentials_count; ++i) {
		juice_server_credentials_t *credentials = server->config.credentials + i;
		free((void *)credentials->username);
		free((void *)credentials->password);
		free(server->credentials_userhash[i]);
	}
	free((void *)server->config.realm);
	free(server->config.credentials);
	free(server->credentials_userhash);
	free(server);

#ifdef _WIN32
	WSACleanup();
#endif
	JLOG_VERBOSE("Destroyed server");
}

void server_destroy(juice_server_t *server) {
	mutex_lock(&server->mutex);

	JLOG_DEBUG("Waiting for server thread");
	server->thread_stopped = true;
	mutex_unlock(&server->mutex);
	server_interrupt(server);
	thread_join(server->thread, NULL);

	server_do_destroy(server);
}

uint16_t server_get_port(juice_server_t *server) {
	mutex_lock(&server->mutex);
	return server->config.port; // updated at creation
}

void server_run(juice_server_t *server) {
	mutex_lock(&server->mutex);

	// Main loop
	timestamp_t next_timestamp;
	while (server_bookkeeping(server, &next_timestamp) == 0) {
		timediff_t timediff = next_timestamp - current_timestamp();
		if (timediff < 0)
			timediff = 0;

		JLOG_VERBOSE("Setting select timeout to %ld ms", (long)timediff);
		struct timeval timeout;
		timeout.tv_sec = (long)(timediff / 1000);
		timeout.tv_usec = (long)((timediff % 1000) * 1000);

		fd_set readfds;
		FD_ZERO(&readfds);
		FD_SET(server->sock, &readfds);
		int max = SOCKET_TO_INT(server->sock);

		int count = 1;
		for (int i = 0; i < server->allocs_count; ++i) {
			server_turn_alloc_t *alloc = server->allocs + i;
			if (alloc->state == SERVER_TURN_ALLOC_FULL) {
				++count;
				FD_SET(alloc->sock, &readfds);
				if (max < SOCKET_TO_INT(alloc->sock))
					max = SOCKET_TO_INT(alloc->sock);
			}
		}

		JLOG_VERBOSE("Entering select on %d socket(s)", count);
		mutex_unlock(&server->mutex);
		int ret = select(max + 1, &readfds, NULL, NULL, &timeout);
		mutex_lock(&server->mutex);
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

		if (server->thread_stopped) {
			JLOG_VERBOSE("Agent destruction requested");
			break;
		}

		for (int i = 0; i < server->allocs_count; ++i) {
			server_turn_alloc_t *alloc = server->allocs + i;
			if (alloc->state == SERVER_TURN_ALLOC_FULL && FD_ISSET(alloc->sock, &readfds))
				server_forward(server, alloc);
		}

		if (FD_ISSET(server->sock, &readfds)) {
			if (server_recv(server) < 0)
				break;
		}
	}
	JLOG_DEBUG("Leaving server thread");
	mutex_unlock(&server->mutex);
}

int server_send(juice_server_t *server, const addr_record_t *dst, const char *data, size_t size) {
	JLOG_VERBOSE("Sending datagram, size=%d", size);

#if defined(_WIN32) || defined(__APPLE__)
	addr_record_t tmp = *dst;
	addr_map_inet6_v4mapped(&tmp.addr, &tmp.len);
	int ret = sendto(server->sock, data, (int)size, 0, (const struct sockaddr *)&tmp.addr, tmp.len);
#else
	int ret = sendto(server->sock, data, size, 0, (const struct sockaddr *)&dst->addr, dst->len);
#endif
	if (ret < 0 && sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK)
		JLOG_WARN("Send failed, errno=%d", sockerrno);

	return ret;
}

int server_stun_send(juice_server_t *server, const addr_record_t *dst, const stun_message_t *msg,
                     const char *password) {
	char buffer[BUFFER_SIZE];
	int size = stun_write(buffer, BUFFER_SIZE, msg, password);
	if (size <= 0) {
		JLOG_ERROR("STUN message write failed");
		return -1;
	}

	if (server_send(server, dst, buffer, size) < 0) {
		JLOG_WARN("STUN message send failed, errno=%d", sockerrno);
		return -1;
	}
	return 0;
}

int server_recv(juice_server_t *server) {
	JLOG_VERBOSE("Receiving datagrams");
	while (true) {
		char buffer[BUFFER_SIZE];
		addr_record_t record;
		record.len = sizeof(record.addr);
		int len = recvfrom(server->sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&record.addr,
		                   &record.len);
		if (len < 0) {
			if (sockerrno == SECONNRESET || sockerrno == SENETRESET || sockerrno == SECONNREFUSED) {
				// On Windows, if a UDP socket receives an ICMP port unreachable response after
				// sending a datagram, this error is stored, and the next call to recvfrom() returns
				// WSAECONNRESET (port unreachable) or WSAENETRESET (TTL expired).
				// Therefore, it may be ignored.
				JLOG_DEBUG("Ignoring %s returned by recvfrom",
				           sockerrno == SECONNRESET
				               ? "ECONNRESET"
				               : (sockerrno == SENETRESET ? "ENETRESET" : "ECONNREFUSED"));
				continue;
			}
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
		server_input(server, buffer, len, &record);
	}

	return 0;
}

int server_forward(juice_server_t *server, server_turn_alloc_t *alloc) {
	JLOG_VERBOSE("Forwarding datagrams");
	while (true) {
		char buffer[BUFFER_SIZE];
		addr_record_t record;
		record.len = sizeof(record.addr);
		int len = recvfrom(alloc->sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&record.addr,
		                   &record.len);
		if (len < 0) {
			if (sockerrno == SECONNRESET || sockerrno == SENETRESET || sockerrno == SECONNREFUSED) {
				// On Windows, if a UDP socket receives an ICMP port unreachable response after
				// sending a datagram, this error is stored, and the next call to recvfrom() returns
				// WSAECONNRESET (port unreachable) or WSAENETRESET (TTL expired).
				// Therefore, it may be ignored.
				JLOG_DEBUG("Ignoring %s returned by recvfrom",
				           sockerrno == SECONNRESET
				               ? "ECONNRESET"
				               : (sockerrno == SENETRESET ? "ENETRESET" : "ECONNREFUSED"));
				continue;
			}
			if (sockerrno == SEAGAIN || sockerrno == SEWOULDBLOCK) {
				break;
			}
			JLOG_WARN("recvfrom failed, errno=%d", sockerrno);
			return -1;
		}
		addr_unmap_inet6_v4mapped((struct sockaddr *)&record.addr, &record.len);

		uint16_t channel;
		if (turn_get_bound_channel(&alloc->map, &record, &channel)) {
			// Use ChannelData
			len = turn_wrap_channel_data(buffer, BUFFER_SIZE, buffer, len, channel);
			if (len <= 0) {
				JLOG_ERROR("TURN ChannelData wrapping failed");
				return -1;
			}

			JLOG_VERBOSE("Forwarding as ChannelData, size=%d", len);

#if defined(_WIN32) || defined(__APPLE__)
			addr_record_t tmp = alloc->record;
			addr_map_inet6_v4mapped(&tmp.addr, &tmp.len);
			int ret =
			    sendto(server->sock, buffer, len, 0, (const struct sockaddr *)&tmp.addr, tmp.len);
#else
			int ret = sendto(server->sock, buffer, (size_t)len, 0,
			                 (const struct sockaddr *)&alloc->record.addr, alloc->record.len);
#endif
			if (ret < 0 && sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK)
				JLOG_WARN("Send failed, errno=%d", sockerrno);

			return ret;

		} else {
			// Use TURN Data indication
			JLOG_VERBOSE("Forwarding as TURN Data indication");

			stun_message_t msg;
			memset(&msg, 0, sizeof(msg));
			msg.msg_class = STUN_CLASS_INDICATION;
			msg.msg_method = STUN_METHOD_DATA;
			msg.peer = record;
			msg.data = buffer;
			msg.data_size = len;
			juice_random(msg.transaction_id, STUN_TRANSACTION_ID_SIZE);

			return server_stun_send(server, &alloc->record, &msg, NULL);
		}
	}

	return 0;
}

int server_input(juice_server_t *server, char *buf, size_t len, const addr_record_t *src) {
	JLOG_VERBOSE("Received datagram, size=%d", len);

	if (is_stun_datagram(buf, len)) {
		JLOG_DEBUG("Received STUN datagram");
		stun_message_t msg;
		if (stun_read(buf, len, &msg) < 0) {
			JLOG_ERROR("STUN message reading failed");
			return -1;
		}
		return server_dispatch_stun(server, buf, len, &msg, src);
	}

	if (is_channel_data(buf, len)) {
		JLOG_DEBUG("Received ChannelData datagram");
		return server_process_channel_data(server, buf, len, src);
	}

	JLOG_WARN("Received unexpected non-STUN datagram, ignoring");
	return -1;
}

int server_interrupt(juice_server_t *server) {
	JLOG_VERBOSE("Interrupting server thread");
	mutex_lock(&server->mutex);
	if (server->sock == INVALID_SOCKET) {
		mutex_unlock(&server->mutex);
		return -1;
	}

	addr_record_t local;
	if (udp_get_local_addr(server->sock, AF_INET, &local) < 0) {
		mutex_unlock(&server->mutex);
		return -1;
	}

	if (server_send(server, &local, NULL, 0) < 0) {
		JLOG_WARN("Failed to interrupt thread by triggering socket, errno=%d", sockerrno);
		mutex_unlock(&server->mutex);
		return -1;
	}

	mutex_unlock(&server->mutex);
	return 0;
}

int server_bookkeeping(juice_server_t *server, timestamp_t *next_timestamp) {
	timestamp_t now = current_timestamp();
	*next_timestamp = now + 60000;

	for (int i = 0; i < server->allocs_count; ++i) {
		server_turn_alloc_t *alloc = server->allocs + i;
		if (alloc->state != SERVER_TURN_ALLOC_FULL)
			continue;

		if (alloc->timestamp > now) {
			if (alloc->timestamp < *next_timestamp)
				*next_timestamp = alloc->timestamp;
		} else {
			JLOG_DEBUG("Allocation timed out");
			delete_allocation(alloc);
		}
	}
	return 0;
}

void server_get_nonce(juice_server_t *server, const addr_record_t *src, char *nonce) {
	timestamp_t now = current_timestamp();
	if (now >= server->nonce_key_timestamp) {
		juice_random(server->nonce_key, SERVER_NONCE_KEY_SIZE);
		server->nonce_key_timestamp = now + SERVER_NONCE_KEY_LIFETIME;
	}

	uint8_t digest[HMAC_SHA256_SIZE];
	hmac_sha256(&src->addr, src->len, server->nonce_key, SERVER_NONCE_KEY_SIZE, digest);

	size_t len = HMAC_SHA256_SIZE;
	if (len > STUN_MAX_NONCE_LEN)
		len = STUN_MAX_NONCE_LEN;

	// RFC 4648 base64url character table
	const char *table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	for (size_t i = 0; i < len; ++i)
		nonce[i] = table[digest[i] % 64];

	nonce[len] = '\0';

	stun_prepend_nonce_cookie(nonce);
}

void server_prepare_credentials(juice_server_t *server, const addr_record_t *src,
                                const juice_server_credentials_t *credentials,
                                stun_message_t *msg) {
	snprintf(msg->credentials.realm, STUN_MAX_REALM_LEN, "%s", server->config.realm);
	server_get_nonce(server, src, msg->credentials.nonce);

	if (credentials)
		snprintf(msg->credentials.username, STUN_MAX_USERNAME_LEN, "%s", credentials->username);
}

int server_dispatch_stun(juice_server_t *server, void *buf, size_t size, stun_message_t *msg,
                         const addr_record_t *src) {

	if (!(msg->msg_class == STUN_CLASS_REQUEST ||
	      (msg->msg_class == STUN_CLASS_INDICATION &&
	       (msg->msg_method == STUN_METHOD_BINDING || msg->msg_method == STUN_METHOD_SEND)))) {
		JLOG_WARN("Unexpected STUN message, class=0x%X, method=0x%X", msg->msg_class,
		          msg->msg_method);
		return -1;
	}

	if (server->allocs_count == 0 && msg->msg_method != STUN_METHOD_BINDING) {
		// TURN support is disabled
		return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
		                                400, // Bad request
		                                NULL);
	}

	if (msg->error_code == STUN_ERROR_INTERNAL_VALIDATION_FAILED) {
		if (msg->msg_class == STUN_CLASS_REQUEST) {
			JLOG_WARN("Invalid STUN message, answering bad request error response");
			return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
			                                400, // Bad request
			                                NULL);
		} else {
			JLOG_WARN("Invalid STUN message, dropping");
			return -1;
		}
	}

	juice_server_credentials_t *credentials = NULL;
	if (msg->msg_method != STUN_METHOD_BINDING && msg->msg_class != STUN_CLASS_INDICATION) {
		if (!msg->has_integrity || //
		    *msg->credentials.realm == '\0' || *msg->credentials.nonce == '\0' ||
		    (*msg->credentials.username == '\0' && !msg->credentials.enable_userhash)) {
			JLOG_DEBUG("Answering STUN unauthorized error response");
			return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
			                                401,   // Unauthorized
			                                NULL); // No username
		}

		char nonce[STUN_MAX_NONCE_LEN];
		server_get_nonce(server, src, nonce);
		if (strcmp(msg->credentials.nonce, nonce) != 0 ||
		    strcmp(msg->credentials.realm, server->config.realm) != 0) {
			JLOG_DEBUG("Answering STUN stale nonce error response");
			return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
			                                438,   // Stale nonce
			                                NULL); // No username
		}

		if (msg->credentials.enable_userhash) {
			for (int i = 0; i < server->config.credentials_count; ++i) {
				if (const_time_memcmp(server->credentials_userhash[i], msg->credentials.userhash,
				                      HASH_SHA256_SIZE) == 0) {
					credentials = &server->config.credentials[i];
				}
			}

			if (credentials)
				snprintf(msg->credentials.username, STUN_MAX_USERNAME_LEN, "%s",
				         credentials->username);
			else
				JLOG_WARN("No credentials for userhash");

		} else {
			for (int i = 0; i < server->config.credentials_count; ++i) {
				if (const_time_strcmp(server->config.credentials[i].username,
				                      msg->credentials.username) == 0) {
					credentials = &server->config.credentials[i];
				}
			}

			if (!credentials)
				JLOG_WARN("No credentials for username \"%s\"", msg->credentials.username);
		}
		if (!credentials) {
			server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
			                         401,   // Unauthorized
			                         NULL); // No username
			return -1;
		}

		// Check credentials
		if (!stun_check_integrity(buf, size, msg, credentials->password)) {
			JLOG_WARN("STUN authentication failed for username \"%s\"", msg->credentials.username);
			server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
			                         401,   // Unauthorized
			                         NULL); // No username
			return -1;
		}
	}

	switch (msg->msg_method) {
	case STUN_METHOD_BINDING:
		return server_answer_stun_binding(server, msg->transaction_id, src);

	case STUN_METHOD_ALLOCATE:
	case STUN_METHOD_REFRESH:
		return server_process_turn_allocate(server, msg, src, credentials);

	case STUN_METHOD_CREATE_PERMISSION:
		return server_process_turn_create_permission(server, msg, src, credentials);

	case STUN_METHOD_CHANNEL_BIND:
		return server_process_turn_channel_bind(server, msg, src, credentials);

	case STUN_METHOD_SEND:
		return server_process_turn_send(server, msg, src);

	default:
		JLOG_WARN("Unknown STUN method 0x%X, ignoring", msg->msg_method);
		return -1;
	}
}

int server_answer_stun_binding(juice_server_t *server, const uint8_t *transaction_id,
                               const addr_record_t *src) {
	JLOG_DEBUG("Answering STUN Binding request");

	stun_message_t ans;
	memset(&ans, 0, sizeof(ans));
	ans.msg_class = STUN_CLASS_RESP_SUCCESS;
	ans.msg_method = STUN_METHOD_BINDING;
	ans.mapped = *src;
	memcpy(ans.transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE);

	char buffer[BUFFER_SIZE];
	int size = stun_write(buffer, BUFFER_SIZE, &ans, NULL);
	if (size <= 0) {
		JLOG_ERROR("STUN message write failed");
		return -1;
	}

	if (server_send(server, src, buffer, size) < 0) {
		JLOG_WARN("STUN message send failed, errno=%d", sockerrno);
		return -1;
	}

	return 0;
}

int server_answer_stun_error(juice_server_t *server, const uint8_t *transaction_id,
                             const addr_record_t *src, stun_method_t method, unsigned int code,
                             const juice_server_credentials_t *credentials) {
	JLOG_DEBUG("Answering STUN error response with code %u", code);

	stun_message_t ans;
	memset(&ans, 0, sizeof(ans));
	ans.msg_class = STUN_CLASS_RESP_ERROR;
	ans.msg_method = method;
	ans.error_code = code;
	memcpy(ans.transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE);

	if (method != STUN_METHOD_BINDING)
		server_prepare_credentials(server, src, credentials, &ans);

	return server_stun_send(server, src, &ans, credentials ? credentials->password : NULL);
}

int server_process_turn_allocate(juice_server_t *server, const stun_message_t *msg,
                                 const addr_record_t *src,
                                 juice_server_credentials_t *credentials) {
	if (msg->msg_class != STUN_CLASS_REQUEST)
		return -1;

	if (msg->msg_method != STUN_METHOD_ALLOCATE && msg->msg_method != STUN_METHOD_REFRESH)
		return -1;

	JLOG_DEBUG("Processing TURN Allocate request");

	server_turn_alloc_t *alloc = find_allocation(server->allocs, server->allocs_count, src, true);
	if (!alloc) {
		return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
		                                486, // Allocation quota reached
		                                credentials);
	}

	if (alloc->state == SERVER_TURN_ALLOC_FULL) {
		// Allocation exists
		if (msg->msg_method == STUN_METHOD_ALLOCATE &&
		    memcmp(alloc->transaction_id, msg->transaction_id, STUN_TRANSACTION_ID_SIZE) != 0) {
			return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
			                                437, // Allocation mismatch
			                                credentials);
		}

		if (alloc->credentials != credentials) {
			return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
			                                441, // Wrong credentials
			                                credentials);
		}
	} else {
		// Allocation does not exist
		if (msg->msg_method == STUN_METHOD_REFRESH) {
			return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
			                                437, // Allocation mismatch
			                                credentials);
		}

		if (credentials->allocations_quota <= 0) {
			return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
			                                486, // Allocation quota reached
			                                credentials);
		}

		udp_socket_config_t socket_config;
		memset(&socket_config, 0, sizeof(socket_config));
		socket_config.bind_address = server->config.bind_address;
		socket_config.port_begin = server->config.relay_port_range_begin;
		socket_config.port_end = server->config.relay_port_range_end;
		alloc->sock = udp_create_socket(&socket_config);
		if (alloc->sock == INVALID_SOCKET) {
			server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method, 500,
			                         credentials);
			return -1;
		}
		if (turn_init_map(&alloc->map, server->config.max_peers) < 0) {
			closesocket(alloc->sock);
			alloc->sock = INVALID_SOCKET;
			server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method, 500,
			                         credentials);
			return -1;
		}

		alloc->state = SERVER_TURN_ALLOC_FULL;
		alloc->record = *src;
		alloc->credentials = credentials;

		--credentials->allocations_quota;
	}

	uint32_t lifetime = ALLOCATION_LIFETIME / 1000;
	if (msg->lifetime_set && msg->lifetime < lifetime)
		lifetime = msg->lifetime;

	alloc->timestamp = current_timestamp() + lifetime * 1000;
	memcpy(alloc->transaction_id, msg->transaction_id, STUN_TRANSACTION_ID_SIZE);

	addr_record_t records[MAX_RELAYED_RECORDS_COUNT];
	const addr_record_t *relayed = NULL;
	if (lifetime == 0) {
		delete_allocation(alloc);

	} else {
		int count = 0;
		if (server->config.external_address) {
			char service[8];
			snprintf(service, 8, "%hu", udp_get_port(alloc->sock));
			count = addr_resolve(server->config.external_address, service, records,
			                     MAX_RELAYED_RECORDS_COUNT);
			if (count <= 0) {
				JLOG_ERROR("Specified external address is invalid");
				goto error;
			}
		} else {
			count = udp_get_addrs(alloc->sock, records, MAX_RELAYED_RECORDS_COUNT);
			if (count <= 0) {
				JLOG_ERROR("No local address found");
				goto error;
			}
		}

		if (count > MAX_RELAYED_RECORDS_COUNT)
			count = MAX_RELAYED_RECORDS_COUNT;

		for (int i = 0; i < count; ++i) {
			const addr_record_t *record = records + i;
			if (record->addr.ss_family == AF_INET || !relayed) {
				relayed = record;
				if (record->addr.ss_family == AF_INET)
					break;
			}
		}

		if (!relayed) {
			JLOG_ERROR("No advertisable relayed address found");
			goto error;
		}
	}

	stun_message_t ans;
	memset(&ans, 0, sizeof(ans));
	ans.msg_class = STUN_CLASS_RESP_SUCCESS;
	ans.msg_method = msg->msg_method;
	ans.lifetime = lifetime;
	ans.lifetime_set = true;
	ans.mapped = *src;
	if (relayed)
		ans.relayed = *relayed;
	memcpy(ans.transaction_id, msg->transaction_id, STUN_TRANSACTION_ID_SIZE);

	server_prepare_credentials(server, src, credentials, &ans);

	return server_stun_send(server, src, &ans, credentials->password);

error:
	delete_allocation(alloc);
	server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method, 500, credentials);
	return -1;
}

int server_process_turn_create_permission(juice_server_t *server, const stun_message_t *msg,
                                          const addr_record_t *src,
                                          const juice_server_credentials_t *credentials) {
	if (msg->msg_class != STUN_CLASS_REQUEST)
		return -1;

	JLOG_DEBUG("Processing STUN CreatePermission request");

	if (!msg->peer.len) {
		JLOG_WARN("Missing peer address in TURN CreatePermission request");
		return -1;
	}

	server_turn_alloc_t *alloc = find_allocation(server->allocs, server->allocs_count, src, false);
	if (!alloc || alloc->state != SERVER_TURN_ALLOC_FULL) {
		return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
		                                437, // Allocation mismatch
		                                credentials);
	}
	if (alloc->credentials != credentials) {
		return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
		                                441, // Wrong credentials
		                                credentials);
	}

	if (!turn_set_permission(&alloc->map, msg->transaction_id, &msg->peer, PERMISSION_LIFETIME)) {
		server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method, 500,
		                         credentials);
		return -1;
	}

	stun_message_t ans;
	memset(&ans, 0, sizeof(ans));
	ans.msg_class = STUN_CLASS_RESP_SUCCESS;
	ans.msg_method = STUN_METHOD_CREATE_PERMISSION;
	memcpy(ans.transaction_id, msg->transaction_id, STUN_TRANSACTION_ID_SIZE);

	server_prepare_credentials(server, src, credentials, &ans);

	return server_stun_send(server, src, &ans, credentials->password);
}

int server_process_turn_channel_bind(juice_server_t *server, const stun_message_t *msg,
                                     const addr_record_t *src,
                                     const juice_server_credentials_t *credentials) {
	if (msg->msg_class != STUN_CLASS_REQUEST)
		return -1;

	JLOG_DEBUG("Processing STUN ChannelBind request");

	if (!msg->peer.len) {
		JLOG_WARN("Missing peer address in TURN ChannelBind request");
		return -1;
	}
	if (!msg->channel_number) {
		JLOG_WARN("Missing channel number in TURN ChannelBind request");
		return -1;
	}

	server_turn_alloc_t *alloc = find_allocation(server->allocs, server->allocs_count, src, false);
	if (!alloc || alloc->state != SERVER_TURN_ALLOC_FULL) {
		return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
		                                437, // Allocation mismatch
		                                credentials);
	}
	if (alloc->credentials != credentials) {
		return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
		                                441, // Wrong credentials
		                                credentials);
	}

	uint16_t channel = msg->channel_number;
	if (!is_valid_channel(channel)) {
		JLOG_WARN("TURN channel 0x%hX is invalid", channel);
		return server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method,
		                                400, // Bad request
		                                credentials);
	}

	if (!turn_bind_channel(&alloc->map, &msg->peer, msg->transaction_id, channel, BIND_LIFETIME)) {
		server_answer_stun_error(server, msg->transaction_id, src, msg->msg_method, 500,
		                         credentials);
		return -1;
	}

	stun_message_t ans;
	memset(&ans, 0, sizeof(ans));
	ans.msg_class = STUN_CLASS_RESP_SUCCESS;
	ans.msg_method = STUN_METHOD_CHANNEL_BIND;
	memcpy(ans.transaction_id, msg->transaction_id, STUN_TRANSACTION_ID_SIZE);

	server_prepare_credentials(server, src, credentials, &ans);

	return server_stun_send(server, src, &ans, credentials->password);
}

int server_process_turn_send(juice_server_t *server, const stun_message_t *msg,
                             const addr_record_t *src) {
	if (msg->msg_class != STUN_CLASS_INDICATION)
		return -1;

	JLOG_DEBUG("Processing STUN Send indication");

	if (!msg->data) {
		JLOG_WARN("Missing data in TURN Send indication");
		return -1;
	}
	if (!msg->peer.len) {
		JLOG_WARN("Missing peer address in TURN Send indication");
		return -1;
	}

	server_turn_alloc_t *alloc = find_allocation(server->allocs, server->allocs_count, src, false);
	if (!alloc || alloc->state != SERVER_TURN_ALLOC_FULL) {
		JLOG_WARN("Allocation mismatch for TURN Send indication");
		return -1;
	}

	if (!turn_has_permission(&alloc->map, &msg->peer)) {
		JLOG_WARN("No permission for peer address");
		return -1;
	}

	JLOG_VERBOSE("Forwarding datagram to peer, size=%zu", msg->data_size);

#if defined(_WIN32) || defined(__APPLE__)
	addr_record_t tmp = msg->peer;
	addr_map_inet6_v4mapped(&tmp.addr, &tmp.len);
	int ret = sendto(alloc->sock, msg->data, (int)msg->data_size, 0,
	                 (const struct sockaddr *)&tmp.addr, tmp.len);
#else
	int ret = sendto(alloc->sock, msg->data, msg->data_size, 0,
	                 (const struct sockaddr *)&msg->peer.addr, msg->peer.len);
#endif
	if (ret < 0 && sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK)
		JLOG_WARN("Forwarding failed, errno=%d", sockerrno);

	return ret;
}

int server_process_channel_data(juice_server_t *server, char *buf, size_t len,
                                const addr_record_t *src) {
	server_turn_alloc_t *alloc = find_allocation(server->allocs, server->allocs_count, src, false);
	if (!alloc || alloc->state != SERVER_TURN_ALLOC_FULL) {
		JLOG_WARN("Allocation mismatch for TURN Channel Data");
		return -1;
	}

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
	len = length;

	addr_record_t record;
	if (!turn_find_bound_channel(&alloc->map, channel, &record)) {
		JLOG_WARN("Channel 0x%hX is not bound", channel);
		return -1;
	}

	JLOG_VERBOSE("Forwarding datagram to peer, size=%zu", len);

#if defined(_WIN32) || defined(__APPLE__)
	addr_map_inet6_v4mapped(&record.addr, &record.len);
	int ret =
	    sendto(alloc->sock, buf, (int)len, 0, (const struct sockaddr *)&record.addr, record.len);
#else
	int ret = sendto(alloc->sock, buf, len, 0, (const struct sockaddr *)&record.addr, record.len);
#endif
	if (ret < 0 && sockerrno != SEAGAIN && sockerrno != SEWOULDBLOCK)
		JLOG_WARN("Send failed, errno=%d", sockerrno);

	return 0;
}

#endif // ifndef NO_SERVER
