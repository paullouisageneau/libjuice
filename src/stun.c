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

#include "stun.h"
#include "crc32.h"
#include "juice.h"
#include "log.h"
#include "udp.h"

#include <assert.h>
#include <stdlib.h>

#define STUN_MAGIC 0x2112A442
#define STUN_FINGERPRINT_XOR 0x5354554E // "STUN"

int stun_write(void *buf, size_t size, const stun_message_t *msg) {
	uint8_t *begin = buf;
	uint8_t *pos = begin;
	uint8_t *end = begin + size;

	size_t length = sizeof(struct stun_attr) + 4;

	size_t len =
	    stun_write_header(pos, end - pos, msg->msg_class, msg->msg_method,
	                      length, msg->transaction_id);
	if (len <= 0)
		goto no_space;
	pos += len;

	// TODO
	// short term credentials
	// PRIORITY, USE-CANDIDATE, ICE-CONTROLLED, and ICE-CONTROLLING

	// WARNING: length !

	uint32_t fingerprint = crc32(buf, pos - begin) ^ STUN_FINGERPRINT_XOR;
	len =
	    stun_write_attr(pos, end - pos, STUN_ATTR_FINGERPRINT, &fingerprint, 4);
	if (len <= 0)
		goto no_space;
	pos += len;

	return pos - begin;

no_space:
	JLOG_ERROR("Not enough space in buffer for STUN message, size=%zu", size);
	return -1;
}

int stun_write_header(void *buf, size_t size, stun_class_t class,
                      stun_method_t method, size_t length,
                      const uint8_t *transaction_id) {
	if(size < sizeof(struct stun_header))
		return -1;

	uint16_t type = (uint16_t) class | (uint16_t)method;

	struct stun_header *header = buf;
	header->type = htons(type);
	header->length = htons(length);
	header->magic = htonl(STUN_MAGIC);
	memcpy(header->transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE);

	return sizeof(struct stun_header);
}

int stun_write_attr(void *buf, size_t size, uint16_t type, const void *value,
                    size_t len) {
	if (size < sizeof(struct stun_attr) + len)
		return -1;

	struct stun_attr *attr = buf;
	attr->type = htons(type);
	attr->length = htons((uint16_t)len);
	memcpy(attr->value, value, len);

	return sizeof(struct stun_attr) + len;
}

int stun_read(const void *data, size_t size, stun_message_t *msg) {
	memset(msg, 0, sizeof(*msg));

	if (size < sizeof(struct stun_header)) {
		JLOG_VERBOSE("STUN message too short, size=%zu", size);
		return -1;
	}

	const struct stun_header *header = data;
	if (ntohl(header->magic) != STUN_MAGIC) {
		JLOG_VERBOSE("STUN magic number invalid");
		return -1;
	}

	size_t length = ntohs(header->length);
	if (size < sizeof(struct stun_header) + length) {
		JLOG_VERBOSE("STUN message length invalid, length=%zu", length);
		return -1;
	}

	uint16_t type = ntohs(header->type);
	msg->msg_class = (stun_class_t)(type & STUN_CLASS_MASK);
	msg->msg_method = (stun_method_t)(type & ~STUN_CLASS_MASK);
	memcpy(msg->transaction_id, header->transaction_id,
	       STUN_TRANSACTION_ID_SIZE);

	JLOG_VERBOSE("Reading STUN message, class=%X, method=%X",
	             (unsigned int)msg->msg_class, (unsigned int)msg->msg_method);

	const uint8_t *ptr = data;
	const uint8_t *begin = ptr + sizeof(struct stun_header);
	const uint8_t *end = begin + length;
	while (begin != end) {
		size_t left = end - begin;
		int ret = stun_read_attr(begin, left, msg);
		if (ret <= 0) {
			JLOG_DEBUG("Reading STUN attribute failed");
			return -1;
		}
		begin += ret;
	}

	JLOG_VERBOSE("Finished reading STUN attributes");
	return 0;
}

int stun_read_attr(const void *data, size_t size, stun_message_t *msg) {
	if (size < sizeof(struct stun_attr)) {
		JLOG_VERBOSE("STUN attribute too short");
		return -1;
	}

	const struct stun_attr *attr = data;
	stun_attr_type_t type = (stun_attr_type_t)ntohs(attr->type);
	size_t length = ntohs(attr->length);
	JLOG_VERBOSE("Reading attribute, type=%X, length=%zu", (unsigned int)type,
	             length);
	switch (type) {
	case STUN_ATTR_MAPPED_ADDRESS: {
		JLOG_VERBOSE("Reading mapped address");
		uint8_t zero_mask[16] = {0};
		if (stun_read_value_mapped_address(attr->value, length, msg,
		                                   zero_mask) < 0)
			return -1;
		break;
	}
	case STUN_ATTR_XOR_MAPPED_ADDRESS: {
		JLOG_VERBOSE("Reading XOR mapped address", length);
		uint8_t mask[16];
		*((uint32_t *)mask) = htonl(STUN_MAGIC);
		memcpy(mask + 4, msg->transaction_id, 12);
		if (stun_read_value_mapped_address(attr->value, length, msg, mask) < 0)
			return -1;
		break;
	}
	default: {
		// Ignore
		JLOG_DEBUG("Ignoring attribute type %X", (unsigned int)type);
		break;
	}
	}
	return sizeof(struct stun_attr) + length;
}

int stun_read_value_mapped_address(const void *data, size_t size,
                                   stun_message_t *msg, const uint8_t *mask) {
	size_t len = sizeof(struct stun_value_mapped_address);
	if (size < len) {
		JLOG_VERBOSE("STUN mapped address value too short, size=%zu", size);
		return -1;
	}

	const struct stun_value_mapped_address *value = data;
	stun_address_family_t family = (stun_address_family_t)value->family;
	switch (family) {
	case STUN_ADDRESS_FAMILY_IPV4: {
		len += 4;
		if (size < len) {
			JLOG_DEBUG("IPv4 mapped address value too short, size=%zu", size);
			return -1;
	    }
	    JLOG_VERBOSE("Reading IPv4 address");
		msg->mapped_addrlen = sizeof(struct sockaddr_in);
		struct sockaddr_in *sin = (struct sockaddr_in *)&msg->mapped_addr;
		sin->sin_family = AF_INET;
		sin->sin_port = value->port ^ *((uint16_t *)mask);
		sin->sin_addr.s_addr =
		    *((uint32_t *)value->address) ^ *((uint32_t *)mask);
		break;
	}
	case STUN_ADDRESS_FAMILY_IPV6: {
		len += 16;
		if (size < len) {
			JLOG_DEBUG("IPv6 mapped address value too short, size=%zu", size);
			return -1;
		}
		JLOG_VERBOSE("Reading IPv6 address");
		msg->mapped_addrlen = sizeof(struct sockaddr_in6);
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg->mapped_addr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = value->port ^ *((uint16_t *)mask);
		for (int i = 0; i < 16; ++i)
			sin6->sin6_addr.s6_addr[i] = value->address[i] ^ mask[i];
		break;
	}
	default: {
		JLOG_DEBUG("Unknown address family %X", (unsigned int)family);
		len = size;
		break;
	}
	}
	return len;
}

