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
#include "juice.h"
#include "log.h"
#include "udp.h"

#include <assert.h>
#include <stdlib.h>

#define STUN_MAGIC 0x2112A442

int stun_write(void *buf, size_t size, const stun_message_t *msg) {
	return stun_write_header(buf, size, msg->msg_class, msg->msg_method,
	                         msg->transaction_id);
}

int stun_write_header(void *buf, size_t size, stun_class_t class,
                      stun_method_t method, const uint8_t *transaction_id) {
	if(size < sizeof(struct stun_header))
		return -1;

	assert(method < 0x0010); // else it would require proper type encoding
	uint16_t type = (uint16_t)class + (uint16_t)method;
	size_t len = size - sizeof(struct stun_header);

	struct stun_header *header = buf;
	header->type = htons(type);
	header->length = htons((uint16_t)len);
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
	if (size < sizeof(struct stun_header))
		return -1;
	const struct stun_header *header = data;
	if (header->magic != htonl(STUN_MAGIC))
		return -1;
	if (size < sizeof(struct stun_header) + header->length)
		return -1;

	memset(msg, 0, sizeof(stun_message_t));
	msg->msg_class = (stun_class_t)(header->type & STUN_CLASS_MASK);
	msg->msg_method = (stun_method_t)(header->type & ~STUN_CLASS_MASK);
	memcpy(msg->transaction_id, header->transaction_id,
	       STUN_TRANSACTION_ID_SIZE);

	const uint8_t *ptr = data;
	const uint8_t *begin = ptr + sizeof(struct stun_header);
	const uint8_t *end = begin + header->length;
	while (begin != end) {
		size_t left = end - begin;
		int ret = stun_read_attr(begin, left, msg);
		if (ret <= 0)
			return -1;
		begin += ret;
	}

	return 0;
}

int stun_read_attr(const void *data, size_t size, stun_message_t *msg) {
	if (size < sizeof(struct stun_attr))
		return -1;

	const struct stun_attr *attr = data;
	switch (attr->type) {
	case STUN_ATTR_MAPPED_ADDRESS: {
		uint8_t zero_mask[16] = {0};
		if (stun_read_value_mapped_address(attr->value, attr->length, msg,
		                                   zero_mask) < 0)
			return -1;
	}
	case STUN_ATTR_XOR_MAPPED_ADDRESS: {
		uint8_t mask[16];
		*((uint32_t *)mask) = htonl(STUN_MAGIC);
		memcpy(mask + 4, msg->transaction_id, 12);
		if (stun_read_value_mapped_address(attr->value, attr->length, msg,
		                                   mask) < 0)
			return -1;
	}
	default:
		// Ignore
		break;
	}
	return sizeof(struct stun_attr) + attr->length;
}

int stun_read_value_mapped_address(const void *data, size_t size,
                                   stun_message_t *msg, const uint8_t *mask) {
	if (size < sizeof(struct stun_value_mapped_address))
		return -1;

	const struct stun_value_mapped_address *value = data;
	stun_address_family_t family = (stun_address_family_t)value->family;
	switch (family) {
	case STUN_ADDRESS_FAMILY_IPV4: {
		msg->mapped_addrlen = sizeof(struct sockaddr_in);
		struct sockaddr_in *sin = (struct sockaddr_in *)&msg->mapped_addr;
		sin->sin_port = value->port ^ *((uint16_t *)mask);
		sin->sin_addr.s_addr =
		    *((uint32_t *)value->address) ^ *((uint32_t *)mask);
		return sizeof(struct stun_value_mapped_address) + 4;
	}
	case STUN_ADDRESS_FAMILY_IPV6: {
		msg->mapped_addrlen = sizeof(struct sockaddr_in6);
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg->mapped_addr;
		sin6->sin6_port = value->port ^ *((uint16_t *)mask);
		for (int i = 0; i < 16; ++i)
			sin6->sin6_addr.s6_addr[i] = value->address[i] ^ mask[i];
		return sizeof(struct stun_value_mapped_address) + 16;
	}
	default:
		return 0;
	}
}

