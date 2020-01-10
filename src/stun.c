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
#include "hmac.h"
#include "juice.h"
#include "log.h"
#include "udp.h"

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#define STUN_MAGIC 0x2112A442
#define STUN_FINGERPRINT_XOR 0x5354554E // "STUN"
#define STUN_ATTR_SIZE sizeof(struct stun_attr)

#define htonll(x)                                                              \
	((uint64_t)htonl(((uint64_t)(x)&0xFFFFFFFF) << 32) |                       \
	 (uint64_t)htonl((uint64_t)(x) >> 32))

// RAND_MAX is guaranteed to be at least 2^15 - 1
#define rand64()                                                               \
	(((uint64_t)(rand() & 0x7800) << 49) |                                     \
	 ((uint64_t)(rand() & 0x7FFF) << 45) |                                     \
	 ((uint64_t)(rand() & 0x7FFF) << 30) |                                     \
	 ((uint64_t)(rand() & 0x7FFF) << 15) | (uint64_t)(rand() & 0x7FFF))

int stun_write(void *buf, size_t size, const stun_message_t *msg) {
	uint8_t *begin = buf;
	uint8_t *pos = begin;
	uint8_t *end = begin + size;

	JLOG_VERBOSE("Writing STUN message, class=%X, method=%X",
	             (unsigned int)msg->msg_class, (unsigned int)msg->msg_method);

	size_t len = stun_write_header(pos, end - pos, msg->msg_class,
	                               msg->msg_method, msg->transaction_id);
	if (len <= 0)
		goto no_space;
	pos += len;
	uint8_t *attr_begin = pos;

	if (msg->error_code) {
		struct stun_value_error_code error;
		memset(&error, 0, sizeof(error));
		error.code_class = (msg->error_code / 100) & 0x08;
		error.code_number = msg->error_code % 100;
		len = stun_write_attr(pos, end - pos, STUN_ATTR_ERROR_CODE, &error,
		                      sizeof(error));
		if (len <= 0)
			goto no_space;
		pos += len;
	}

	if (msg->mapped.len) {
		JLOG_VERBOSE("Writing XOR mapped address");
		uint8_t value[32];
		uint8_t mask[16];
		*((uint32_t *)mask) = htonl(STUN_MAGIC);
		memcpy(mask + 4, msg->transaction_id, 12);
		int value_len = stun_write_value_mapped_address(
		    value, 32, (const struct sockaddr *)&msg->mapped.addr,
		    msg->mapped.len, mask);
		if (value_len > 0) {
			len = stun_write_attr(pos, end - pos, STUN_ATTR_XOR_MAPPED_ADDRESS,
			                      value, value_len);
			if (len <= 0)
				goto no_space;
			pos += len;
		}
	}

	if (msg->priority) {
		uint32_t priority = htonl(msg->priority);
		len = stun_write_attr(pos, end - pos, STUN_ATTR_PRIORITY, &priority, 4);
		if (len <= 0)
			goto no_space;
		pos += len;
	}

	if (msg->use_candidate) {
		len = stun_write_attr(pos, end - pos, STUN_ATTR_USE_CANDIDATE, NULL, 0);
		if (len <= 0)
			goto no_space;
		pos += len;
	}

	if (msg->ice_controlling) {
		uint64_t random = htonll(rand64());
		len = stun_write_attr(pos, end - pos, STUN_ATTR_ICE_CONTROLLING,
		                      &random, 8);
		if (len <= 0)
			goto no_space;
		pos += len;
	}

	if (msg->ice_controlled) {
		uint64_t random = htonll(rand64());
		len = stun_write_attr(pos, end - pos, STUN_ATTR_ICE_CONTROLLED, &random,
		                      8);
		if (len <= 0)
			goto no_space;
		pos += len;
	}

	if (msg->username) {
		const char *username = msg->username;
		len = stun_write_attr(pos, end - pos, STUN_ATTR_USERNAME, username,
		                      strlen(username));
		if (len <= 0)
			goto no_space;
		pos += len;
	}

	if (msg->password) {
		size_t tmp_length = pos - attr_begin + STUN_ATTR_SIZE + HMAC_SHA1_SIZE;
		stun_update_header_length(begin, tmp_length);

		const char *password = msg->password;
		uint8_t hmac[HMAC_SHA1_SIZE];
		hmac_sha1(begin, pos - begin, password, strlen(password), hmac);
		len = stun_write_attr(pos, end - pos, STUN_ATTR_MESSAGE_INTEGRITY, hmac,
		                      HMAC_SHA1_SIZE);
		if (len <= 0)
			goto no_space;
		pos += len;
	}

	size_t length = pos - attr_begin + STUN_ATTR_SIZE + 4;
	stun_update_header_length(begin, length);

	uint32_t fingerprint =
	    htonl(crc32(buf, pos - begin) ^ STUN_FINGERPRINT_XOR);
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
                      stun_method_t method, const uint8_t *transaction_id) {
	if(size < sizeof(struct stun_header))
		return -1;

	uint16_t type = (uint16_t) class | (uint16_t)method;

	struct stun_header *header = buf;
	header->type = htons(type);
	header->length = htons(0);
	header->magic = htonl(STUN_MAGIC);
	memcpy(header->transaction_id, transaction_id, STUN_TRANSACTION_ID_SIZE);

	return sizeof(struct stun_header);
}

size_t stun_update_header_length(void *buf, size_t length) {
	struct stun_header *header = buf;
	size_t previous = ntohs(header->length);
	header->length = htons(length);
	return previous;
}

int stun_write_attr(void *buf, size_t size, uint16_t type, const void *value,
                    size_t length) {
	JLOG_DEBUG("Writing STUN attribute type %X, length=%zu", (unsigned int)type,
	           length);

	if (size < sizeof(struct stun_attr) + length)
		return -1;

	struct stun_attr *attr = buf;
	attr->type = htons(type);
	attr->length = htons((uint16_t)length);
	memcpy(attr->value, value, length);

	return sizeof(struct stun_attr) + length;
}

int stun_write_value_mapped_address(void *buf, size_t size,
                                    const struct sockaddr *addr,
                                    socklen_t addrlen, const uint8_t *mask) {
	if (size < sizeof(struct stun_value_mapped_address))
		return -1;

	struct stun_value_mapped_address *value = buf;
	switch (addr->sa_family) {
	case AF_INET: {
		value->family = STUN_ADDRESS_FAMILY_IPV4;
		if (size < sizeof(struct stun_value_mapped_address) + 4)
			return -1;
		JLOG_VERBOSE("Writing IPv4 address");
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		value->port = sin->sin_port ^ *((uint16_t *)mask);
		*((uint32_t *)value->address) =
		    sin->sin_addr.s_addr ^ *((uint32_t *)mask);
		return sizeof(struct stun_value_mapped_address) + 4;
	}
	case AF_INET6: {
		value->family = STUN_ADDRESS_FAMILY_IPV6;
		if (size < sizeof(struct stun_value_mapped_address) + 16)
			return -1;
		JLOG_VERBOSE("Writing IPv6 address");
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		value->port = sin6->sin6_port ^ *((uint16_t *)mask);
		for (int i = 0; i < 16; ++i)
			value->address[i] = sin6->sin6_addr.s6_addr[i] ^ mask[i];
		return sizeof(struct stun_value_mapped_address) + 16;
	}
	default: {
		JLOG_DEBUG("Unknown address family %u", (unsigned int)addr->sa_family);
		return -1;
	}
	}
}

int stun_read(void *data, size_t size, stun_message_t *msg) {
	memset(msg, 0, sizeof(*msg));

	// RFC 5245: The most significant 2 bits of every STUN message MUST be
	// zeroes.
	if (!size || *((uint8_t *)data) & 0xC0) {
		JLOG_VERBOSE("Not a STUN message: first 2 bits are not zeroes");
		return 0;
	}

	if (size < sizeof(struct stun_header)) {
		JLOG_VERBOSE("Not a STUN message: message too short, size=%zu", size);
		return 0;
	}

	const struct stun_header *header = data;
	if (ntohl(header->magic) != STUN_MAGIC) {
		JLOG_VERBOSE("Not a STUN message: magic number invalid");
		return 0;
	}

	// RFC 5245: The message length MUST contain the size, in bytes, of the
	// message not including the 20-byte STUN header. Since all STUN attributes
	// are padded to a multiple of 4 bytes, the last 2 bits of this field are
	// always zero.
	size_t length = ntohs(header->length);
	if (length & 0x03) {
		JLOG_VERBOSE(
		    "Not a STUN message: invalid length %zu not multiple of 4");
		return 0;
	}
	if (size != sizeof(struct stun_header) + length) {
		JLOG_VERBOSE(
		    "Not a STUN message: invalid length %zu while expecting %zu",
		    length, size - sizeof(struct stun_header));
		return 0;
	}

	uint16_t type = ntohs(header->type);
	msg->msg_class = (stun_class_t)(type & STUN_CLASS_MASK);
	msg->msg_method = (stun_method_t)(type & ~STUN_CLASS_MASK);
	memcpy(msg->transaction_id, header->transaction_id,
	       STUN_TRANSACTION_ID_SIZE);

	JLOG_VERBOSE("Reading STUN message, class=%X, method=%X",
	             (unsigned int)msg->msg_class, (unsigned int)msg->msg_method);

	uint8_t *begin = data;
	uint8_t *attr_begin = begin + sizeof(struct stun_header);
	uint8_t *end = attr_begin + length;
	const uint8_t *pos = attr_begin;
	while (pos != end) {
		int ret = stun_read_attr(pos, end - pos, msg, begin, attr_begin);
		if (ret <= 0) {
			JLOG_DEBUG("Reading STUN attribute failed");
			return -1;
		}
		pos += ret;
	}

	JLOG_VERBOSE("Finished reading STUN attributes");
	return sizeof(struct stun_header) + length;
}

int stun_read_attr(const void *data, size_t size, stun_message_t *msg,
                   uint8_t *begin, uint8_t *attr_begin) {
	// RFC5389: When present, the FINGERPRINT attribute MUST be the last
	// attribute in the message
	if (msg->has_fingerprint) {
		JLOG_DEBUG("Invalid STUN attribute after fingerprint");
		return -1;
	}

	if (size < sizeof(struct stun_attr)) {
		JLOG_VERBOSE("STUN attribute too short");
		return -1;
	}

	const struct stun_attr *attr = data;
	stun_attr_type_t type = (stun_attr_type_t)ntohs(attr->type);
	size_t length = ntohs(attr->length);
	JLOG_VERBOSE("Reading attribute %X, length=%zu", (unsigned int)type,
	             length);
	if (size < sizeof(struct stun_attr) + length) {
		JLOG_DEBUG("STUN attribute length invalid, length=%zu, available=%zu",
		           length, size - sizeof(struct stun_attr));
		return -1;
	}

	// RFC5359: With the exception of the FINGERPRINT attribute, which appears
	// after MESSAGE-INTEGRITY, agents MUST ignore all other attributes that
	// follow MESSAGE-INTEGRITY.
	if (msg->has_integrity && type != STUN_ATTR_FINGERPRINT) {
		JLOG_DEBUG("Ignoring STUN attribute %X after message integrity",
		           (unsigned int)type);
		return sizeof(struct stun_attr) + length;
	}

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
		JLOG_VERBOSE("Reading XOR mapped address");
		uint8_t mask[16];
		*((uint32_t *)mask) = htonl(STUN_MAGIC);
		memcpy(mask + 4, msg->transaction_id, 12);
		if (stun_read_value_mapped_address(attr->value, length, msg, mask) < 0)
			return -1;
		break;
	}
	case STUN_ATTR_ERROR_CODE: {
		JLOG_VERBOSE("Reading error code");
		if (length < sizeof(struct stun_value_error_code)) {
			JLOG_DEBUG("STUN error code value too short, length=%zu", length);
			return -1;
		}
		const struct stun_value_error_code *error =
		    (const struct stun_value_error_code *)attr->value;
		msg->error_code = (error->code_class & 0x08) * 100 + error->code_number;
		JLOG_DEBUG("Got STUN error code %u", msg->error_code);
		break;
	}
	case STUN_ATTR_USERNAME: {
		JLOG_VERBOSE("Reading username");
		const char *username = msg->username ? msg->username : "";
		if (strncmp(username, (const char *)attr->value, attr->length) != 0) {
			JLOG_DEBUG("STUN username check failed");
			return -1;
		}
		break;
	}
	case STUN_ATTR_MESSAGE_INTEGRITY: {
		JLOG_VERBOSE("Reading message integrity");
		if (attr->length != HMAC_SHA1_SIZE) {
			JLOG_DEBUG("STUN message integrity length invalid, length=%zu",
			           length);
			return -1;
		}
		size_t tmp_length =
		    (uint8_t *)data - attr_begin + STUN_ATTR_SIZE + HMAC_SHA1_SIZE;
		size_t prev_length = stun_update_header_length(begin, tmp_length);

		const char *password = msg->password ? msg->password : "";
		uint8_t hmac[HMAC_SHA1_SIZE];
		hmac_sha1(begin, (uint8_t *)data - begin, password, strlen(password),
		          hmac);

		stun_update_header_length(begin, prev_length);

		if (memcmp(hmac, attr->value, HMAC_SHA1_SIZE) != 0) {
			JLOG_DEBUG("STUN message integrity check failed");
			return -1;
		}
		msg->has_integrity = true;
		break;
	}
	case STUN_ATTR_FINGERPRINT: {
		JLOG_VERBOSE("Reading fingerprint");
		// No need to update header length since fingerprint must be the last
		// attribute anyway
		if (attr->length != 4) {
			JLOG_DEBUG("STUN fingerprint length invalid, length=%zu", length);
			return -1;
		}
		uint32_t fingerprint = ntohl(*((uint32_t *)attr->value));
		uint32_t expected =
		    crc32(begin, (uint8_t *)data - begin) ^ STUN_FINGERPRINT_XOR;
		if (fingerprint != expected) {
			JLOG_DEBUG("STUN fingerprint check failed, expected=%lX, found=%lX",
			           (unsigned long)expected, (unsigned long)fingerprint);
			return -1;
		}
		msg->has_fingerprint = true;
		break;
	}
	case STUN_ATTR_PRIORITY: {
		JLOG_VERBOSE("Reading priority");
		if (length != 4) {
			JLOG_DEBUG("STUN priority length invalid, length=%zu", length);
			return -1;
		}
		msg->priority = ntohl(*((uint32_t *)attr->value));
		break;
	}
	case STUN_ATTR_USE_CANDIDATE: {
		JLOG_VERBOSE("Found use candidate flag");
		msg->use_candidate = true;
		break;
	}
	case STUN_ATTR_ICE_CONTROLLING: {
		JLOG_VERBOSE("Found ICE controlling flag");
		msg->ice_controlling = true;
		break;
	}
	case STUN_ATTR_ICE_CONTROLLED: {
		JLOG_VERBOSE("Found ICE controlled flag");
		msg->ice_controlled = true;
		break;
	}
	default: {
		// Ignore
		JLOG_DEBUG("Ignoring unknown STUN attribute type %X",
		           (unsigned int)type);
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
		msg->mapped.len = sizeof(struct sockaddr_in);
		struct sockaddr_in *sin = (struct sockaddr_in *)&msg->mapped.addr;
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
		msg->mapped.len = sizeof(struct sockaddr_in6);
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&msg->mapped.addr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = value->port ^ *((uint16_t *)mask);
		for (int i = 0; i < 16; ++i)
			sin6->sin6_addr.s6_addr[i] = value->address[i] ^ mask[i];
		break;
	}
	default: {
		JLOG_DEBUG("Unknown STUN address family %X", (unsigned int)family);
		len = size;
		break;
	}
	}
	return len;
}

