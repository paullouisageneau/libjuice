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

#include "hmac.h"

#if USE_NETTLE
#include <nettle/hmac.h>
#else
#include "picohash.h"
#endif

void hmac_sha1(const void *message, size_t size, const void *key, size_t key_size, void *digest) {
#if USE_NETTLE
	struct hmac_sha1_ctx ctx;
	hmac_sha1_set_key(&ctx, key_size, key);
	hmac_sha1_update(&ctx, size, message);
	hmac_sha1_digest(&ctx, HMAC_SHA1_SIZE, digest);
#else
	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_sha1, key, key_size);
	picohash_update(&ctx, message, size);
	picohash_final(&ctx, digest);
#endif
}

void hmac_sha256(const void *message, size_t size, const void *key, size_t key_size, void *digest) {
#if USE_NETTLE
	struct hmac_sha256_ctx ctx;
	hmac_sha256_set_key(&ctx, key_size, key);
	hmac_sha256_update(&ctx, size, message);
	hmac_sha256_digest(&ctx, HMAC_SHA256_SIZE, digest);
#else
	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_sha256, key, key_size);
	picohash_update(&ctx, message, size);
	picohash_final(&ctx, digest);
#endif
}
