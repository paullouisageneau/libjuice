/**
 * Copyright (c) 2026 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "picohash.h"

#include <stdio.h>
#include <string.h>

struct hash_vector {
    const char *name;
    void (*init)(picohash_ctx_t *);
    const char *expected;
};

static int digest_matches(const unsigned char *digest, size_t size, const char *expected) {
    static const char hex[] = "0123456789abcdef";
    if (strlen(expected) != size * 2)
        return 0;
    for (size_t i = 0; i < size; ++i) {
        if (hex[digest[i] >> 4] != expected[2 * i] ||
            hex[digest[i] & 0x0f] != expected[2 * i + 1])
            return 0;
    }
    return 1;
}

static int check_vector(const struct hash_vector *vector, int hmac) {
    static const char input[] = "abc";
    static const char hmac_input[] = "The quick brown fox jumps over the lazy dog";
    static const char key[] = "key";
    const char *message = hmac ? hmac_input : input;
    size_t length = strlen(message);
    picohash_ctx_t ctx;
    unsigned char digest[PICOHASH_MAX_DIGEST_LENGTH];

    if (hmac)
        picohash_init_hmac(&ctx, vector->init, key, strlen(key));
    else
        vector->init(&ctx);

    for (int i = 0; i < 2; ++i) {
        if (i != 0)
            picohash_reset(&ctx);
        picohash_update(&ctx, message, length);
        picohash_final(&ctx, digest);
        if (!digest_matches(digest, ctx.digest_length, vector->expected)) {
            fprintf(stderr, "%s%s digest mismatch\n", hmac ? "HMAC-" : "", vector->name);
            return -1;
        }
    }
    return 0;
}

int test_picohash(void) {
    static const struct hash_vector hashes[] = {
        { "MD5", picohash_init_md5, "900150983cd24fb0d6963f7d28e17f72" },
        { "SHA-1", picohash_init_sha1, "a9993e364706816aba3e25717850c26c9cd0d89d" },
        { "SHA-224", picohash_init_sha224, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
        { "SHA-256", picohash_init_sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    };
    static const struct hash_vector hmacs[] = {
        { "SHA-1", picohash_init_sha1, "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9" },
        { "SHA-256", picohash_init_sha256, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8" },
    };

    for (size_t i = 0; i < sizeof(hashes) / sizeof(hashes[0]); ++i) {
        if (check_vector(&hashes[i], 0))
            return -1;
    }
    for (size_t i = 0; i < sizeof(hmacs) / sizeof(hmacs[0]); ++i) {
        if (check_vector(&hmacs[i], 1))
            return -1;
    }
    return 0;
}

#ifdef PICOHASH_STANDALONE
int main(void) {
    return test_picohash() != 0;
}
#endif
