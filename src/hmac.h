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

#ifndef JUICE_HMAC_H
#define JUICE_HMAC_H

#include <stdint.h>
#include <stdlib.h>

#define HMAC_SHA1_SIZE 20
#define HMAC_SHA256_SIZE 32

void hmac_sha1(const void *message, size_t size, const void *key, size_t key_size, void *digest);
void hmac_sha256(const void *message, size_t size, const void *key, size_t key_size, void *digest);

#endif
