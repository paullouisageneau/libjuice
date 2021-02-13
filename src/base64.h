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

#ifndef JUICE_BASE64_H
#define JUICE_BASE64_H

#include "juice.h"

#include <stdint.h>
#include <stdlib.h>

// RFC4648-compliant base64 encoder and decoder
JUICE_EXPORT int juice_base64_encode(const void *data, size_t size, char *out, size_t out_size);
JUICE_EXPORT int juice_base64_decode(const char *str, void *out, size_t out_size);

#define BASE64_ENCODE(data, size, out, out_size) juice_base64_encode(data, size, out, out_size)
#define BASE64_DECODE(str, out, out_size) juice_base64_decode(str, out, out_size)

#endif // JUICE_BASE64_H
