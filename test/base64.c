/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "base64.h"

#include <stdint.h>
#include <string.h>

#define BUFFER_SIZE 1024

int test_base64(void) {
	const char *str = "Man is distinguished, not only by his reason, but by this singular passion "
	                  "from other animals, which is a lust of the mind, that by a perseverance of "
	                  "delight in the continued and indefatigable generation of knowledge, exceeds "
	                  "the short vehemence of any carnal pleasure.";
	const char *expected =
	    "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlzIHNpbmd1bGFyIH"
	    "Bhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2YgdGhlIG1pbmQsIHRoYXQgYnkgYSBw"
	    "ZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGludWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb2"
	    "4gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRoZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4"
	    "=";

	char buffer1[BUFFER_SIZE];
	if (BASE64_ENCODE(str, strlen(str), buffer1, BUFFER_SIZE) <= 0)
		return -1;

	if (strcmp(buffer1, expected) != 0)
		return -1;

	char buffer2[BUFFER_SIZE];
	int len = BASE64_DECODE(buffer1, buffer2, BUFFER_SIZE);
	if (len <= 0)
		return -1;

	buffer2[len] = '\0';
	if (strcmp(buffer2, str) != 0)
		return -1;

	return 0;
}
