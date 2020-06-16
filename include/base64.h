/**
 * This code is Copyright John Schember. All rights are reserved. 
 * This code is created by John Schember is licensed under the MIT License.
 */

#ifndef BASE64_H_
#define BASE64_H_

#include <stdint.h>
#include <stdlib.h>

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const int32_t b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
	59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51 };

/** Decodes a word encoded in base64 */
int32_t b64_decode(const char * in, unsigned char * out, uint64_t outlen);

/** Encodes a word to base64 */
char * b64_encode(const unsigned char * in, uint64_t len);

#endif