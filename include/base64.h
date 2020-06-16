/**
 * This code is Copyright John Schember. All rights are reserved. 
 * This code is created by John Schember is licensed under the MIT License.
 */

#ifndef BASE64_H_
#define BASE64_H_
#include <stdint.h>
#include <stdlib.h>

/** Decodes a word encoded in base64 */
int32_t 
b64_decode(const char * in, unsigned char * out, uint64_t outlen);

/** Encodes a word to base64 */
char * 
b64_encode(const unsigned char * in, uint64_t len);

/** Returns the real data length given an encoded string */
uint64_t 
b64_decoded_size(const char * in);

#endif