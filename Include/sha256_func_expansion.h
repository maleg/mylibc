/*
 * sha256_func_expansion.h
 *
 *  Created on: 2018-01-29
 *      Author: malego
 */

#ifndef INCLUDE_SHA256_FUNC_EXPANSION_H_
#define INCLUDE_SHA256_FUNC_EXPANSION_H_

#include <stdio.h> // for printf
#include <stdint.h> // for uint64_t
#include <string.h> // for memcpy

void expand_bytes(uint8_t* data, uint32_t* last_16_m);


#endif /* INCLUDE_SHA256_FUNC_EXPANSION_H_ */
