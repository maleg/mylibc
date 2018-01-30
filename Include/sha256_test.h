/*
 * sha256_test.h
 *
 *  Created on: 2018-01-29
 *      Author: malego
 */

#ifndef INCLUDE_SHA256_TEST_H_
#define INCLUDE_SHA256_TEST_H_

#include <stdio.h> // for printf
#include <stdint.h> // for uint64_t
#include <string.h> // for memcpy

struct TestCase{
	uint32_t answer[8];
	char * message;
};



int check_all();


#endif /* INCLUDE_SHA256_TEST_H_ */
