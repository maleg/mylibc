/*
 * sha256_generate_train_files.h
 *
 *  Created on: 2018-01-29
 *      Author: malego
 */

#ifndef SHA256_GENERATE_TRAIN_FILES_H_
#define SHA256_GENERATE_TRAIN_FILES_H_


#include "sha256_lisible.h"
#include "sha256_inverse.h"

#include <stdint.h> // for uint64_t
#include <stdio.h> // for printf
#include <string.h> // for memcpy
#include <fcntl.h> // for open
#include <unistd.h> // for close


void generate_train_file();

#endif /* SHA256_GENERATE_TRAIN_FILES_H_ */
