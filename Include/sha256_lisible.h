/*
 * sha256_lisible.h
 *
 *  Created on: 2018-01-12
 *      Author: malego
 */

#ifndef SHA256_LISIBLE_H_
#define SHA256_LISIBLE_H_


#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>


#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

#define BYTE unsigned char
#define WORD uint32_t


typedef struct {
	uint32_t state[8];
	BYTE data[64];
	uint32_t m[64];
	int datalen;
	uint64_t bitlen;
}SHA256_CTX;


void sha256_transform(SHA256_CTX *ctx, const uint32_t data[], int verbose);
void sha256_init(SHA256_CTX *ctx);
void sha256_update_old(SHA256_CTX *ctx, const BYTE data[], size_t len, int verbose);
void sha256_update_from_bytes(SHA256_CTX *ctx, const BYTE data[], size_t len, int verbose);
void sha256_update_from_words(SHA256_CTX *ctx, const uint32_t data[], size_t len, int verbose);
void sha256_final_words(SHA256_CTX *ctx, uint32_t hash[], int verbose);
void sha256_final_bytes(SHA256_CTX *ctx, BYTE hash[], int verbose);
void sha256_final_old(SHA256_CTX *ctx, BYTE hash[], int verbose);


#endif /* SHA256_LISIBLE_H_ */
