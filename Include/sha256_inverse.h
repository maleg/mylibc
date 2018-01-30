#ifndef _SHA256_INVERSE_H_
#define _SHA256_INVERSE_H_

/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include <stdint.h> //For uint32_t
#include <memory.h>
#include <stdio.h>

/****************************** MACROS ******************************/
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** STRUCTURES *****************************/
typedef struct {
	uint32_t state[8];
	uint8_t data[64];
	uint32_t a[65];
	uint32_t b[65];
	uint32_t c[65];
	uint32_t d[65];
	uint32_t e[65];
	uint32_t f[65];
	uint32_t g[65];
	uint32_t h[65];
	uint32_t t1[65];
	uint32_t t2[65];
	uint32_t m[65];
	int datalen;
	uint64_t bitlen;
}SHA256INV_CTX;

/*********************** FUNCTION DEFINITIONS ***********************/


void sha256inv_init(SHA256INV_CTX *ctx, uint8_t* hash_bytes, uint32_t m[16], int msg_len, int verbose);
void sha256inv_transform(SHA256INV_CTX* ctx, int verbose);
int sha256inv_final(SHA256INV_CTX *ctx, int verbose);



#endif
