#ifndef _SHA256_INVERSE_H_
#define _SHA256_INVERSE_H_

/*************************** HEADER FILES ***************************/
#include <stdlib.h>
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
struct SHA256_CTX {
	uint32_t state[8];
	int datalen;
	int bitlen;
}

/*********************** FUNCTION DEFINITIONS ***********************/


void sha256inv_init(SHA256_CTX *ctx, uint32_t* hash, WORD m[16]);
void sha256inv_transform(SHA256_CTX* ctx);
int sha256inv_final(SHA256_CTX *ctx, BYTE hash[]);



#endif
