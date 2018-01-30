/*********************************************************************
* Filename:   sha256.c
* Author:     Marc-Andre Legault
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Implementation of the inversed SHA-256 hashing algorithm.
              This implementation uses little endian byte order.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include "sha256_inverse.h"

#include <stdlib.h>
#include <memory.h>
#include <stdio.h>

/****************************** MACROS ******************************/

/**************************** VARIABLES *****************************/
static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/

void sha256inv_init(SHA256_CTX *ctx, uint32_t* hash, WORD m[16])
{
	int idx;
	
	ctx->datalen = 0;
	ctx->bitlen = 0;
	
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
	
	// Iverse all states so we finish with all zeros
	ctx->a[63] = ~ctx->state[0] + 1;
	ctx->b[63] = ~ctx->state[1] + 1;
	ctx->c[63] = ~ctx->state[2] + 1;
	ctx->d[63] = ~ctx->state[3] + 1;
	ctx->e[63] = ~ctx->state[4] + 1;
	ctx->f[63] = ~ctx->state[5] + 1;
	ctx->g[63] = ~ctx->state[6] + 1;
	ctx->h[63] = ~ctx->state[7] + 1;
	
	// Filling the expansion
	for (idx=0 ; idx<16 ; idx++)
	{
		ctx->m[63-idx] = m[idx];
	}
	for (idx=63-16 ; idx>=0 ; idx--)
	{
		ctx->m[idx] = ctx->m[idx+16] - SIG1(ctx->m[idx+14]) - ctx->m[idx+9] - SIG0(ctx->m[idx+1]);
		//printf("Setting m%d to 0x%08X\n", idx, ctx->m[idx]);
	}

	
}


void sha256inv_transform(SHA256_CTX* ctx)
{
	int idx=64;

	for (idx=64 ; idx>=1 ; idx--)
	{
		ctx->a[idx-1] = ctx->b[idx];
		ctx->b[idx-1] = ctx->c[idx];
		ctx->c[idx-1] = ctx->d[idx];
		ctx->e[idx-1] = ctx->f[idx];
		ctx->f[idx-1] = ctx->g[idx];
		ctx->g[idx-1] = ctx->h[idx];

		ctx->t2[idx-1] = EP0(ctx->a[idx-1]) + MAJ(ctx->a[idx-1],ctx->b[idx-1],ctx->c[idx-1]);
		ctx->t1[idx-1] = ctx->a[idx] - ctx->t2[idx-1];
		ctx->d[idx-1] = ctx->e[idx] - ctx->t1[idx-1];
		ctx->t1k[idx] = ctx->t1[idx-1] - EP1(ctx->e[idx-1]) - CH(ctx->e[idx-1],ctx->f[idx-1],ctx->g[idx-1]) - k[idx-1];
		//printf("t1=0x%08X, t2=0x%08X, konst=0x%08X\n", t1, t2, konst);
		ctx->h[idx-1] = ctx->t1k[idx]-ctx->m[idx-1]; 
	}
}

int sha256inv_final(SHA256_CTX *ctx, BYTE hash[])
{
	int i, j;
	for (i = 0, j = 0; i < 16; ++i, j += 4)
	{
		ctx->data[j] = ctx->m[i] >> 24;
		ctx->data[j+1] = ctx->m[i] >> 16;
		ctx->data[j+2] = ctx->m[i] >> 8;
		ctx->data[j+3] = ctx->m[i] ;
	}
	
	ctx->bitlen = 0;
	for (i=0; i<8 ; i++)
	{
		ctx->bitlen |= ctx->data[56+i]<<(56-i*8);
	}

	if (ctx->bitlen >= 448)
	{
		printdata(ctx);
		printf("Damn,bitlen=%llu\n", ctx->bitlen);
		//printf("Damn,bitlen=%X\n", ctx->bitlen);
		return 1;
	}	
	//printf("Youpppi,message is one pass!\n");
	
	//Check if message is delimited with a 1
	unsigned int bytenumber = ctx->bitlen >> 3;
	unsigned int bitnumber = (ctx->bitlen & 0x07) + 1;
	BYTE mask = (1<<(8-bitnumber));
	//printf("bytenumber=%d, bitnumber=%d, mask=0x%08X, databyte=0x%08X, result=0x%08X\n", bytenumber, bitnumber, mask, ctx->data[bytenumber], ctx->data[bytenumber]&mask);
	if ( (ctx->data[bytenumber] & mask) != 1)
	{
		printdata(ctx);
		printf("Damn,message is delimited with a 0!\n");	
		return 1;
	}
	//printf("Youpppi, message is delimited with a 1!\n");

	//Check if the message is zero padded
	for (i=bytenumber ; i<56 ; i++)
	{
		if (ctx->data[i] != 0x00)
		{
			printdata(ctx);
			printf("Damn, message is not zero padded\n");
			return 1;
		}
	}
	printctx(ctx);
	printf("Youpppi!!! message is valid!\n");
	exit(0);
}




