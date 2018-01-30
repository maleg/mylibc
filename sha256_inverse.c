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
#include "common.h"

/****************************** MACROS ******************************/

/**************************** VARIABLES *****************************/
static const uint32_t k[64] = {
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

void sha256inv_init(SHA256INV_CTX *ctx, uint8_t* hash_bytes, uint32_t m[16], int msg_len, int verbose)
{
	int idx;
	uint32_t hash[8];
	memcpy_swap32(hash, hash_bytes, 32);
	//hexdump_uint32_hn("sha256inv_init hash words: ", hash, 8);
	
	ctx->datalen = msg_len;
	ctx->bitlen = 0;
	
	// Substract states from the hash so we get the last a/b/c...
	ctx->a[64] = hash[0] - 0x6a09e667;
	ctx->b[64] = hash[1] - 0xbb67ae85;
	ctx->c[64] = hash[2] - 0x3c6ef372;
	ctx->d[64] = hash[3] - 0xa54ff53a;
	ctx->e[64] = hash[4] - 0x510e527f;
	ctx->f[64] = hash[5] - 0x9b05688c;
	ctx->g[64] = hash[6] - 0x1f83d9ab;
	ctx->h[64] = hash[7] - 0x5be0cd19;
	ctx->t1[0] = 0;
	//ctx->t2[0] = 0;
	ctx->m[64] = 0;
	
	// Filling the expansion from the end (48th to 64th slots)
	for (idx=0 ; idx<16 ; idx++)
	{
		ctx->m[63-idx] = m[idx];
	}
	for (idx=63-16 ; idx>=0 ; idx--)
	{
		ctx->m[idx] = ctx->m[idx+16] - SIG1(ctx->m[idx+14]) - ctx->m[idx+9] - SIG0(ctx->m[idx+1]);
		//printf("Setting m%d to 0x%08X\n", idx, ctx->m[idx]);
	}
	memcpy_swap32(ctx->data, ctx->m, 64);
	//hexdump_bytes_hn("sha256inv_init m bytes : ", (uint8_t*)ctx->m, 256);
	
}


void sha256inv_transform(SHA256INV_CTX* ctx, int verbose)
{
	int idx;

	//M63 = ctx->a[idx] - EP0(ctx->b[idx]) - MAJ(ctx->b[idx],ctx->c[idx],ctx->d[idx]) - EP1(ctx->f[idx]) - CH(ctx->f[idx],ctx->g[idx],ctx->h[idx]) - k[idx-1] - H63
	for (idx=64 ; idx>=1 ; idx--)
	{
		ctx->t1[idx] = ctx->a[idx] - EP0(ctx->b[idx]) - MAJ(ctx->b[idx],ctx->c[idx],ctx->d[idx]);
		ctx->t2[idx] = ctx->t1[idx] - EP1(ctx->f[idx]) - CH(ctx->f[idx],ctx->g[idx],ctx->h[idx]) - k[idx-1];
		if (verbose) printf("Round%d : a=%.8X b=%.8X c=%.8X d=%.8X e=%.8X f=%.8X g=%.8X h=%.8X t1=%.8X t2=%.8X m=%.8X\n", idx, ctx->a[idx], ctx->b[idx], ctx->c[idx], ctx->d[idx], ctx->e[idx], ctx->f[idx], ctx->g[idx], ctx->h[idx], ctx->t1[idx], ctx->t2[idx], ctx->m[idx]);
		ctx->a[idx-1] = ctx->b[idx];
		ctx->b[idx-1] = ctx->c[idx];
		ctx->c[idx-1] = ctx->d[idx];
		ctx->d[idx-1] = ctx->e[idx] - ctx->t1[idx];
		ctx->e[idx-1] = ctx->f[idx];
		ctx->f[idx-1] = ctx->g[idx];
		ctx->g[idx-1] = ctx->h[idx];
		ctx->h[idx-1] = ctx->t2[idx] - ctx->m[idx-1];

		//ctx->t2[idx-1] = EP0(ctx->a[idx-1]) + MAJ(ctx->a[idx-1],ctx->b[idx-1],ctx->c[idx-1]);
		//ctx->t1[idx-1] = ctx->a[idx] - ctx->t2[idx-1];
		//ctx->d[idx-1] = ctx->e[idx] - ctx->t1[idx-1];
		//printf("t1=0x%08X, t2=0x%08X, konst=0x%08X\n", t1, t2, konst);
		//ctx->h[idx-1] = ctx->t1[idx-1] - EP1(ctx->e[idx-1]) - CH(ctx->e[idx-1],ctx->f[idx-1],ctx->g[idx-1]) - k[idx-1] - ctx->m[idx-1];
	}
	idx=0;
	if (verbose) printf("Round%d : a=%.8X b=%.8X c=%.8X d=%.8X e=%.8X f=%.8X g=%.8X h=%.8X t1=%.8X t2=%.8X m=%.8X\n", idx, ctx->a[idx], ctx->b[idx], ctx->c[idx], ctx->d[idx], ctx->e[idx], ctx->f[idx], ctx->g[idx], ctx->h[idx], ctx->t1[idx], ctx->t2[idx], ctx->m[idx]);
}

int sha256inv_final(SHA256INV_CTX* ctx, int verbose)
{
	int i;
	int final_state_valid = 1;
	if (ctx->a[0] != 0x6a09e667) final_state_valid = 0;
	if (ctx->b[0] != 0xbb67ae85) final_state_valid = 0;
	if (ctx->c[0] != 0x3c6ef372) final_state_valid = 0;
	if (ctx->d[0] != 0xa54ff53a) final_state_valid = 0;
	if (ctx->e[0] != 0x510e527f) final_state_valid = 0;
	if (ctx->f[0] != 0x9b05688c) final_state_valid = 0;
	if (ctx->g[0] != 0x1f83d9ab) final_state_valid = 0;
	if (ctx->h[0] != 0x5be0cd19) final_state_valid = 0;

	if	(!final_state_valid)
	{
		printf("Final state invalid\n");
		return 1;
	}
	//printf("Final state Valid\n");

	ctx->bitlen = be64toh(*(uint64_t*)&ctx->data[56]);

	if (ctx->bitlen >= 448)
	{
		//printdata(ctx);
		printf("Damn,bitlen=%lu\n", ctx->bitlen);
		//printf("Damn,bitlen=%X\n", ctx->bitlen);
		return 1;
	}
	//printf("Youpppi,message is one pass of length = %lubits = %luB!\n", ctx->bitlen, ctx->bitlen/8);

	//Check if message is delimited with a 1
	if (ctx->data[ctx->bitlen/8] != 0x80)
	{
		//printdata(ctx);
		printf("Damn,message is delimited with %.2X!\n", ctx->data[ctx->bitlen/8]);
		return 1;
	}
	//printf("Youpppi, message is delimited with a 0x80!\n");

	//Check if the message is zero padded
	for (i=(ctx->bitlen/8)+1 ; i<56 ; i++)
	{
		if (ctx->data[i] != 0x00)
		{
			//printdata(ctx);
			printf("Damn, message is not zero padded at i=%d, value=%.2X\n", i, ctx->data[i]);
			return 1;
		}
	}
	//printctx(ctx);
	return 0;

}



