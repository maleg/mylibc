/*********************************************************************
* Filename:   sha256.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Implementation of the SHA-256 hashing algorithm.
              SHA-256 is one of the three algorithms in the SHA2
              specification. The others, SHA-384 and SHA-512, are not
              offered in this implementation.
              Algorithm specification can be found here:
               * http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
              This implementation uses little endian byte order.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include "sha256_lisible.h"
#include <string.h>

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

void sha256_transform(SHA256_CTX *ctx, const uint32_t data[], int verbose)
{
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2;
	WORD m1=0, m2=0;

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		ctx->m[i] = data[i];
	for ( ; i < 64; ++i){
		ctx->m[i] = SIG1(ctx->m[i - 2]) + ctx->m[i - 7] + SIG0(ctx->m[i - 15]) + ctx->m[i - 16];
	}
	//hexdump_bytes_hn("sha256inv_init hash : ", (uint8_t*)ctx->m, 256);

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];
	for (i = 0; i < 64; ++i) {
		// E61 = HashH-KH = D60 + h60 + EP1(e60) + CH(e60,f60,g60) + k[60] + ctx->m[60];
		// A61 = HashD-KD = h60 + EP1(e) + CH(e,f,g) + k[60] + ctx->m[60] + EP0(a) + MAJ(a,b,c)
		/*if (i==59){
			// For both
			// 0x6F7B4F79 was brute force calculated
			//ctx->m[i] = 0x20CA0CC2 - h - EP1(e) - CH(e,f,g) -k[i] - EP0(a) - MAJ(a,b,c) ;
			//ctx->m[i] = 0 ;
		}
		if (i==60){
			// For correct H                              K           HashH
			m1 =  - h - EP1(e) - CH(e,f,g) - k[i] - d - 0x5BE0CD19 + 0x393CB650 ;
			// For correct D
			m2 =   - h - EP1(e) - CH(e,f,g) - k[i] - EP0(a) - MAJ(a,b,c) - 0xA54FF53A + 0xE1550CAD;
			//For Both
			// d60 - 0x5BE0CD19 + 0x393CB650 = EP0(a) - MAJ(a,b,c) - 0xA54FF53A + 0xE1550CAD;
			// 0xF9EB9D5B - 0x5BE0CD19 + 0x393CB650 + 0xA54FF53A - 0xE1550CAD = EP0(a) - MAJ(a,b,c)
			// −0x15894CB97 = (ROTRIGHT(a,2) ^ ROTRIGHT(a,13) ^ ROTRIGHT(a,22)) - ((a & b60) ^ (a & c60) ^ (b60 & c60))
			// −0x15894CB97 = (ROTRIGHT(a,2) ^ ROTRIGHT(a,13) ^ ROTRIGHT(a,22)) - ((a & b60) ^ (a & c60) ^ 0x2A061244)
			// a60 = 061D4FBB or 20CA0CC2 or 8777EEFB
			// HashH = 393CB650
			// recompute mh
			//ctx->m[i] =m2;
		}
		if (i==61){
			// For correct G
			m1 = 0xA3A1413D - 0x1F83D9AB - d - h - EP1(e) - CH(e,f,g) - k[i];
			// For correct C
			m2 = 0xEBEAB5B4 - 0x3C6EF372 - h - EP1(e) - CH(e,f,g) - k[i] - EP0(a) - MAJ(a,b,c) ;
			//ctx->m[i] =m2;
		}
		if (i==62){
			// For correct F
			m1 =  - h - EP1(e) - CH(e,f,g) - k[i] + 0x48FBC4EF - 0x9B05688C - d;
			// For correct B
			m2  = - h - EP1(e) - CH(e,f,g) - k[i] + 0xCF23E14E - 0xBB67AE85 - EP0(a) - MAJ(a,b,c) ;
			// Both
			// a =
			ctx->m[i] = - h - EP1(e) - CH(e,f,g) -k[i] + 0x2B3F8B26 - EP0(a) - MAJ(a,b,c) ;
			//ctx->m[i] =m2;
		}
		if (i==63){
			// For correct E                           HashE        kE:
			m1 =  -h - EP1(e) - CH(e,f,g) - k[i] + 0x5B509E33 - 0x510E527F - d;
			// For correct A                         HashA        kA
			m2 =  -h - EP1(e) - CH(e,f,g) - k[i] + 0xF7846F55 - 0x6A09E667 - EP0(a) - MAJ(a,b,c);
			// Both
			// a = HashB-kB, b=HashC-kC, c=HashD-kD => Resoudre pour d
			// D63 = HashE - kE - HashA + kA + EP0(HashB-kB) + MAJ(HashB-kB,HashC-kC,HashD-kd)
			// D63 = 0x5B509E33 - 0x510E527F - 0xF7846F55 + 0x6A09E667 + EP0(a) + MAJ(a,b,c)
			//ctx->m[i] =m2; answer ctx->m=AD706F97
		}
		*/
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + ctx->m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		if (verbose) printf("Round%d : a=%.8X b=%.8X c=%.8X d=%.8X e=%.8X f=%.8X g=%.8X h=%.8X m=%.8X m1=%.8X m2=%.8X t1=%.8X t2=%.8X\n", i, a, b, c, d, e, f, g, h, ctx->m[i], m1, m2, t1, t2);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
	if (verbose) printf("Round%d : a=%.8X b=%.8X c=%.8X d=%.8X e=%.8X f=%.8X g=%.8X h=%.8X\n", 64, a, b, c, d, e, f, g, h);
	if (verbose) printf("Add k   :ka=%.8Xkb=%.8Xkc=%.8Xkd=%.8Xke=%.8Xkf=%.8Xkg=%.8Xkh=%.8X\n", ctx->state[0], ctx->state[1], ctx->state[2], ctx->state[3], ctx->state[4], ctx->state[5], ctx->state[6], ctx->state[7]);


	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
/*
	for (idx=0 ; idx<8 ; idx++){
		printf("result%d = %08X\n", idx, ctx->state[idx]);
	}
*/
	//hexdump("Trs: ", ctx->state, 32);
	if (verbose) printf("Result  : a=%.8X b=%.8X c=%.8X d=%.8X e=%.8X f=%.8X g=%.8X h=%.8X\n", ctx->state[0], ctx->state[1], ctx->state[2], ctx->state[3], ctx->state[4], ctx->state[5], ctx->state[6], ctx->state[7]);

}

void sha256_init(SHA256_CTX *ctx)
{
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
}

void sha256_update_old(SHA256_CTX *ctx, const BYTE data[], size_t len, int verbose)
{
	WORD i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, (const uint32_t*)ctx->data, verbose);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_update_from_bytes(SHA256_CTX *ctx, const BYTE data[], size_t len, int verbose)
{
	int i;
	int rest = len%4;
	len >>= 2;
	for (i = 0; i < len; i++) {
		ctx->data[i] = htobe32(*(uint32_t*)&data[i*4]);
		ctx->datalen+=4;
		if (ctx->datalen >= 64) {
			sha256_transform(ctx, ctx->data, verbose);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
	if (rest){
		ctx->data[i] =0;
		for (int j=0 ; j<rest ; j++){
			ctx->data[i] |= (
					(uint32_t)data[i*4 + j])<<(24-(j*8));
		}
		ctx->datalen+=rest;
	}
}

void sha256_update_from_words(SHA256_CTX *ctx, const uint32_t data[], size_t len, int verbose)
{
	int i;
	int rest = len%4;
	len >>= 2;

	for (i = 0; i < len; i++) {
		ctx->data[i] = data[i];
		ctx->datalen+=4;
		if (ctx->datalen >= 64) {
			sha256_transform(ctx, ctx->data, verbose);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
	if (rest){

		if (rest==1) ctx->data[i] = data[i] & 0xFF000000;
		if (rest==2) ctx->data[i] = data[i] & 0xFFFF0000;
		if (rest==3) ctx->data[i] = data[i] & 0xFFFFFF00;
		ctx->datalen+=rest;
	}
}

void sha256_final_words(SHA256_CTX *ctx, uint32_t hash[], int verbose)
{

	int i = ctx->datalen>>2;
	int rest = ctx->datalen%4;

	// Pad whatever data is left in the buffer.
	ctx->data[i] |= 0x80<<(24-(rest*8));
	i++;
	if (ctx->datalen < 56) {
		while (i < 14)
			ctx->data[i++] = 0x00000000;
	}
	else {
		while (i < 16)
			ctx->data[i++] = 0x00000000;
		sha256_transform(ctx, ctx->data, verbose);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[15] = (uint32_t)ctx->bitlen;
	sha256_transform(ctx, (const uint32_t*)ctx->data, verbose);

	memcpy(hash, ctx->state, 32);
}

void sha256_final_bytes(SHA256_CTX *ctx, BYTE hash[], int verbose)
{

	int i = ctx->datalen>>2;
	int rest = ctx->datalen%4;

	// Pad whatever data is left in the buffer.
	ctx->data[i] |= 0x80<<(24-(rest*8));
	i++;
	if (ctx->datalen < 56) {
		while (i < 14)
			ctx->data[i++] = 0x00000000;
	}
	else {
		while (i < 16)
			ctx->data[i++] = 0x00000000;
		sha256_transform(ctx, ctx->data, verbose);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[15] = (uint32_t)ctx->bitlen;
	sha256_transform(ctx, (const uint32_t*)ctx->data, verbose);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

void sha256_final_old(SHA256_CTX *ctx, BYTE hash[], int verbose)
{
	WORD i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, (const uint32_t*)ctx->data, verbose);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, (const uint32_t*)ctx->data, verbose);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}
