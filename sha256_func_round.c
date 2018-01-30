/*
 * round.c
 *
 *  Created on: 2018-01-26
 *      Author: malego
 */


#include "sha256_lisible.h"
#include "common.h"

#include <stdio.h> // for printf
#include <stdint.h> // for uint64_t
#include <string.h> // for memcpy



#define A 0
#define B 1
#define C 2
#define D 3
#define E 4
#define F 5
#define G 6
#define H 7


static uint32_t k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static uint32_t init[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};

int brute_force_1_word()
{
	SHA256INV_CTX ctxinv;
	SHA256INV_CTX* ctxinv_p = &ctxinv;
	uint32_t a=0;
	uint32_t solution = 0;
	uint32_t solutions[128];

}

int brute_force_32(uint32_t b, uint32_t c, uint32_t d, uint32_t h1, uint32_t k1, uint32_t h2, uint32_t k2)
{
	uint32_t a=0;
	uint32_t solution = 0;
	uint32_t solutions[128];

	do{
		uint32_t rot = (ROTRIGHT(a,2) ^ ROTRIGHT(a,13) ^ ROTRIGHT(a,22));
		uint32_t xor = ((a & b) ^ (a & c) ^ (b^c));
		if (rot-xor == (d - k1 + h1 + k2 - h2)){
			solutions[solution] = a;
			solution++;
		}
		a++;
		if (a%0x100000 == 0){
			printf(" %d Solutions at a=%08X\n", solution, a);
		}
	}while(a != 0);
	printf(" %d Solutions at a=%08X\n", solution, a);
	for (int i=0 ; i<solution ; i++){
		printf("Solution %d = %08X\n", i, solutions[i]);
	}
	return 0;
}

void sumHM_ri(int r0, uint32_t a_r1, uint32_t f_r1, uint32_t g_r1, uint32_t t2_r0)
{
	#define MAX_SOLUTION_QTY 1000000
	uint32_t h_r1 = 0;
	uint32_t solution_qty=0;
	uint32_t sumMH;

	unsigned char * lookup_p;
	lookup_p = malloc(1UL<<29);
	if (lookup_p == NULL)
	{
		printf("Error malloc");
		exit(1);
	}
	memset(lookup_p, 0, 1UL<<29);

	do{
		sumMH = a_r1 - EP1(f_r1) - CH(f_r1, g_r1, h_r1) - k[r0] - t2_r0;
		int match = msg_get_bit(lookup_p, sumMH);
		if (!match){
			msg_set_bit(lookup_p, sumMH);
			solution_qty++;
			printf("Solution %d = %08X\n", solution_qty, sumMH);
		}
		if (h_r1%0x1000000 == 0){
			printf(" %d Solutions at a=%08X\n", solution_qty, h_r1);
		}
		h_r1++;
	}while(h_r1 != 0);

}

uint32_t solve_D63(uint32_t hash[8])
{
	// a = HashB-kB, b=HashC-kC, c=HashD-kD => Resoudre pour d
	// D63 = HashE - kE - HashA + kA + EP0(HashB-kB) + MAJ(HashB-kB,HashC-kC,HashD-kd)
	// D63 = 0x5B509E33 - 0x510E527F - 0xF7846F55 + 0x6A09E667 + EP0(a) + MAJ(a,b,c)
	uint32_t a[65];
	uint32_t b[65];
	uint32_t c[65];
	uint32_t d[65];
	uint32_t e[65];
	uint32_t f[65];
	uint32_t g[65];
	uint32_t h[65];
	uint32_t m[64];
	uint32_t t1[64];
	uint32_t t2[64];
	int i;

	a[64] = hash[A]-init[A];
	b[64] = hash[B]-init[B];
	c[64] = hash[C]-init[C];
	d[64] = hash[D]-init[D];
	e[64] = hash[E]-init[E];
	f[64] = hash[F]-init[F];
	g[64] = hash[G]-init[G];
	h[64] = hash[H]-init[H];
	i=64;
	printf("Round%d : a=%.8X b=%.8X c=%.8X d=%.8X e=%.8X f=%.8X g=%.8X h=%.8X m=%.8X t1=%.8X t2=%.8X\n", i, a[i], b[i], c[i], d[i], e[i], f[i], g[i], h[i], m[i], t1[i], t2[i]);

	t2[63] = EP0(b[64]) + MAJ(b[64],c[64],d[64]);
	uint32_t sum_m63_h63 = (a[64] - EP1(f[64]) - CH(f[64],g[64],h[64]) - k[63] - t2[63]);
	//uint32_t sum_m63_h63 = e64 - EP1(f[64]) - CH(f[64],g[64],h[64]) - k[63] - d[63];
	//uint32_t sum_m62_h62 = b[64] - EP1(g[64]) - CH(g[64],h[64],((a[64] - EP1(f[64]) - CH(f[64],g[64],h[64]) - k[63] - EP0(b[64]) - MAJ(b[64],c[64],d[64]))-m[63])) - k[62] - EP0(c[64]) + MAJ(c[64],d[64], (e[64] - a[64] + EP0(b[64]) + MAJ(b[64],c[64],d[64])) );
	printf("%08X\n",sum_m63_h63);
	a[63] = b[64];
	b[63] = c[64];
	c[63] = d[64];
	//d[63] = e[64] - a[64] + t2[63]  ;
	d[63] = e[64] - a[64] + EP0(b[64]) + MAJ(b[64],c[64],d[64]);
	e[63] = f[64];
	f[63] = g[64];
	g[63] = h[64];
	h[63] =  0 ; // E9E49D83
	m[63] =  0 ; // AD706F97
	i = 63;
	sumHM_ri(i, a[i+1], f[i+1], g[i+1], t2[i]);
	printf("Round%d : a=%.8X b=%.8X c=%.8X d=%.8X e=%.8X f=%.8X g=%.8X h=%.8X m=%.8X t1=%.8X t2=%.8X\n", i, a[i], b[i], c[i], d[i], e[i], f[i], g[i], h[i], m[i], t1[i], t2[i]);

	t2[62] = EP0(b[63]) + MAJ(b[63],c[63],d[63]);
	uint32_t sum_m62_h62 = a[63] - EP1(f[63]) - CH(f[63],g[63],h[63]) - k[62] - t2[62];
	a[62] = b[63];
	b[62] = c[63];
	c[62] = d[63];
	d[62] = e[63] - a[63] + t2[62]  ; // AF6E2DEF
	e[62] = f[63];
	f[62] = g[63];
	g[62] = 0 ;
	h[62] = 0 ; // D12CF8AE
	m[62] = 0 ; // C974594C
	i = 62;
	sumHM_ri(i, a[i+1], f[i+1], g[i+1], t2[i]);
	printf("Round%d : a=%.8X b=%.8X c=%.8X d=%.8X e=%.8X f=%.8X g=%.8X h=%.8X m=%.8X t1=%.8X t2=%.8X\n", i, a[i], b[i], c[i], d[i], e[i], f[i], g[i], h[i], m[i], t1[i], t2[i]);

	t2[61] = EP0(b[62]) + MAJ(b[62],c[62],d[62]);
	uint32_t sum_m61_h61 = a[62] - EP1(f[62]) - CH(f[62],0,0) - k[61] - t2[61];
	a[61] = b[62];
	b[61] = c[62];
	c[61] = d[62];
	d[61] = e[62] - a[62] + t2[61]  ; // F3CC1DBB
	e[61] = f[62];
	f[61] = 0 ;
	g[61] = 0 ;
	h[61] = 0 ; // CA279B7A
	m[61] = 0 ; // 03FA48B0
	i = 61;
	printf("Round%d : a=%.8X b=%.8X c=%.8X d=%.8X e=%.8X f=%.8X g=%.8X h=%.8X m=%.8X t1=%.8X t2=%.8X\n", i, a[i], b[i], c[i], d[i], e[i], f[i], g[i], h[i], m[i], t1[i], t2[i]);

	t2[60] = EP0(b[61]) + MAJ(b[61],c[61],d[61]);
	uint32_t sum_m60_h60 = a[61] - EP1(0) - CH(0,0,0) - k[60] - t2[60];
	a[60] = b[61];
	b[60] = c[61];
	c[60] = d[61];
	d[60] = e[61] - a[61] + t2[60]  ; // F3CC1DBB
	e[60] = 0 ;
	f[60] = 0 ;
	g[60] = 0 ;
	h[60] = 0 ; // CA279B7A
	m[60] = 0 ; // 03FA48B0
	i = 60;
	printf("Round%d : a=%.8X b=%.8X c=%.8X d=%.8X e=%.8X f=%.8X g=%.8X h=%.8X m=%.8X t1=%.8X t2=%.8X\n", i, a[i], b[i], c[i], d[i], e[i], f[i], g[i], h[i], m[i], t1[i], t2[i]);
	// M60 = 0X00000001 ; aFFECTE A61 & E61
	// t1=h + EP1(e) + CH(e,f,g) + k[i] + m[i]
	t2[59] = EP0(b[60]) + MAJ(b[60],c[60],d[60]);
	uint32_t sum_m59_h59 = a[60] - EP1(0) - CH(0,0,0) - k[59] - t2[59];
	a[59] = b[60];
	b[59] = c[60];
	c[59] = d[60];
	d[59] = 0 - a[60] + t2[59]  ;
	e[59] = 0 ;
	f[59] = 0 ;
	g[59] = 0 ;
	h[59] = 0 ;
	m[59] = 0 ;
	i = 59;
	printf("Round%d : a=%.8X b=%.8X c=%.8X d=%.8X e=%.8X f=%.8X g=%.8X h=%.8X m=%.8X t1=%.8X t2=%.8X\n", i, a[i], b[i], c[i], d[i], e[i], f[i], g[i], h[i], m[i], t1[i], t2[i]);
	return 0;
}
