/*
 * expansion.c
 *
 *  Created on: 2018-01-26
 *      Author: malego
 */

#include "sha256_lisible.h"
#include "common.h"

#include <stdio.h> // for printf
#include <stdint.h> // for uint64_t
#include <string.h> // for memcpy


char* add_sig1term( char* str_p, uint8_t m[][32], int w, int b, int*prev_is_set);
char* add_sig0term( char* str_p, uint8_t m[][32], int w, int b, int*prev_is_set);


unsigned char * lookup_p;


void expand_bytes(uint8_t* data, uint32_t* last_16_m){
	int i, j;
	uint32_t m[64];
	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = htobe32(((uint32_t*)data)[i]);
	for ( ; i < 64; ++i){
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
		if (i>=48){
			last_16_m[i-48] = m[i];
		}
	}
}
void expand_words(uint8_t* data, uint32_t* last_16_m){
	int i, j;
	uint32_t m[64];
	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = htobe32(((uint32_t*)data)[i]);
	for ( ; i < 64; ++i){
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
		if (i>=48){
			last_16_m[i-48] = m[i];
		}
	}
}


void brute_force_expansion()
{
	//unsigned char msg_padded[64];
	uint32_t m[64];
	int i, solution_qty=0;

	memset(m, 0, 64);
	m[8] = 0x00800000;
	m[15] = 0x00000108;

	memset(lookup_p, 0, 1UL<<29);
	//i=16 => No reduction
	i=17;
	m[0]=0;
	//m[1]=0xAAAAAAAA;
	do{
		for (i=16 ; i<64 ; i++)
		{
			m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
		}
		int match = msg_get_bit(lookup_p, m[63]);
		if (!match){
			msg_set_bit(lookup_p, m[63]);
			solution_qty++;
		}
		if (m[0]%0x0100000 == 0){
			printf("Iter %08X = %08X SolQty (Result=%08X)\n", m[0], solution_qty, m[63]);
		}
		m[0]++;
	}while(m[0] != 0);

}
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

void print_expansion_analysis()
{
	int i=16, b;
	char term[4][64];
	char sig0[3][16];
	char sig1[3][16];

	for (i=16 ; i<64 ; i++)
	{
		for (b=0 ; b<32 ; b++)
		{
			int sig0a_idx = b+7 < 32 ? b+7 : b+7-32;
			int sig0b_idx = b+18 < 32 ? b+18 : b+18-32;
			int sig0c_idx = b+3;
			int sig1a_idx = b+17 < 32 ? b+17 : b+17-32;
			int sig1b_idx = b+19 < 32 ? b+19 : b+19-32;
			int sig1c_idx = b+10;

			sprintf(sig1[0], "m[%d][%d]", i-2, sig1a_idx);
			sprintf(sig1[1], "m[%d][%d]", i-2, sig1b_idx);
			sig1c_idx < 32 ? sprintf(sig1[2], "m[%d][%d]", i-2, sig1c_idx) : sprintf(sig1[2], "0");
			sprintf(sig0[0], "m[%d][%d]", i-15, sig0a_idx);
			sprintf(sig0[1], "m[%d][%d]", i-15, sig0b_idx);
			sig0c_idx < 32 ? sprintf(sig0[2], "m[%d][%d]", i-15, sig0c_idx) : sprintf(sig0[2], "0");

			sprintf(term[0], "(%s ^ %s ^ %s)", sig1[0], sig1[1], sig1[2]);
			sprintf(term[1], "m[%d][%d]", i-7, b);
			sprintf(term[2], "(%s ^ %s ^ %s)", sig0[0], sig0[1], sig0[2]);
			sprintf(term[3], "m[%d][%d]", i-16, b);

			printf("m[%d][%d] = %s + %s + %s + %s\n", i, b, term[0], term[1], term[2], term[3]);
		}
	}
}

void expansion_analysis()
{
//SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
//SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
//m[w][b] = (m[w-2][b+17^m[w-2][b+19]^m[w-2][b+10] )+ m[w - 7][b] + (m[w-15][b+7]^m[w-15][b+18]^m[w-15][b+3]) + m[w - 16][b];

	uint8_t m[64][32];
	int w=16, b;
	char term[16];
	char str[1024];
	char *str_p;
	int ret, prev_is_set=0;

	memset(m, 0, 64*32);
	//For a 32bit msg

	for (b=0 ; b<8 ; b++)
	{
		m[0][0] = 2;
	}
	m[0][8] = 1;
	m[15][3] = 1;

	for (w=16 ; w<64 ; w++)
	{
		for (b=0 ; b<32 ; b++)
		{
			str[0] = '\0';
			str_p = str;

			prev_is_set = 0;
			str_p = add_sig1term(str_p, m, w-2, b, &prev_is_set);

			sprintf(term, "m[%d][%d]", w-7, b);
			if(m[w-7][b]){
				ret = sprintf(str_p, "%s%s", prev_is_set?" + ":"", m[w-7][b]==1 ? "1":term);
				str_p += ret;
				prev_is_set = 1;
			}

			str_p = add_sig0term(str_p, m, w-15, b, &prev_is_set);

			sprintf(term, "m[%d][%d]", w-16, b);
			if(m[w-16][b]){
				ret = sprintf(str_p, "%s%s", prev_is_set?" + ":"", m[w-16][b]==1 ? "1":term);
				str_p += ret;
			}

			//Check if the formula reduced to zero
			if (str_p==str) sprintf(str, "0");

			if (str[0] == 'm' || str[0] == '(') m[w][b] = 2;
			else if (str[0] == '1') m[w][b] = 1;
			else m[w][b] = 0;

			printf("m[%d][%d] = %s\n", w, b, str);
		}
	}

}

char* add_sig1term( char* str_p, uint8_t m[][32], int w, int b, int*prev_is_set)
{
	int sig1a_idx = b+17 < 32 ? b+17 : b+17-32;
	int sig1b_idx = b+19 < 32 ? b+19 : b+19-32;
	int sig1c_idx = b+10;
	int sig1c = sig1c_idx < 32 ? m[w][sig1c_idx] : 0;

	//How many non-zero term, can make that easy
	int non_zero_qty = 0, ret;
	if (m[w][sig1a_idx]) non_zero_qty++;
	if (m[w][sig1b_idx]) non_zero_qty++;
	if (sig1c) non_zero_qty++;

	//Precompile the term string in case the value is 2 (unknown from message)
	char term1[16], term2[16], term3[16];
	sprintf(term1, "m[%d][%d]", w, sig1a_idx);
	sprintf(term2, "m[%d][%d]", w, sig1b_idx);
	sprintf(term3, "m[%d][%d]", w, sig1c_idx);

	if (non_zero_qty == 0){
		return str_p;
	}

	if (*prev_is_set){
		ret = sprintf(str_p, " + ");
		str_p += ret;
	}

	if (non_zero_qty == 1){

		if (m[w][sig1a_idx]==1) ret = sprintf(str_p, "1");
		if (m[w][sig1a_idx]==2) ret = sprintf(str_p, "m[%d][%d]", w, sig1a_idx);
		if (m[w][sig1b_idx]==1) ret = sprintf(str_p, "1");
		if (m[w][sig1b_idx]==2) ret = sprintf(str_p, "m[%d][%d]", w, sig1b_idx);
		if (sig1c==1) ret = sprintf(str_p, "1");
		if (sig1c==2) ret = sprintf(str_p, "m[%d][%d]", w, sig1c_idx);
		*prev_is_set = 1;
		return str_p+ret;
	}


	ret = sprintf(str_p, "(%s%s%s%s%s)",
			m[w][sig1a_idx] ? (m[w][sig1a_idx]==2 ? term1 : "1") : "",
			m[w][sig1a_idx] ? "^":"",
			m[w][sig1b_idx] ? (m[w][sig1b_idx]==2 ? term2 : "1") : "",
			(m[w][sig1b_idx] && sig1c) ? "^":"",
			sig1c ? (sig1c==2 ? term3 : "1") : "");
	*prev_is_set = 1;
	return str_p+ret;

}
char* add_sig0term( char* str_p, uint8_t m[][32], int w, int b, int*prev_is_set)
{
	int sig0a_idx = b+7 < 32 ? b+7 : b+7-32;
	int sig0b_idx = b+18 < 32 ? b+18 : b+18-32;
	int sig0c_idx = b+3;
	int sig0c = sig0c_idx < 32 ? m[w][sig0c_idx] : 0;

	//How many non-zero term, can make that easy
	int non_zero_qty = 0, ret;
	if (m[w][sig0a_idx]) non_zero_qty++;
	if (m[w][sig0b_idx]) non_zero_qty++;
	if (sig0c) non_zero_qty++;

	//Precompile the term string in case the value is 2 (unknown from message)
	char term1[16], term2[16], term3[16];
	sprintf(term1, "m[%d][%d]", w, sig0a_idx);
	sprintf(term2, "m[%d][%d]", w, sig0b_idx);
	sprintf(term3, "m[%d][%d]", w, sig0c_idx);

	if (non_zero_qty == 0){
		return str_p;
	}

	if (*prev_is_set){
		ret = sprintf(str_p, " + ");
		str_p += ret;
	}

	if (non_zero_qty == 1){

		if (m[w][sig0a_idx]==1) ret = sprintf(str_p, "1");
		if (m[w][sig0a_idx]==2) ret = sprintf(str_p, "m[%d][%d]", w, sig0a_idx);
		if (m[w][sig0b_idx]==1) ret = sprintf(str_p, "1");
		if (m[w][sig0b_idx]==2) ret = sprintf(str_p, "m[%d][%d]", w, sig0b_idx);
		if (sig0c==1) ret = sprintf(str_p, "1");
		if (sig0c==2) ret = sprintf(str_p, "m[%d][%d]", w, sig0c_idx);
		*prev_is_set = 1;
		return str_p+ret;
	}


	ret = sprintf(str_p, "(%s%s%s%s%s)",
			m[w][sig0a_idx] ? (m[w][sig0a_idx]==2 ? term1 : "1") : "",
			m[w][sig0a_idx] ? "^":"",
			m[w][sig0b_idx] ? (m[w][sig0b_idx]==2 ? term2 : "1") : "",
			(m[w][sig0b_idx] && sig0c) ? "^":"",
			sig0c ? (sig0c==2 ? term3 : "1") : "");
	*prev_is_set = 1;
	return str_p+ret;

}
