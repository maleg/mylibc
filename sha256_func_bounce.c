/*
 * bounce.c
 *
 *  Created on: 2018-01-28
 *      Author: malego
 */

#include "sha256_func_bounce.h"
#include "common.h"
#include "sha256_lisible.h"
#include "sha256_inverse.h"

SHA256INV_CTX ctxinv;
SHA256_CTX ctx;


void bounce()
{
	SHA256INV_CTX* ctxinv_p = &ctxinv;
	SHA256_CTX* ctx_p = &ctx;

	uint32_t test_hash_words[8] = {0xF7846F55,0xCF23E14E,0xEBEAB5B4,0xE1550CAD,0x5B509E33,0x48FBC4EF,0xA3A1413D,0x393CB650};
	uint8_t test_hash_bytes[32];
	memcpy_swap32(test_hash_bytes, test_hash_words, 32);
	char test_msg_string[] = "message digest";

	uint32_t last_m[16];
	uint32_t first_m[16];
	uint32_t hash[8];
	memset(last_m, 0, 64);
	memset(first_m, 0, 64);
	int i, ret, msg_len=14;

	for (uint32_t iter=0 ; iter <1000000 ; iter++)
	{
		sha256_init(ctx_p);
		sha256_update_from_words(ctx_p, first_m, msg_len, 0);
		sha256_final_words(ctx_p, hash, 0);

		for (i=0 ; i<8 ; i++){
			last_m[i] = ctx_p->m[63-i] + test_hash_words[7-i]-hash[7-i];
		}
		//for (i=8 ; i<16 ; i++){
		//	last_m[i] = ctx_p->m[63-i];
		//}
		sha256inv_init(ctxinv_p, test_hash_bytes, last_m, msg_len, 0);
		sha256inv_transform(ctxinv_p, 0);
		ret = sha256inv_final(ctxinv_p, 0);

		//hexdump_uint32_hn("Msg bytes : ", ctxinv_p->m, 16);
		if (ret == 0){
			printf("Successfull!");
			exit(0);
		}
		memcpy(first_m, ctxinv.m, 64);
		// Adjust msg with trailing zeros/length
		/*
		i = msg_len>>2;
		ctxinv.m[i] = (ctxinv.m[4]&0xFFFF0000) | 0x80<<(24-((msg_len%4)*8));
		i++;
		if (ctxinv.datalen < 56) {
			while (i < 14)
				ctxinv.m[i++] = 0x00000000;
		}
		ctxinv.m[15] = msg_len*8;
		for (i=16; i < 64; ++i){
			ctxinv.m[i] = SIG1(ctxinv.m[i - 2]) + ctxinv.m[i - 7] + SIG0(ctxinv.m[i - 15]) + ctxinv.m[i - 16];
		}
		*/
	}
}





void test()
{
	SHA256INV_CTX* ctxinv_p = &ctxinv;
	SHA256_CTX* ctx_p = &ctx;

	uint32_t test_hash_words[8] = {0xF7846F55,0xCF23E14E,0xEBEAB5B4,0xE1550CAD,0x5B509E33,0x48FBC4EF,0xA3A1413D,0x393CB650};
	uint8_t test_hash_bytes[32];
	char test_msg_string[] = "message digest";
	uint8_t hash_bytes1[32] = {0};
	memcpy_swap32(test_hash_bytes, test_hash_words, 32);

	//sha256_hash_message(msg_bytes, strlen(test_msg_string), hash_bytes1);
	sha256_init(ctx_p);
	//sha256_update(ctx_p, msg_bytes, strlen(test_msg_string));
	sha256_update_from_bytes(ctx_p, (unsigned char*)test_msg_string, strlen(test_msg_string), 1);
	sha256_final_bytes(ctx_p, hash_bytes1, 1);
	hexdump_bytes_hn("Result Hash: ", hash_bytes1, 32);
	hexdump_bytes_hn("Valid  Hash: ", test_hash_bytes, 32);

}
