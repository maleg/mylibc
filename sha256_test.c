/*
 * test.c
 *
 *  Created on: 2018-01-28
 *      Author: malego
 */

#include "sha256_test.h"
#include "common.h"



static int check_sha256fast();
static int check_sha256inv();
static int check_sha256_lisible();




SHA256INV_CTX ctxinv;
SHA256_CTX ctx;


static const struct TestCase cases[] = {
	#define TESTCASE(a,b,c,d,e,f,g,h,msg) {{UINT32_C(a),UINT32_C(b),UINT32_C(c),UINT32_C(d),UINT32_C(e),UINT32_C(f),UINT32_C(g),UINT32_C(h)}, msg}
	TESTCASE(0xE3B0C442,0x98FC1C14,0x9AFBF4C8,0x996FB924,0x27AE41E4,0x649B934C,0xA495991B,0x7852B855, ""),
	TESTCASE(0xCA978112,0xCA1BBDCA,0xFAC231B3,0x9A23DC4D,0xA786EFF8,0x147C4E72,0xB9807785,0xAFEE48BB, "a"),
	TESTCASE(0xBA7816BF,0x8F01CFEA,0x414140DE,0x5DAE2223,0xB00361A3,0x96177A9C,0xB410FF61,0xF20015AD, "abc"),
	TESTCASE(0xF7846F55,0xCF23E14E,0xEBEAB5B4,0xE1550CAD,0x5B509E33,0x48FBC4EF,0xA3A1413D,0x393CB650, "message digest"),
	TESTCASE(0x71C480DF,0x93D6AE2F,0x1EFAD144,0x7C66C952,0x5E316218,0xCF51FC8D,0x9ED832F2,0xDAF18B73, "abcdefghijklmnopqrstuvwxyz"),
	TESTCASE(0x248D6A61,0xD20638B8,0xE5C02693,0x0C3E6039,0xA33CE459,0x64FF2167,0xF6ECEDD4,0x19DB06C1, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
	#undef TESTCASE
};




int check_all()
{
	size_t numCases = sizeof(cases) / sizeof(cases[0]);
	for (size_t i = 0; i < numCases; i++) {
		const struct TestCase *tc = &cases[i];
		size_t len = strlen(tc->message);
		uint8_t *msg = calloc(len, sizeof(uint8_t));
		if (msg == NULL) {
			perror("calloc");
			exit(1);
		}
		for (size_t j = 0; j < len; j++)
			msg[j] = (uint8_t)tc->message[j];

		uint32_t hash[STATE_LEN];
		sha256_hash(msg, len, hash);
		if (memcmp(hash, tc->answer, sizeof(tc->answer)) != 0)
			return false;
		free(msg);
	}
	if (check_sha256_lisible() != 0)
	{
		printf("Test sha256_lisible invalid.\n");
		return 1;
	}
	printf("Test sha256_lisible Valid.\n");
	if (check_sha256fast() != 0)
	{
		printf("Test sha256_fast invalid.\n");
		return 1;
	}
	printf("Test sha256_fast Valid.\n");
	if (check_sha256inv() != 0)
	{
		printf("Test sha256_inverse invalid\n\n");
		return 1;
	}
	printf("Test sha256_inverse Valid\n\n");
	return 0;
}

unsigned char* pad_msg(uint8_t* msg, int msg_len){
	static unsigned char padded[64];
	uint64_t bitlen = msg_len*8;

	memset(padded, 0, 64);
	memcpy(padded, msg, msg_len);
	if (msg_len < 56) {
		padded[msg_len] = 0x80;
	}else{
		printf("Message too long\n");
		exit(EXIT_FAILURE);
	}
	padded[63] = bitlen;
	padded[62] = bitlen >> 8;
	padded[61] = bitlen >> 16;
	padded[60] = bitlen >> 24;
	padded[59] = bitlen >> 32;
	padded[58] = bitlen >> 40;
	padded[57] = bitlen >> 48;
	padded[56] = bitlen >> 56;

	return padded;
}


//Return 0 on SUCCESS
static int check_sha256inv(){
	uint32_t test_hash_words[8] = {0xF7846F55,0xCF23E14E,0xEBEAB5B4,0xE1550CAD,0x5B509E33,0x48FBC4EF,0xA3A1413D,0x393CB650};
	uint8_t test_hash_bytes[32];
	memcpy_swap32(test_hash_bytes, test_hash_words, 32);
	char test_msg[] = "message digest";

	SHA256INV_CTX* ctxinv_p = &ctxinv;

	uint32_t m[16] = {0};

	expand_bytes(pad_msg((uint8_t*)test_msg, strlen(test_msg)), m);
	//hexdump_uint32_hn("Last16m : ", m, 16);
	sha256inv_init(ctxinv_p, test_hash_bytes, m, 14);
	sha256inv_transform(ctxinv_p, 0);
	hexdump_bytes_hn("Msg bytes : ", ctxinv_p->data, 64);
	return sha256inv_final(ctxinv_p);

}

//Return 0 on SUCCESS
static int check_sha256_lisible(){
	uint32_t test_hash_words[8] = {0xF7846F55,0xCF23E14E,0xEBEAB5B4,0xE1550CAD,0x5B509E33,0x48FBC4EF,0xA3A1413D,0x393CB650};
	uint8_t test_hash_bytes[32];
	BYTE hash[32] = {0};
	char test_msg[] = "message digest";
	//char test_msg[] = "ssem egaegid\0\0ts";
	memcpy_swap32(test_hash_bytes, test_hash_words, 32);

	SHA256_CTX* ctx_p = &ctx;

	sha256_init(ctx_p);
	sha256_update_from_bytes(ctx_p, (unsigned char*)test_msg, 14, 1);
	sha256_final_bytes(ctx_p, hash, 1);

	if ( memcmp(hash, test_hash_bytes, 32) != 0){
		hexdump_bytes_hn("Calc : ", hash, 32);
		hexdump_bytes_hn("Valid: ", test_hash_bytes, 32);
		return 1;
	}
	return 0;
}

static int check_sha256fast(){
	uint32_t test_hash_words[8] = {0xF7846F55,0xCF23E14E,0xEBEAB5B4,0xE1550CAD,0x5B509E33,0x48FBC4EF,0xA3A1413D,0x393CB650};
	uint8_t test_hash_bytes[32];
	uint32_t hash[8] = {0};
	char test_msg[] = "message digest";
	memcpy_swap32(test_hash_bytes, test_hash_words, 32);

	sha256_hash_message((const uint8_t*)test_msg, strlen(test_msg), hash);
	return memcmp(hash, test_hash_bytes, 32);

}

