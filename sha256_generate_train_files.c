/*
 * sha256_generate_train_files.c
 *
 *  Created on: 2018-01-29
 *      Author: malego
 */

#include "sha256_generate_train_files.h"
#include "sha256.h"


void generate_train_file()
{
	int i, j, msg_len = 16;
	SHA256INV_CTX ctxinv;
	SHA256_CTX ctx;
	SHA256INV_CTX* ctxinv_p = &ctxinv;
	SHA256_CTX* ctx_p = &ctx;
	uint8_t msg[33] = {0};
	uint8_t hash[32] = {0};
	uint32_t m[16] = {0};
	char header[64];

	int fout = open_outfile("sha256_train.txt");
	//Save Header
	sprintf(header, "%d %d %d\n", msg_len*8*msg_len*8, 256, 32);
	str_to_file(fout, header);

	uint8_t* msg_pad = pad_msg(msg, msg_len);
	for(i=0 ; i<msg_len*8 ; i++){
		for(j=0 ; j<msg_len*8 ; j++){
			memset(msg, 0, msg_len);
			msg_set_bit(msg_pad, i);
			msg_set_bit(msg_pad, j);
			//hexdump("mesg2 : ", msg, 64);printf("\n");

			sha256_init(ctx_p);
			sha256_update_from_bytes(ctx_p, msg_pad, msg_len, 0);
			sha256_final_bytes(ctx_p, hash, 0);

			expand_bytes(msg_pad, m);
			//hexdump_uint32_hn("Last16m : ", m, msg_len);
			sha256inv_init(ctxinv_p, hash, m, 32, 0);
			sha256inv_transform(ctxinv_p, 0);
			if ( sha256inv_final(ctxinv_p, 0) != 0){
				printf("Got an invalid reverse sha256\n");
				exit(EXIT_FAILURE);
			}

			//Save Input
			str_to_file(fout, str_bits(&ctxinv_p->a[63], 4));
			str_to_file(fout, " ");
			str_to_file(fout, str_bits(&ctxinv_p->b[63], 4));
			str_to_file(fout, " ");
			str_to_file(fout, str_bits(&ctxinv_p->c[63], 4));
			str_to_file(fout, " ");
			str_to_file(fout, str_bits(&ctxinv_p->d[63], 4));
			str_to_file(fout, " ");
			str_to_file(fout, str_bits(&ctxinv_p->e[63], 4));
			str_to_file(fout, " ");
			str_to_file(fout, str_bits(&ctxinv_p->f[63], 4));
			str_to_file(fout, " ");
			str_to_file(fout, str_bits(&ctxinv_p->g[63], 4));
			str_to_file(fout, " ");
			strline_to_file(fout, str_bits(&ctxinv_p->t2[64], 4));

			//Save Output
			strline_to_file(fout, str_bits(&ctxinv_p->m[63], 4));
		}
	}
	close(fout);
	printf("Done.\n");
}
