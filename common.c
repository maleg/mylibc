#define _COMMON_C_ 1

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"

int memcmppos(void* inl, void* inr, int len){
	int rem = len;
	while(rem>8){
		if ( *(uint64_t*)inl != *(uint64_t*)inr ){
			break;
		}
		(uint64_t*)inl ++;
		(uint64_t*)inr ++;
		rem -= 8;
	}
	while(rem>4){
		if ( *(uint32_t*)inl != *(uint32_t*)inr ){
			break;
		}
		(uint32_t*)inl ++;
		(uint32_t*)inr ++;
		rem -= 4;
	}
	while(rem>1){
		if ( *(uint8_t*)inl != *(uint8_t*)inr ){
			break;
		}
		(uint8_t*)inl ++;
		(uint8_t*)inr ++;
		rem --;
	}
	return len-rem;
}



//----------------------------------------------------
//----------------------------------------------------
//----------------------------------------------------
// HEXADECIMAL Manipulation functions
//----------------------------------------------------
//----------------------------------------------------
//----------------------------------------------------

void hex2bin(void* dest, const char* src)
{
	uint8_t * dest_p = (uint8_t*)dest;
	int c, pos;
	char buf[3];
	int len = strlen(src);
	pos=0;
	c=0;
	buf[2] = 0;
	while(c < len)
	{
			// read in 2 characaters at a time
			buf[0] = src[c++];
			buf[1] = src[c++];
			// convert them to a interger and recast to a char (uint8)
			dest_p[pos++] = (unsigned char)strtol(buf, NULL, 16);
	}
       
}

 
void bin2hex(char*out_p, unsigned char*in_p, int len)
{
	char * out_pp = out_p;
	for (int i = 0; i < len; i++)
	{
		out_pp += sprintf(out_pp, "%02X", in_p[i]);
	}
}
 
 
 void hex_dump(void *data, size_t len) {
    unsigned char *chr = data;
    for ( size_t pos = 0; pos < len; pos++, chr++ ) { printf("%02X ", *chr & 0xFF); }
}

// this function is mostly useless in a real implementation, were only using it for demonstration purposes
void hexdump(const char* header, const uint8_t* data, int len)
{
    int c;
   
	printf("%s", header);

    c=0;
    while(c < len)
    {
            printf("%.2X", data[c++]);
    }
    printf("\n");
}

void DumpBinBigEndian(void* ptr, int size)
{
    unsigned char *b = (unsigned char*) ptr;
    unsigned char byte;
    int i, j;

    for (i=0;i<size;i++)
    {
        for (j=7;j>=0;j--)
        {
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
    }
    puts("");
}
 
 
 

//----------------------------------------------------
//----------------------------------------------------
//----------------------------------------------------
// Bit Manipulation Functions
//----------------------------------------------------
//----------------------------------------------------
//----------------------------------------------------

void 
msg_set_bit(unsigned char* msg, int offset){
	int byte_offset = offset >> 3;
	int bit_offset = offset & 0x7;
	msg[byte_offset] |= 0x80 >> bit_offset;
	
}

void 
msg_clear_bit(unsigned char* msg, int offset){
	int byte_offset = offset >> 3;
	int bit_offset = offset & 0x7;
	msg[byte_offset] &= ~( 0x80 >> bit_offset);
	
}

static inline void 
incr_256bit(uint64_t* p_data, int qty)
{
	//printf("Increment\n");
	p_data[0] += qty;
	if (p_data[0] == 0)
	{
		p_data[1] += qty;
		if (p_data[1] == 0)
		{
			p_data[2] += qty;
			if (p_data[2] == 0)
			{
				p_data[3] += qty;
				if (p_data[3] == 0)
				{
					printf("Msg wrap around");
					exit(0);
				}
			}
		}		
	}
	
}



int get_entropy8b(unsigned char * msg_p)
{
	int i, consec = 0, max_consec = 0;
	
	for (i=0 ; i<31 ; i++)
	{
		if (*(msg_p+i) == *(msg_p+i+1))
		{
			if (++consec > max_consec)
			{
				max_consec = consec;
			}
			
		}else
		{
			consec = 0;
		}
	}
	return max_consec;
}
int get_entropy16b(unsigned char * msg_p)
{
	int consec = 0, max_consec = 0;
	uint8_t* p8 = msg_p;
	uint8_t* end_p = msg_p+30;
	
	while( p8 < end_p )
	{
		if (*(uint16_t*)p8 == *(uint16_t*)(p8+2))
		{
			if (++consec > max_consec)
			{
				max_consec = consec;
			}
			p8 += 2;
		}else
		{
			consec = 0;
			p8 += 1;
		}
	}
	return max_consec;
}

void* ProcessBits(int startBit, int endBit, int level){
	int idx;
	int hashValid;
	int bit, B, b;
	static int mem[128][3] = {{0,0,0}};

	for (bit=startBit ; bit<=endBit ; bit++){
		B = bit >> 3;
		b = bit & 0x7;
		hashIn[B] ^= 0x80>>b;

		if (level == 1){
			iter++;
			//hexdump(hashIn, SHA256_DIGEST_LENGTH);
				//same as above
			sha256_init(&sha256_pass2);
			sha256_update(&sha256_pass2, hashIn, SHA256_DIGEST_LENGTH);
			sha256_final(&sha256_pass2, hash2);
			   
			hashValid = 1;
			for (idx = 28 ; idx <SHA256_DIGEST_LENGTH ; idx++){
				if (hash2[idx] != 0) {
					hashValid=0 ;
					break;
				}
			}
			
			if (iter%(1UL<<24) == 0)
			//if (iter == 385)
				dumpIter(hashIn);
			if (hashValid){
				printf("Success!!!!\n");
				hexdump(hashIn, SHA256_DIGEST_LENGTH);
				printf("From\n");
				hexdump(hash2, SHA256_DIGEST_LENGTH);
				
			}else{
				//printf(".");
			}
		}else{
			testCombinations(bit+1, endBit+1, hashIn, level-1);
		}
		hashIn[B] ^= 0x80>>b;
	}

}
