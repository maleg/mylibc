#define _COMMON_C_ 1

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> // For write
#include <stdint.h>

//#include "common.h"

int memcmppos(void* inl, void* inr, int len)
{
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

void memcpy_swap32(void* dest, void* src, int len)
{
	uint32_t* dest_p = dest;
	uint32_t* src_p = src;
	int i;

	for (i=0 ; i<(len>>2) ; i++)
	{
		dest_p[i] = htobe32(src_p[i]);
	}

}

void bytes_to_file(int file, char* str, int len)
{
	int ret = write(file, str,len);
	if (ret != len)
	{
		printf("write_to_disk : Didn't write all the bytes.");
		exit(EXIT_FAILURE);
	}
}

void str_to_file(int file, char* str)
{
	int write_length = strlen(str);
	int ret = write(file, str, write_length);
	if (ret != write_length)
	{
		printf("write_to_disk : Didn't write all the bytes.");
		exit(EXIT_FAILURE);
	}
}

void strline_to_file(int file, char* str)
{
	str_to_file(file, str);
	str_to_file(file, "\n");
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
 
 
 void hex_dump(void *data, size_t len)
{
    unsigned char *chr = data;
    for ( size_t pos = 0; pos < len; pos++, chr++ ) { printf("%02X ", *chr & 0xFF); }
}

// this function is mostly useless in a real implementation, were only using it for demonstration purposes
void hexdump_bytes_hn(const char* header, void* data_p, int len)
{
    int c;
    unsigned char * data = data_p;

	printf("%s", header);
    c=0;
    while(c < len)
    {
            printf("%.2X", data[c++]);
    }
    printf("\n");
}

void hexdump_uint32_hn(const char* header, uint32_t* data, int len)
{
    int c;

	printf("%s", header);
    c=0;
    while(c < len)
    {
            printf("%.8X", data[c++]);
    }
    printf("\n");
}

 
 

//----------------------------------------------------
//----------------------------------------------------
//----------------------------------------------------
// Bit Manipulation Functions
//----------------------------------------------------
//----------------------------------------------------
//----------------------------------------------------

void 
msg_set_bit(unsigned char* msg, uint32_t offset){
	uint32_t byte_offset = offset >> 3;
	uint32_t bit_offset = offset & 0x7;
	msg[byte_offset] |= 0x80 >> bit_offset;
	
}

void 
msg_clear_bit(unsigned char* msg, uint32_t offset){
	uint32_t byte_offset = offset >> 3;
	uint32_t bit_offset = offset & 0x7;
	msg[byte_offset] &= ~( 0x80 >> bit_offset);
	
}

void
msg_flip_bit(unsigned char* msg, uint32_t offset){
	uint32_t byte_offset = offset >> 3;
	uint32_t bit_offset = offset & 0x7;
	msg[byte_offset] ^= (0x80 >> bit_offset);

}


int
msg_get_bit(unsigned char* msg, uint32_t bit_offset){
	uint32_t B = bit_offset >> 3;
	uint32_t b = bit_offset & 0x07;
	int ret = (msg[B] >> (7-b)) & 0x1;
	return ret;
}

// Return string length in bytes
int
sprintf_bits(char * dest, void const * const src, int const size)
{
	unsigned char *in_p = (unsigned char*) src;
	char *out_p = dest;
	unsigned char byte;
	int i, j, ret, len;

	for (i=0;i<size;i++)
	{
		for (j=7;j>=0;j--)
		{
			byte = (in_p[i] >> j) & 1;
			ret = sprintf(out_p, (byte == 1) ? "1 ":"-1 ");
			out_p += ret;
		}
	}
	len = out_p - dest;
	dest[len-1] = '\n';
	return len;
}

// Return string length in bytes
char*
str_bits(void const * const src, int const bytesize)
{

	static char buf[4096];
	unsigned char *in_p = (unsigned char*) src;
	char *out_p = buf;
	unsigned char byte;
	int i, j, ret, len;

	for (i=0;i<bytesize;i++)
	{
		for (j=7;j>=0;j--)
		{
			byte = (in_p[i] >> j) & 1;
			ret = sprintf(out_p, (byte == 1) ? "1 ":"0 ");
			out_p += ret;
		}
	}
	len = out_p - buf;
	buf[len-1] = '\0';
	return (char*)buf;
}

void
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

void ProcessBits(unsigned char hashIn[], int startBit, int endBit, int level)
{
	int bit, B, b, iter;

	for (bit=startBit ; bit<=endBit ; bit++){
		msg_flip_bit(hashIn, bit);

		if (level == 1)
		{
			iter++;
			printf(".");

		}
		else
		{
			ProcessBits(hashIn, bit+1, endBit+1, level-1);
		}
		msg_flip_bit(hashIn, bit);
	}

}

void ScanBits(unsigned char hashIn[], int level)
{
	static int states[8][3] = {{7,7,255},{6,6,254},{5,5,253},{4,4,252},{3,3,251},{2,2,250},{1,1,249},{0,0,248}};
	int bit, B, b, iter;

	msg_flip_bit(hashIn, states[level][1]);

	if (level == 0)
	{
		return;
	}
	else
	{
		ScanBits(hashIn, level-1);
	}

}
