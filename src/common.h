#ifndef _COMMON_H_
#define _COMMON_H_

#include "stdint.h"

#ifndef _COMMON_C_


	int memcmppos(void* inl, void* inr, int len);

	//----------------------------------------------------
	// HEXADECIMAL Manipulation functions
	//----------------------------------------------------
	void hex2bin(void* dest, const char* src);
	void bin2hex(char*out_p, unsigned char*in_p, int len);
	void hexdump(const char* header, const uint8_t* data, int len);
	void DumpBinBigEndian(void* ptr, int size);
	
	//----------------------------------------------------
	// Bit Manipulation Functions
	//----------------------------------------------------
	void msg_set_bit(unsigned char* msg, int offset);
	void msg_clear_bit(unsigned char* msg, int offset);
	uint64_t Get_mask_left_64bit(int mask_len, int mask_offset);
	uint64_t Get_mask_right_64bit(int mask_len, int mask_offset);
	
	static inline void 
	incr_256bit(uint64_t* p_data, int qty);
	void* ProcessBits(int startBit, int endBit, int level);

#endif

#endif
