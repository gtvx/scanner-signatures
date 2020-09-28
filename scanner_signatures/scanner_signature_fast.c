#include "signature.h"

//movaps sse
//pcmpeqb sse2
//pmovmskb sse2
//movdqa sse2
//vmovdqa avx
//vpcmpeqb avx
//vpmovmskb avx


#define __bsf(in, out) \
	__asm__ \
	( \
	".intel_syntax noprefix;" \
	"bsf %0, %1;" \
	".att_syntax noprefix" \
	: "=r" (out) : "r" (in));

#define __movaps_xmm0_ptr(address) \
	__asm__ \
	( \
	".intel_syntax noprefix;" \
	"movaps xmm0,[%0];" \
	".att_syntax noprefix" \
	:: "r" (address));

#define __movdqa_xmm0_ptr(address) \
	__asm__ \
	( \
	".intel_syntax noprefix;" \
	"movdqa xmm0,[%0];" \
	".att_syntax noprefix" \
	:: "r" (address));

#define __vmovdqa_xmm0_ptr(address) \
	__asm__ \
	( \
	".intel_syntax noprefix;" \
	"vmovdqa ymm0,[%0];" \
	".att_syntax noprefix" \
	:: "r" (address));

#define __vmovdqa_ymm0_ptr(address) \
	__asm__ \
	( \
	".intel_syntax noprefix;" \
	"vmovdqa ymm0,[%0];" \
	".att_syntax noprefix" \
	:: "r" (address));

#define __movaps_pcmpeqb_pmovmskb(address, out) \
	__asm__ \
	( \
	".intel_syntax noprefix;" \
	"movaps xmm1, [%1];" \
	"pcmpeqb xmm1, xmm0;" \
	"pmovmskb %0, xmm1;" \
	".att_syntax noprefix" \
	: "=r" (out) : "r" (address));

#define __movdqa_pcmpeqb_pmovmskb(address, out) \
	__asm__ \
	( \
	".intel_syntax noprefix;" \
	"movdqa xmm1, [%1];" \
	"pcmpeqb xmm1, xmm0;" \
	"pmovmskb %0, xmm1;" \
	".att_syntax noprefix" \
	: "=r" (out) : "r" (address));

#define __vmovdqa_vpcmpeqb_vpmovmskb_xmm(address, out) \
	__asm__ \
	( \
	".intel_syntax noprefix;" \
	"vmovdqa xmm1, [%1];" \
	"vpcmpeqb xmm1, xmm1, xmm0;" \
	"vpmovmskb %0, xmm1;" \
	".att_syntax noprefix" \
	: "=r" (out) : "r" (address));

#define __vmovdqa_vpcmpeqb_vpmovmskb_ymm(address, out) \
	__asm__ \
	( \
	".intel_syntax noprefix;" \
	"vmovdqa ymm1, [%1];" \
	"vpcmpeqb ymm1, ymm1, ymm0;" \
	"vpmovmskb %0, ymm1;" \
	".att_syntax noprefix" \
	: "=r" (out) : "r" (address));




ADDRESS scanner_signatures_primitive(ADDRESS current, ADDRESS stop, const void *ymm_first_array, const struct Signature *signature)
{
	(void)ymm_first_array;

	const uint16 count = signature_count(signature);
	const uint8 first_byte = signature_get_byte(signature, 0)->byte;

	while (current < stop)
	{
		if (*(uint8*)current == first_byte)
		{
			for (uint16 i = 1;; i++)
			{
				if (i == count)
					return current;
				const struct SignatureByte *byte = signature_get_byte(signature, i);
				if (((uint8*)current)[byte->offset] != byte->byte)
					break;
			}
		}
		current++;
	}

	return 0;
}



//1 - align address and scanner
//2 - fast scanner
//3 - primitive scanner



ADDRESS scanner_signatures_sse(ADDRESS current, ADDRESS stop, const void *ymm_first_array, const struct Signature *signature)
{
	const uint16 count = signature_count(signature);

	if ((SIGNED_ADDRESS)(stop - current) > 0x50)
	{
		stop -= 0x20;
		__movaps_xmm0_ptr(ymm_first_array);

		// 1

		{
			const uint32 mask = 0xFFFFFFFF << (current & 0xF);
			current &= -0x10;
			uint32 bits;
			__movaps_pcmpeqb_pmovmskb(current, bits);
			bits &= mask;

			if (bits != 0)
			{
				for (;;)
				{
					uint32 first_bit_pos;
					__bsf(bits, first_bit_pos);
					current += first_bit_pos;

					for (uint16 i = 1;; i++) {
						if (i == count)
							return current;
						const struct SignatureByte *byte = signature_get_byte(signature, i);
						if (((uint8*)current)[byte->offset] != byte->byte)
							break;
					}

					first_bit_pos++;
					bits >>= first_bit_pos;

					if (bits == 0) {
						current &= -0x10;
						break;
					}

					current++;
				}
			}
		}

		current += 0x10;

		// 2

		while (current < stop)
		{
			uint32 bits;
			__movaps_pcmpeqb_pmovmskb(current, bits);

			if (bits != 0)
			{
				for (;;)
				{
					uint32 first_bit_pos;
					__bsf(bits, first_bit_pos);
					current += first_bit_pos;

					for (uint16 i = 1;; i++) {
						if (i == count)
							return current;
						const struct SignatureByte *byte = signature_get_byte(signature, i);
						if (((uint8*)current)[byte->offset] != byte->byte)
							break;
					}

					first_bit_pos++;
					bits >>= first_bit_pos;

					if (bits == 0) {
						current &= -0x10;
						break;
					}

					current++;
				}
			}

			current += 0x10;
		}

		stop += 0x20;
	}

	// 3

	const uint8 first_byte = signature_get_byte(signature, 0)->byte;

	while (current < stop)
	{
		if (*(uint8*)current == first_byte)
		{
			for (uint16 i = 1;; i++)
			{
				if (i == count)
					return current;
				const struct SignatureByte *byte = signature_get_byte(signature, i);
				if (((uint8*)current)[byte->offset] != byte->byte)
					break;
			}
		}
		current++;
	}

	return 0;
}



ADDRESS scanner_signatures_sse2(ADDRESS current, ADDRESS stop, const void *ymm_first_array, const struct Signature *signature)
{
	const uint16 count = signature_count(signature);

	if ((SIGNED_ADDRESS)(stop - current) > 0x50)
	{
		stop -= 0x20;
		__movdqa_xmm0_ptr(ymm_first_array);

		// 1

		{
			const uint32 mask = 0xFFFFFFFF << (current & 0xF);
			current &= -0x10;
			uint32 bits;
			__movdqa_pcmpeqb_pmovmskb(current, bits);
			bits &= mask;

			if (bits != 0)
			{
				for (;;)
				{
					uint32 first_bit_pos;
					__bsf(bits, first_bit_pos);
					current += first_bit_pos;

					for (uint16 i = 1;; i++) {
						if (i == count)
							return current;
						const struct SignatureByte *byte = signature_get_byte(signature, i);
						if (((uint8*)current)[byte->offset] != byte->byte)
							break;
					}

					first_bit_pos++;
					bits >>= first_bit_pos;

					if (bits == 0) {
						current &= -0x10;
						break;
					}

					current++;
				}
			}
		}

		current += 0x10;

		// 2

		while (current < stop)
		{
			volatile uint32 bits;
			__movdqa_pcmpeqb_pmovmskb(current, bits);

			if (bits != 0)
			{
				for (;;)
				{
					uint32 first_bit_pos;
					__bsf(bits, first_bit_pos);
					current += first_bit_pos;

					for (uint16 i = 1;; i++) {
						if (i == count)
							return current;
						const struct SignatureByte *byte = signature_get_byte(signature, i);
						if (((uint8*)current)[byte->offset] != byte->byte)
							break;
					}

					first_bit_pos++;
					bits >>= first_bit_pos;

					if (bits == 0) {
						current &= -0x10;
						break;
					}

					current++;
				}
			}

			current += 0x10;
		}

		stop += 0x20;
	}

	// 3

	const uint8 first_byte = signature_get_byte(signature, 0)->byte;

	while (current < stop)
	{
		if (*(uint8*)current == first_byte)
		{
			for (uint16 i = 1;; i++)
			{
				if (i == count)
					return current;
				const struct SignatureByte *byte = signature_get_byte(signature, i);
				if (((uint8*)current)[byte->offset] != byte->byte)
					break;
			}
		}
		current++;
	}


	return 0;
}



ADDRESS scanner_signatures_avx_xmm(ADDRESS current, ADDRESS stop, const void *ymm_first_array, const struct Signature *signature)
{
	const uint16 count = signature_count(signature);

	if ((SIGNED_ADDRESS)(stop - current) > 0x50)
	{
		stop -= 0x20;
		__vmovdqa_xmm0_ptr(ymm_first_array);

		// 1

		{
			const uint32 mask = 0xFFFFFFFF << (current & 0x0F);
			current &= -0x10;
			uint32 bits;
			__vmovdqa_vpcmpeqb_vpmovmskb_xmm(current, bits);
			bits &= mask;

			if (bits != 0)
			{
				for (;;)
				{
					uint32 first_bit_pos;
					__bsf(bits, first_bit_pos);
					current += first_bit_pos;

					for (uint16 i = 1;; i++) {
						if (i == count)
							return current;
						const struct SignatureByte *byte = signature_get_byte(signature, i);
						if (((uint8*)current)[byte->offset] != byte->byte)
							break;
					}

					first_bit_pos++;
					bits >>= first_bit_pos;

					if (bits == 0) {
						current &= -0x10;
						break;
					}

					current++;
				}
			}
		}

		current += 0x10;

		// 2

		while (current < stop)
		{
			uint32 bits;
			__vmovdqa_vpcmpeqb_vpmovmskb_xmm(current, bits);

			if (bits != 0)
			{
				for (;;)
				{
					uint32 first_bit_pos;
					__bsf(bits, first_bit_pos);
					current += first_bit_pos;

					for (uint16 i = 1;; i++) {
						if (i == count)
							return current;
						const struct SignatureByte *byte = signature_get_byte(signature, i);
						if (((uint8*)current)[byte->offset] != byte->byte)
							break;
					}

					first_bit_pos++;
					bits >>= first_bit_pos;

					if (bits == 0) {
						current &= -0x10;
						break;
					}

					current++;
				}
			}

			current += 0x10;
		}

		stop += 0x20;
	}

	// 3

	const uint8 first_byte = signature_get_byte(signature, 0)->byte;

	while (current < stop)
	{
		if (*(uint8*)current == first_byte)
		{
			for (uint16 i = 1;; i++)
			{
				if (i == count)
					return current;
				const struct SignatureByte *byte = signature_get_byte(signature, i);
				if (((uint8*)current)[byte->offset] != byte->byte)
					break;
			}
		}
		current++;
	}

	return 0;
}



ADDRESS scanner_signatures_avx_ymm(ADDRESS current, ADDRESS stop, const void *ymm_first_array, const struct Signature *signature)
{
	const uint16 count = signature_count(signature);

	if ((SIGNED_ADDRESS)(stop - current) > 0x50)
	{
		stop -= 0x40;
		__vmovdqa_ymm0_ptr(ymm_first_array);

		// 1

		{
			const uint32 mask = 0xFFFFFFFF << (current & 0x1F);
			current &= -0x20;
			uint32 bits;
			__vmovdqa_vpcmpeqb_vpmovmskb_ymm(current, bits);
			bits &= mask;

			if (bits != 0)
			{
				for (;;)
				{
					uint32 first_bit_pos;
					__bsf(bits, first_bit_pos);
					current += first_bit_pos;

					for (uint16 i = 1;; i++) {
						if (i == count)
							return current;
						const struct SignatureByte *byte = signature_get_byte(signature, i);
						if (((uint8*)current)[byte->offset] != byte->byte)
							break;
					}

					bits >>= 1;
					bits >>= first_bit_pos;

					if (bits == 0) {
						current &= -0x20;
						break;
					}

					current++;
				}
			}
		}

		current += 0x20;

		// 2

		while (current < stop)
		{
			uint32 bits;
			__vmovdqa_vpcmpeqb_vpmovmskb_ymm(current, bits);

			if (bits != 0)
			{
				for (;;)
				{
					uint32 first_bit_pos;
					__bsf(bits, first_bit_pos);
					current += first_bit_pos;

					for (uint16 i = 1;; i++) {
						if (i == count)
							return current;
						const struct SignatureByte *byte = signature_get_byte(signature, i);
						if (((uint8*)current)[byte->offset] != byte->byte)
							break;
					}

					bits >>= 1;
					bits >>= first_bit_pos;

					if (bits == 0) {
						current &= -0x20;
						break;
					}

					current++;
				}
			}

			current += 0x20;
		}

		stop += 0x40;
	}

	// 3

	const uint8 first_byte = signature_get_byte(signature, 0)->byte;

	while (current < stop)
	{
		if (*(uint8*)current == first_byte)
		{
			for (uint16 i = 1;; i++)
			{
				if (i == count)
					return current;
				const struct SignatureByte *byte = signature_get_byte(signature, i);
				if (((uint8*)current)[byte->offset] != byte->byte)
					break;
			}
		}
		current++;
	}

	return 0;
}
