#include "support_instructions.h"
#include <cpuid.h>
#include <string.h>


static unsigned long long _xgetbv(unsigned long index)
{
	unsigned long eax, edx;
	__asm__ __volatile__("xgetbv" : "=a" (eax), "=d" (edx) : "c" (index));
	return ((unsigned long long)edx << 32) | eax;
}


void support_instructions_init(struct support_instructions *s)
{
	memset(s, 0, sizeof(struct support_instructions));

	unsigned long __eax, __ebx, __ecx, __edx;

	__cpuid(0x00000000, __eax, __ebx, __ecx, __edx);
	const long nIds = __eax;

	if (nIds >= 0x00000001) {
			__cpuid(0x00000001, __eax, __ebx, __ecx, __edx);
			s->MMX = (__edx & bit_MMX) != 0;
			s->SSE = (__edx & bit_SSE) != 0;
			s->SSE2 = (__edx & bit_SSE2) != 0;
			s->SSE3 = (__ecx & bit_SSE3) != 0;
			s->SSSE3 = (__ecx & bit_SSSE3) != 0;
			s->SSE41 = (__ecx & (1 << 19)) != 0;
			s->SSE42 = (__ecx & (1 << 20)) != 0;
			s->OSXSAVE = (__ecx & bit_OSXSAVE) != 0;
			s->AVX = (__ecx & bit_AVX) != 0;
	}

	if (nIds >= 0x00000007) {
			__cpuid_count(0x00000007, 0, __eax, __ebx, __ecx, __edx);
			s->AVX2 = (__ebx & bit_AVX2) != 0;
	}

	if (!(s->OSXSAVE && s->AVX && (_xgetbv(0) & 0x6) != 0))
			s->AVX = s->AVX2 = 0;
}
