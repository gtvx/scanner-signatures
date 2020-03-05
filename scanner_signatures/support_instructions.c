#include "support_instructions.h"
#include <cpuid.h>


static unsigned long long _xgetbv(unsigned long index)
{
	unsigned long eax, edx;
	__asm__ __volatile__("xgetbv" : "=a" (eax), "=d" (edx) : "c" (index));
	return ((unsigned long long)edx << 32) | eax;
}



static struct support_instructions t;


__attribute__((constructor))
static void support_instructions_init()
{
	unsigned long __eax, __ebx, __ecx, __edx;

	__cpuid(0x00000000, __eax, __ebx, __ecx, __edx);
	const long nIds = __eax;

	if (nIds >= 0x00000001) {
		__cpuid(0x00000001, __eax, __ebx, __ecx, __edx);
		t.MMX = (__edx & bit_MMX) != 0;
		t.SSE = (__edx & bit_SSE) != 0;
		t.SSE2 = (__edx & bit_SSE2) != 0;
		t.SSE3 = (__ecx & bit_SSE3) != 0;
		t.SSSE3 = (__ecx & bit_SSSE3) != 0;
		t.SSE41 = (__ecx & (1 << 19)) != 0;
		t.SSE42 = (__ecx & (1 << 20)) != 0;
		t.OSXSAVE = (__ecx & bit_OSXSAVE) != 0;
		t.AVX = (__ecx & bit_AVX) != 0;
	}

	if (nIds >= 0x00000007) {
		__cpuid_count(0x00000007, 0, __eax, __ebx, __ecx, __edx);
		t.AVX2 = (__ebx & bit_AVX2) != 0;
	}

	if (!(t.OSXSAVE && t.AVX && (_xgetbv(0) & 0x6) != 0))
		t.AVX = t.AVX2 = 0;
}

const struct support_instructions* get_support_instructions()
{
	return &t;
}
