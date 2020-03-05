#ifndef SUPPORT_INSTRUCTIONS_H
#define SUPPORT_INSTRUCTIONS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

struct support_instructions
{
	Bool MMX;

	//SIMD: 128-bit
	Bool SSE;
	Bool SSE2;
	Bool SSE3;
	Bool SSSE3;
	Bool SSE41;
	Bool SSE42;

	//SIMD: 256-bit
	Bool AVX;
	Bool AVX2;
	Bool OSXSAVE;
};

const struct support_instructions* get_support_instructions();

#ifdef __cplusplus
}
#endif

#endif // SUPPORT_INSTRUCTIONS_H
