#ifndef SIGNATURE_H
#define SIGNATURE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

struct SignatureByte
{
	int32 offset;
	uint8 byte;
};

struct Signature
{
	struct SignatureByte *list;
	int32 offset;
	int32 offset_end;
	uint32 allocated;
	uint16 count;
	Bool valid;
	Bool error;
};

void signature_init(struct Signature *t);
void signature_free(struct Signature *t);

Bool signature_add_byte(struct Signature *t, int32 offset, uint8 byte);
Bool signature_add_bytes(struct Signature *t, int32 offset, uint8 *bytes, uint16 size);

static inline uint16 signature_count(const struct Signature *t) { return t->count; }
static inline const struct SignatureByte* signature_get_byte(const struct Signature *t, uint16 index) { return &t->list[index]; }

void signature_end(struct Signature *t);
static inline Bool signature_is_valid(const struct Signature *t) { return t->valid; }

//signature_from_string(t, 0, "11 ?? 33 ?? 55");
Bool signature_from_string(struct Signature *t, int32 offset, const char *str_signature);

//signature_from_data_mask(t, 0, "\x11\x00\x33\x00\x55", "x?x?x");
Bool signature_from_data_mask(struct Signature *t, int32 offset, const char *data, const char *mask);

#ifdef __cplusplus
}
#endif

#endif // SIGNATURE_H
