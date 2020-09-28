#include "signature.h"
#include <string.h>
#include <stdlib.h>

#define _maximum 60000

void signature_init(struct Signature *t)
{
	t->offset = 0;
	t->offset_end = 0;
	t->count = 0;
	t->allocated = 0;
	t->valid = false;
	t->error = false;
	t->list = NULL;
}

void signature_free(struct Signature *t)
{
	if (t->list != NULL) {
		free(t->list);
		t->list = NULL;
		t->count = t->allocated = 0;
	}
}

static Bool signature_highlight_more(struct Signature *t)
{
	if (t->allocated == 0)
	{
		const uint32 size = 20;
		t->list = malloc(sizeof(struct SignatureByte) * size);
		if (t->list == NULL) {
			t->error = true;
			return false;
		}
		t->allocated = size;
	}
	else
	{
		const uint32 new_size = t->allocated * 2;

		if (new_size > _maximum) {
			t->error = true;
			return false;
		}

		struct SignatureByte* list = malloc(sizeof(struct SignatureByte) * new_size);
		if (list == NULL) {
			free(t->list);
			t->list = NULL;
			t->allocated = 0;
			t->error = true;
			return false;
		}
		memcpy(list, t->list, sizeof(struct SignatureByte) * t->count);
		free(t->list);
		t->list = list;
		t->allocated = new_size;
	}
	return true;
}


inline Bool signature_add_byte(struct Signature *t, int32 offset, uint8 byte)
{
	if (offset < 0) {
		t->error = true;
		return false;
	}

	if (t->count >= t->allocated) {
		if (!signature_highlight_more(t))
			return false;
	}

	struct SignatureByte *b = &t->list[t->count++];
	b->offset = offset;
	b->byte = byte;
	return true;
}


Bool signature_add_bytes(struct Signature *t, int32 offset, uint8 *bytes, uint16 size)
{
	for (uint16 i = 0; i < size; i++) {
		if (!signature_add_byte(t, offset++, bytes[i]))
			return false;
	}
	return true;
}


static uint8 getValue(uint8 v)
{
	switch (v) {
		case 0x00:
			return 0;
		case 0xFF:
			return 1;
		case 0xCC:
			return 2;
		case 0x90:
			return 3;
		default:
			return 4;
	}
}

static Bool compare(const struct SignatureByte *byte_a, const struct SignatureByte *byte_b)
{
	const uint8 a = getValue(byte_a->byte);
	const uint8 b = getValue(byte_b->byte);
	if (a == b)
		return byte_a->offset > byte_b->offset;
	return a < b;
}

void signature_end(struct Signature *t)
{
	if (t->count == 0 || t->error == true || t->valid == true)
		return;

	t->valid = true;

	t->offset_end = 0;

	//Sort
	if (t->count >= 2) {
		const uint16 maximum = t->count - 1;
		for (uint16 i = 0; i < maximum; i++) {
			struct SignatureByte *a = &t->list[i];
			struct SignatureByte *b = &t->list[i+1];
			if (compare(a, b)) {
				struct SignatureByte _b = *b;
				t->list[i+1] = *a;
				t->list[i] = _b;
				if (i != 0) {
					i--;
					continue;
				}
			}
		}
	}

	t->offset = t->list[0].offset;
	for (uint16 i = 0; i < t->count; i++) {
		struct SignatureByte *byte = &t->list[i];
		byte->offset -= t->offset;
		if (byte->offset >= t->offset_end)
			t->offset_end = byte->offset;
	}
}








static Bool hex(uint8 c, uint8 *out)
{
	if (c >= 'A' && c <= 'F') {
		*out = c - ('A' - 10);
		return true;
	} else if (c >= 'a' && c <= 'f') {
		*out = c - ('a' - 10);
		return true;
	} else if (c >= '0' && c <= '9') {
		*out = c - '0';
		return true;
	}
	return false;
}


Bool signature_from_string(struct Signature *t, int32 offset, const char *str_signature)
{
	if (offset < 0)
		return false;

	const char *str = str_signature;
	const char *str_maximum = str_signature + strlen(str_signature);
	uint8 b1, b2;

	for (; str < str_maximum; str++)
	{
		switch (*str)
		{
			case '?':
				if (++str == str_maximum || *str != '?')
					return false;
				offset++;
				break;

			case ' ':
				break;

			default:

				if (!hex(*str, &b1) || ++str == str_maximum || !hex(*str, &b2))
					return false;

				if (!signature_add_byte(t, offset, (b1 << 4) | b2))
					return false;

				offset++;
				break;
		}
	}

	return signature_count(t) > 0;
}


Bool signature_from_data_mask(struct Signature *t, int32 offset, const char *data, const char *mask)
{
	if (offset < 0)
		return false;

	for (;;)
	{
		switch (*mask++)
		{
			case '?':
				offset++;
				data++;
				break;

			case 'x':
			case 'X':
				if (!signature_add_byte(t, offset++, (uint8)*data++))
					return false;
				break;

			case '\0':
				return signature_count(t) > 0;

			default:
				return false;
		}
	}
}
