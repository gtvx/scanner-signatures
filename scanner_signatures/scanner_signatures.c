#include "scanner_signatures.h"
#include "support_instructions.h"
#include <memoryapi.h>
#include <stdlib.h>


ADDRESS scanner_signatures_primitive(ADDRESS, ADDRESS, const void*, const struct Signature*);
ADDRESS scanner_signatures_sse(ADDRESS, ADDRESS, const void*, const struct Signature*);
ADDRESS scanner_signatures_sse2(ADDRESS, ADDRESS, const void*, const struct Signature*);
ADDRESS scanner_signatures_avx_xmm(ADDRESS, ADDRESS, const void*, const struct Signature*);
ADDRESS scanner_signatures_avx_ymm(ADDRESS, ADDRESS, const void*, const struct Signature*);




/////////////////////////////////////////////////////////////////////////////////////////
/// Buffer

struct Buffer
{
	_SIZE size;
	void *data;
};

static Bool buffer_alloc(struct Buffer *t, _SIZE new_size)
{
	t->size = new_size;
	t->data = _aligned_malloc(new_size, 32);
	return t->data != NULL;
}

static void buffer_free(struct Buffer *t)
{
	if (t->data != NULL) {
		_aligned_free(t->data);
		t->data = NULL;
	}
	t->size = 0;
}

static Bool buffer_set_size(struct Buffer *t, _SIZE new_size)
{
	if (new_size > t->size) {
		buffer_free(t);
		return buffer_alloc(t, new_size);
	}
	return true;
}

/// Buffer end
/////////////////////////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////////////////////////
/// CheckFlagsProtection

struct CheckFlagsProtection
{
	Bool write_off, write_on;
	Bool executanle_off, executanle_on;
	Bool writecopy_off, writecopy_on;
};

static void check_flags_protection_init(struct CheckFlagsProtection *t, uint32 flags)
{
	t->write_off = (SCANNER_WRITE_OFF & flags) != 0;
	t->write_on = (SCANNER_WRITE_ON & flags) != 0;
	t->executanle_off = (SCANNER_EXECUTABLE_OFF & flags) != 0;
	t->executanle_on = (SCANNER_EXECUTABLE_ON & flags) != 0;
	t->writecopy_off = (SCANNER_WRITECOPY_OFF & flags) != 0;
	t->writecopy_on = (SCANNER_WRITECOPY_ON & flags) != 0;
}

static Bool check_flags_protection_check(const struct CheckFlagsProtection *t, uint32 flag)
{
	Bool write = false;
	Bool executanle = false;
	Bool writecopy = false;

	switch (flag)
	{
		case PAGE_NOACCESS:
			return false;
		case PAGE_READONLY:
			break;
		case PAGE_READWRITE:
			write = true;
			break;
		case PAGE_WRITECOPY:
			writecopy = true;
			write = true;
			break;
		case PAGE_EXECUTE:
			return false;
		case PAGE_EXECUTE_READ:
			executanle = true;
			break;
		case PAGE_EXECUTE_READWRITE:
			executanle = true;
			write = true;
			break;
		case PAGE_EXECUTE_WRITECOPY:
			write = true;
			executanle = true;
			writecopy = true;
			break;
		default:
			return false;
	};

	if (t->write_off == true && write == true)
		return false;

	if (t->write_on == true && write == false)
		return false;

	if (t->executanle_off == true && executanle == true)
		return false;

	if (t->executanle_on == true && executanle == false)
		return false;

	if (t->writecopy_off == true && writecopy == true)
		return false;

	if (t->writecopy_on == true && writecopy == false)
		return false;

	return true;
}

/// CheckFlagsProtection end
/////////////////////////////////////////////////////////////////////////////////////////


Bool scanner_buffer_check_region(const struct ScannerBuffer *t, uint32 back, uint32 forward)
{
	if ((t->buffer_current - t->buffer_begin) < (int32)back)
		return false;

	if (((t->buffer_begin + t->size) - t->buffer_current) < (int32)forward)
		return false;

	return true;
}


static ADDRESS (*scanner_signatures_ptr) (ADDRESS, ADDRESS, const void*, const struct Signature*);

static void scanner_signatures_ptr_init()
{
	struct support_instructions inst;
	support_instructions_init(&inst);

	if (inst.AVX2) {
		scanner_signatures_ptr = scanner_signatures_avx_ymm;
	} else if (inst.AVX) {
		scanner_signatures_ptr = scanner_signatures_avx_xmm;
	} else if (inst.SSE2) {
		scanner_signatures_ptr = scanner_signatures_sse2;
	} else if (inst.SSE) {
		scanner_signatures_ptr = scanner_signatures_sse;
	} else {
		scanner_signatures_ptr = scanner_signatures_primitive;
	}
}


struct ScannerSignatures
{
	unsigned ymm __attribute__ ((__vector_size__ (32), __may_alias__));
	HANDLE hProcess;
	struct Buffer buffer;
	ADDRESS address_start;
	ADDRESS address_stop;
	const struct Signature *signature;
	struct CheckFlagsProtection checkflags;
	ADDRESS local_address;
	ADDRESS local_address_stop;
	ADDRESS process_base_address;
	ADDRESS process_my_base_address;
	_SIZE process_base_size;
	enum SCANNER_TYPE_PAGE type;
	uint32 protection;
};


struct ScannerSignatures* scanner_signatures_create()
{
	if (scanner_signatures_ptr == NULL)
		scanner_signatures_ptr_init();

	struct ScannerSignatures *t = (struct ScannerSignatures*)_aligned_malloc(sizeof(struct ScannerSignatures), 32);
	if (t == NULL)
		return NULL;
	t->buffer.data = NULL;
	t->buffer.size = 0;
	return t;
}


void scanner_signatures_free(struct ScannerSignatures *t)
{
	buffer_free(&t->buffer);
	_aligned_free(t);
}


Bool scanner_signatures_init(struct ScannerSignatures *t, HANDLE hProcess, enum BIT bit, const struct Signature *signature, uint32 protection, enum SCANNER_TYPE_PAGE type)
{
	if (!signature_is_valid(signature))
		return false;

	if (!buffer_set_size(&t->buffer, 0x1000000))
		return false;

	t->hProcess = hProcess;

	t->protection = protection;
	t->type = type;

	t->signature = signature;

	t->address_start = 0;
	t->process_my_base_address = 0;

#ifdef WIN64
	t->address_stop = (bit == _64bit) ? 0x7FFFFFFFFFFFFFFF : 0x7FFFFFFF;
#else
	(void)bit;
	t->address_stop = 0x7FFFFFFF;
#endif

	t->address_stop++;

	memset(&t->ymm, signature_get_byte(signature, 0)->byte, sizeof(t->ymm));

	check_flags_protection_init(&t->checkflags, protection);

	t->local_address = 0;

	return true;
}


void scanner_signatures_set_start_stop(struct ScannerSignatures *t, ADDRESS start, ADDRESS stop)
{
	t->address_start = start;
	t->address_stop = stop + 1;
	t->process_my_base_address = t->address_start;
	t->local_address = 0;
}


void scanner_signatures_reset(struct ScannerSignatures *t)
{
	t->process_my_base_address = t->address_start;
	t->local_address = 0;
}


Bool scanner_signatures_find(struct ScannerSignatures *t, Bool *error, ADDRESS *found_address, struct ScannerBuffer *scanner_buffer)
{
	*error = false;

	if (t->local_address != 0)
	{
		const ADDRESS local_found = scanner_signatures_ptr(t->local_address, t->local_address_stop, &t->ymm, t->signature);

		if (local_found != 0)
		{
			const ADDRESS local_found_offset = (local_found - t->signature->offset);
			*found_address = t->process_my_base_address + (local_found_offset - (ADDRESS)(t->buffer.data));
			if (scanner_buffer != NULL)
				scanner_buffer->buffer_current = (uint8*)local_found_offset;
			t->local_address = local_found + 1;
			return true;
		}

		t->local_address = 0;
		t->process_my_base_address = t->process_base_address += t->process_base_size;
	}

	for (; t->process_my_base_address < t->address_stop; t->process_my_base_address = t->process_base_address += t->process_base_size)
	{
		MEMORY_BASIC_INFORMATION mbi;
		if (!VirtualQueryEx(t->hProcess, (void*)t->process_my_base_address, &mbi, sizeof(mbi)))
			return false;

		const ADDRESS BaseAddress = (ADDRESS)mbi.BaseAddress;
		const _SIZE RegionSize = (_SIZE)mbi.RegionSize;

		_SIZE process_my_base_size = RegionSize - (t->process_my_base_address - BaseAddress);

		const _SIZE size = t->address_stop - t->process_my_base_address;

		if (size < process_my_base_size)
			process_my_base_size = size;

		if (process_my_base_size == 0)
			return false;

		t->process_base_address = BaseAddress;
		t->process_base_size = RegionSize;

		if ((mbi.Type & t->type) != 0 && check_flags_protection_check(&t->checkflags, mbi.Protect)) {

			if (!buffer_set_size(&t->buffer, process_my_base_size)) {
				*error = true;
				return false;
			}

			SIZE_T NumberOfBytesRead;
			if (!ReadProcessMemory(t->hProcess, (void*)t->process_my_base_address, t->buffer.data, process_my_base_size, &NumberOfBytesRead))
				continue;
			if (NumberOfBytesRead != process_my_base_size)
				continue;

			const int32 offset = t->signature->offset;
			const ADDRESS _buffer = (ADDRESS)t->buffer.data;

			if (scanner_buffer != NULL) {
				scanner_buffer->buffer_begin = t->buffer.data;
				scanner_buffer->size = process_my_base_size;
			}

			t->local_address_stop = (_buffer + process_my_base_size) - t->signature->offset_end;
			t->local_address = _buffer + offset;

			if (t->local_address >= t->local_address_stop)
				continue;

			const ADDRESS local_found = scanner_signatures_ptr(t->local_address, t->local_address_stop, &t->ymm, t->signature);

			if (local_found != 0)
			{
				const ADDRESS local_found_offset = (local_found - offset);
				*found_address = t->process_my_base_address + (local_found_offset - _buffer);
				if (scanner_buffer != NULL)
					scanner_buffer->buffer_current = (uint8*)local_found_offset;
				t->local_address = local_found + 1;
				return true;
			}
		}
	}

	return false;
}
