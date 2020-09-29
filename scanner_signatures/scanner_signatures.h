#ifndef SCANNER_SIGNATURES_H
#define SCANNER_SIGNATURES_H

#ifdef __cplusplus
extern "C" {
#endif

#include "signature.h"

struct ScannerSignatures;

enum SCANNER_PROTECTION_PAGE
{
	SCANNER_PROTECTION_PAGE_ALL = 0,

	SCANNER_WRITE_OFF = 1,
	SCANNER_WRITE_ON = 2,

	SCANNER_EXECUTABLE_OFF = 4,
	SCANNER_EXECUTABLE_ON = 8,

	SCANNER_WRITECOPY_OFF = 16,
	SCANNER_WRITECOPY_ON = 32,

	SCANNER_READONLY = SCANNER_WRITE_OFF | SCANNER_EXECUTABLE_OFF | SCANNER_WRITECOPY_OFF,
	SCANNER_READWRITE = SCANNER_WRITE_ON | SCANNER_EXECUTABLE_OFF | SCANNER_WRITECOPY_OFF,
	SCANNER_EXECUTE_READ = SCANNER_WRITE_OFF | SCANNER_EXECUTABLE_ON | SCANNER_WRITECOPY_OFF,
	SCANNER_EXECUTE_READWRITE = SCANNER_WRITE_ON | SCANNER_EXECUTABLE_ON | SCANNER_WRITECOPY_OFF,
};

enum SCANNER_TYPE_PAGE
{
	SCANNER_PRIVATE = 0x20000,
	SCANNER_MAPPED = 0x40000,
	SCANNER_IMAGE = 0x1000000,
	SCANNER_PRIVATE_MAPPED  = SCANNER_PRIVATE | SCANNER_MAPPED,
	SCANNER_PRIVATE_IMAGE = SCANNER_PRIVATE | SCANNER_IMAGE,
	SCANNER_MAPPED_IMAGE = SCANNER_MAPPED | SCANNER_IMAGE,
	SCANNER_TYPE_PAGE_ALL = SCANNER_PRIVATE | SCANNER_MAPPED | SCANNER_IMAGE
};


struct ScannerBuffer
{
	uint8 *buffer_begin;
	uint8 *buffer_current;
	_SIZE size;
};

Bool scanner_buffer_check_region(const struct ScannerBuffer *t, uint32 back, uint32 forward);

struct ScannerSignatures* scanner_signatures_create();
void scanner_signatures_free(struct ScannerSignatures *t);
Bool scanner_signatures_init(struct ScannerSignatures *t, HANDLE hProcess, enum BIT bit, const struct Signature *signature, uint32 protection, enum SCANNER_TYPE_PAGE type);
void scanner_signatures_set_start_stop(struct ScannerSignatures *t, ADDRESS start, ADDRESS stop);
void scanner_signatures_reset(struct ScannerSignatures *t);
Bool scanner_signatures_find(struct ScannerSignatures *t, Bool *error, ADDRESS *found_address, struct ScannerBuffer *scanner_buffer);


#ifdef __cplusplus
}
#endif

#endif // SCANNER_SIGNATURES_H
