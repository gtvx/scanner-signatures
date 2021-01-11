#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "scanner_signatures.h"
#include "support_instructions.h"


//32 -> 32 OK
//32 -> 64 NO
//64 -> 32 OK
//64 -> 64 OK


static void print_address(ADDRESS address)
{
#ifdef WIN64
	printf("%016IX\n", address);
#else
	printf("%08lX\n", address);
#endif
}


static Bool get_system_bit(enum BIT *bit)
{
	SYSTEM_INFO si;
	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	GetNativeSystemInfo(&si);
	switch (si.wProcessorArchitecture) {
		case PROCESSOR_ARCHITECTURE_AMD64:
			*bit = _64bit;
			return true;
		case PROCESSOR_ARCHITECTURE_INTEL:
			*bit = _32bit;
			return true;
		default:
			return false;
	}
}


static const char* bit_to_string(enum BIT bit)
{
	switch (bit)
	{
		case _32bit:
			return "32bit";
		case _64bit:
			return "64bit";
		default:
			return "";
	}
}





static DWORD find_process(const wchar_t *name)
{
	DWORD PID = 0;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == NULL)
		return PID;

	PROCESSENTRY32W proc;
	proc.dwSize = sizeof(PROCESSENTRY32W);
	if (Process32FirstW(hSnap, &proc)) {
		do {
			if (!wcscmp(proc.szExeFile, name)) {
				PID = proc.th32ProcessID;
				break;
			}
		} while (Process32NextW(hSnap, &proc));
	}

	CloseHandle(hSnap);
	return PID;
}



/////////////////////////////////////////////////////////////////////////////////////////
/// Process

struct Process
{
	HANDLE handle;
	enum BIT bit;
};

static void process_init(struct Process *t)
{
	t->handle = NULL;
}

static void process_free(struct Process *t)
{
	if (t->handle != NULL) {
		CloseHandle(t->handle);
		t->handle = NULL;
	}
}

static Bool process_open(struct Process *t, DWORD PID)
{
	t->handle = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
	return t->handle != NULL;
}

static Bool process_check_activity(const struct Process *t)
{
	DWORD ExitCode;
	if (!GetExitCodeProcess(t->handle, &ExitCode))
		return false;
	return ExitCode == STILL_ACTIVE;
}

static Bool process_init_process_bit(struct Process *t, enum BIT system_bit)
{
	if (system_bit == _32bit) {
		t->bit = _32bit;
		return true;
	}

	BOOL Wow64Process;
	if (!IsWow64Process(t->handle, &Wow64Process))
		return false;

	t->bit = Wow64Process ? _32bit : _64bit;
	return true;
}

/// Process end
/////////////////////////////////////////////////////////////////////////////////////////



__attribute__((unused))
static void print_signature(const struct Signature *signature)
{
	printf("offset byte\n");
	const int32 offset = signature->offset;
	const uint16 count = signature->count;
	for (uint16 i = 0; i < count; i++) {
		const struct SignatureByte *b = signature_get_byte(signature, i);
		if (offset == 0)
			printf("%04ld %02X\n", b->offset, b->byte);
		else
			printf("%04ld %04ld  %02X\n", b->offset, b->offset + offset, b->byte);
	}
	printf("\n");
}



__attribute__((unused))
static void print_support_instructions()
{
	struct support_instructions inst;
	support_instructions_init(&inst);
	printf("HW_MMX %d\n", inst.MMX);
	printf("HW_SSE %d\n", inst.SSE);
	printf("HW_SSE2 %d\n", inst.SSE2);
	printf("HW_SSE3 %d\n", inst.SSE3);
	printf("HW_SSSE3 %d\n", inst.SSSE3);
	printf("HW_SSE41 %d\n", inst.SSE41);
	printf("HW_SSE42 %d\n", inst.SSE42);
	printf("HW_AVX %d\n", inst.AVX);
	printf("HW_AVX2 %d\n", inst.AVX2);
	printf("HW_OSXSAVE %d\n", inst.OSXSAVE);
	fflush(stdout);
}



//////////////////////////////////////////////////////////////////////////////////////////
/// TestTime

__attribute__((unused))
static void TestTime(const struct Process *process)
{
	struct Signature signature;
	signature_init(&signature);

	if (!signature_from_string(&signature, 0, "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF")) {
		printf("error signature_from_string\n");
		signature_free(&signature);
		return;
	}

	signature_end(&signature);

	//print_signature(&signature);

	struct ScannerSignatures *scanner = scanner_signatures_create();
	if (scanner == NULL) {
		signature_free(&signature);
		return;
	}

	if (!scanner_signatures_init(scanner, process->handle, process->bit, &signature, SCANNER_EXECUTE_READ, SCANNER_TYPE_PAGE_ALL)) {
		signature_free(&signature);
		scanner_signatures_free(scanner);
		return;
	}

	for (;;) {

		system("pause");

		SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS);

		uint32 time_start = GetTickCount();

		Bool error;
		ADDRESS found_address;

		while (scanner_signatures_find(scanner, &error, &found_address, NULL))
		{
			print_address(found_address);
		}

		uint32 time_end = GetTickCount();

		printf("ms %ld\n", time_end - time_start);

		SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);

		scanner_signatures_reset(scanner);
	}
}

/// TestTime end
/////////////////////////////////////////////////////////////////////////////////////////





//////////////////////////////////////////////////////////////////////////////////////////
/// AOBScan

static Bool AOBScan(const struct Process *process, const char *str_signature, uint32 protection, uint32 maximum, ADDRESS *array_address, uint32 *out_count)
{
	struct Signature signature;
	signature_init(&signature);

	if (!signature_from_string(&signature, 0, str_signature)) {
		signature_free(&signature);
		return false;
	}
	signature_end(&signature);

	struct ScannerSignatures *scanner = scanner_signatures_create();
	if (scanner == NULL) {
		signature_free(&signature);
		return false;
	}

	if (!scanner_signatures_init(scanner, process->handle, process->bit, &signature, protection, SCANNER_TYPE_PAGE_ALL)) {
		signature_free(&signature);
		scanner_signatures_free(scanner);
		return false;
	}

	uint32 current_index = 0;
	ADDRESS found_address;
	Bool error = false;

	while (current_index != maximum && scanner_signatures_find(scanner, &error, &found_address, NULL))
		array_address[current_index++] = found_address;

	*out_count = current_index;
	signature_free(&signature);
	scanner_signatures_free(scanner);

	return !error;
}

/// AOBScan end
//////////////////////////////////////////////////////////////////////////////////////////




static const wchar_t *process_name = L"Game.exe";



int main()
{
	//print_support_instructions();

	enum BIT system_bit;
	if (!get_system_bit(&system_bit)) {
		printf("error get_system_bit\n");
		return -1;
	}

	const DWORD PID = find_process(process_name);
	if (PID == 0) {
		printf("process not found\n");
		return -1;
	}

	struct Process process;
	process_init(&process);

	if (!process_open(&process, PID)) {
		printf("error OpenProcess\n");
		return -1;
	}

	if (!process_check_activity(&process)) {
		printf("process not active!\n");
		return -1;
	}

	if (!process_init_process_bit(&process, system_bit)) {
		printf("error process.init_process_bit\n");
		return -1;
	}

	printf("PID: %ld %s\n", PID, bit_to_string(process.bit));

#ifndef WIN64
	if (process.bit == _64bit) {
		printf("Will not scan 64bit process!\n");
		return -1;
	}
#endif

	TestTime(&process);


	for (;;)
	{
		ADDRESS array_address[500];
		uint32 count;

		if (AOBScan(&process, "00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF", SCANNER_EXECUTE_READ, 500, array_address, &count)) {

			printf("found %ld\n", count);

			for (uint32 i = 0; i < count; i++) {
				print_address(array_address[i]);
			}
		}

		system("pause");
	}

	process_free(&process);

	return 0;
}
