#include "stdafx.h"
#include <stdint.h>
#include <Windows.h>
#include <winternl.h>
#include <winnt.h>
#include <assert.h>

/*
* this reverse engineers how the dll is loaded and functions are resolved.
*
* Lloyd Macrohon <jl.macrohon@gmail.com>
*/

uint64_t HashDllName(UNICODE_STRING* name)
{
	/* this is the same as HashFunctionName, except this one ensures
	* each character is at least 0x20 ' '. it does not check upper
	* bound though. This is effectively a tolower call.
	*
	* Update: after reverse engineering this function and a little
	* bit of research, I've discovered that this function is the
	* Jenkins' one_at_a_time hash function, but expanded to 64-bits.
	*
	* https://en.wikipedia.org/wiki/Jenkins_hash_function
	*/
	uint64_t hash = 0;
	for (const wchar_t* p = name->Buffer; *p; p++) {
		hash += tolower(*p);
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return hash;
}

uint64_t HashFunctionName(const char* name)
{
	/* this is the same as HashFunctionName, except this one ensures
	* each character is at least 0x20 ' '. it does not check upper
	* bound though.
	*
	* Update: after reverse engineering this function and a little
	* bit of research, I've discovered that this function is the
	* Jenkins' one_at_a_time hash function, but expanded to 64-bits.
	*
	* https://en.wikipedia.org/wiki/Jenkins_hash_function
	*/
	uint64_t hash = 0;
	for (const char* p = name; *p; p++) {
		hash += *p;
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return hash;
}

HMODULE FindModule(uint64_t dllhash)
{
	struct _PEB* peb = NULL;

	__asm {
		mov eax, fs:[30h]
		mov peb, eax;
	}

	// In the code, they actually use InInitializationOrderModuleList but is not defined in our
	// version of winternl.h (it's the next LIST_ENTRY) after InMemoryOrderList.
	struct _LDR_DATA_TABLE_ENTRY* pEntry = NULL;
	struct _LIST_ENTRY* pList = (struct _LIST_ENTRY*)((BYTE*)&peb->Ldr->InMemoryOrderModuleList + sizeof(struct _LIST_ENTRY));
	for (struct _LIST_ENTRY* p = pList->Flink; ; p = p->Flink) {
		if (p == pList)
			return 0;

		// typedef struct _LDR_DATA_TABLE_ENTRY {
		//     PVOID Reserved1[2];
		//     LIST_ENTRY InMemoryOrderLinks;   
		//     PVOID Reserved2[2];				<- we are here
		//     PVOID DllBase;
		//     PVOID Reserved3[2];
		//     UNICODE_STRING FullDllName;
		//     BYTE Reserved4[8];				<- this is BaseDllName

		pEntry = (struct _LDR_DATA_TABLE_ENTRY*)((BYTE*)p - sizeof(struct _LIST_ENTRY) * 2);

		// reserved4 is actually BaseDll (but not defined in our wintrnl.h)
		// > dt _LDR_DATA_TABLE_ENTRY
		// ntdll!_LDR_DATA_TABLE_ENTRY
		//  +0x000 InLoadOrderLinks : _LIST_ENTRY
		//  +0x008 InMemoryOrderLinks : _LIST_ENTRY
		//  +0x010 InInitializationOrderLinks : _LIST_ENTRY
		//  +0x018 DllBase : Ptr32 Void
		//  +0x01c EntryPoint : Ptr32 Void
		//  +0x020 SizeOfImage : Uint4B
		//  +0x024 FullDllName : _UNICODE_STRING
		//  +0x02c BaseDllName : _UNICODE_STRING
		UNICODE_STRING* pBaseDllName = (UNICODE_STRING*)pEntry->Reserved4;
		if (HashDllName(pBaseDllName) == dllhash)
			break;
	}
	return (HMODULE)pEntry->DllBase;
}

void* GetProcAddressByHash(HMODULE hMod, uint64_t funcHash)
{
	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)hMod;
	IMAGE_NT_HEADERS* pNtHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hMod + pDos->e_lfanew);
	IMAGE_EXPORT_DIRECTORY* pExportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)hMod +
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD* nameOffsets = (DWORD*)((BYTE*)hMod + pExportDir->AddressOfNames);
	DWORD* fnOffsets = (DWORD*)((BYTE*)hMod + pExportDir->AddressOfFunctions);
	WORD* nameOrdinals = (WORD*)((BYTE*)hMod + pExportDir->AddressOfNameOrdinals);
	for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
		const char* funcName = (char*)hMod + nameOffsets[i];
		if (HashFunctionName(funcName) == funcHash)
			return (BYTE*)hMod + fnOffsets[nameOrdinals[i]];
	}

	return NULL;
}


int main()
{
	const uint64_t KERNEL32 = 0xD78ACAF904A2CF36;
	const uint64_t LOAD_LIBRARY = 0xDB1A22ECDCBFC8BB;
	HMODULE hKernel32 = FindModule(KERNEL32);

	typedef HMODULE WINAPI LoadLibraryFn(const char* filename);
	LoadLibraryFn* pLoadLibrary = (LoadLibraryFn*)GetProcAddressByHash(hKernel32, LOAD_LIBRARY);
	printf("LoadLibrary @ %p\n", pLoadLibrary);

	if (pLoadLibrary) {
		HMODULE hNtDll = pLoadLibrary("ntdll.dll");
		assert(hNtDll != NULL);
		printf("ntdll base address @ %p\n", hNtDll);
	}

	return 0;
}


