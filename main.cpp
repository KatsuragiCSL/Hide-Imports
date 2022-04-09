#include <Windows.h>
#include <string.h>
#include "PE.h"

HMODULE WINAPI _GetModuleHandle(LPCTSTR lpModuleName) {
#ifdef _M_IX86
	PEB* Peb = (PEB*)__readfsdword(0x30);
#endif
#ifdef _M_AMD64
	PEB * Peb = (PEB*)__readgsqword(0x60);
#endif
	//null means addr of process itself
	if (lpModuleName == NULL) {
		return (HMODULE)(Peb->ImageBaseAddress);
	}
	PEB_LDR_DATA * Ldr = Peb->Ldr;
	LIST_ENTRY * ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY * FirstEntry = ModuleList->Flink;
	for (LIST_ENTRY* ThisEntry = FirstEntry; ThisEntry != ModuleList; ThisEntry = ThisEntry->Flink) {
		LDR_DATA_TABLE_ENTRY* Entry = (LDR_DATA_TABLE_ENTRY*)ThisEntry;
		if (wcscmp((const wchar_t*)Entry->BaseDllName.Buffer, (const wchar_t*)lpModuleName) == 0) {
			return (HMODULE)Entry->DllBase;
		}
	}
	return NULL;
}

FARPROC WINAPI _GetProcAddress(HMODULE hModule, LPCSTR  lpProcName) {
	void* ProcAddr = NULL;

	char* BaseAddr = (char*)hModule;
	IMAGE_DOS_HEADER * DOSHeader = (IMAGE_DOS_HEADER *)BaseAddr;

	//check x86 or x64
#ifdef _M_IX86
	IMAGE_NT_HEADERS32 * NtHeader = (IMAGE_NT_HEADERS32 *)(BaseAddr + DOSHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER32 * OptHeader = &NtHeader->OptionalHeader;
#endif
#ifdef _M_AMD64
	IMAGE_NT_HEADERS64 * NtHeader = (IMAGE_NT_HEADERS64 *)(BaseAddr + DOSHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER64* OptHeader = &NtHeader->OptionalHeader;
#endif
	//get the export directory
	IMAGE_DATA_DIRECTORY* ExportDataDir = (IMAGE_DATA_DIRECTORY*)(&OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* ExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(BaseAddr + ExportDataDir->VirtualAddress);

	//get the addresses of functions, their names and ordinals
	DWORD* FuncAddr = (DWORD*)(BaseAddr + ExportDirectory->AddressOfFunctions);
	DWORD* NameAddr = (DWORD*)(BaseAddr + ExportDirectory->AddressOfNames);
	DWORD* OrdAddr = (DWORD*)(BaseAddr + ExportDirectory->AddressOfNameOrdinals);

	//get function address by name
	for (DWORD i = 0; i < ExportDirectory->NumberOfNames; i++) {
		LPCSTR thisName = (LPCSTR)(BaseAddr + NameAddr[i]);
		char * thisNameChar = (char *)thisName;
		if (strcmp(thisNameChar, (char*)lpProcName) == 0) {
			ProcAddr = (FARPROC)(BaseAddr + FuncAddr[OrdAddr[i]]);
			break;
		}
	}
	return (FARPROC) ProcAddr;
}
