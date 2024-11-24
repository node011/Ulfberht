#include "ntdll.h"
#include "hash.h"

void* xGetModuleHandleA(DWORD dwModuleHash)
{
	PTEB pTeb = (PTEB)__readgsqword(0x30);
	PPEB pPeb = pTeb->ProcessEnvironmentBlock;

	void* firstEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
	PLIST_ENTRY parser = (PLIST_ENTRY)firstEntry;

	do
	{
		PLDR_DATA_TABLE_ENTRY content = (PLDR_DATA_TABLE_ENTRY)parser;

		if (dwModuleHash == 0)
		{
			return content->DllBase;
		}

		if (djb2W(content->BaseDllName.Buffer) == dwModuleHash)
		{
			return content->DllBase;
		}

		parser = parser->Flink;
	} while (parser->Flink != firstEntry);

	return nullptr;
}

void* xGetProcAddress(void* pModuleAddr, DWORD dwProcHash)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleAddr;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(reinterpret_cast<UINT_PTR>(pModuleAddr) + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_EXPORT_DIRECTORY pImgExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(reinterpret_cast<UINT_PTR>(pModuleAddr) + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleAddr + pImgExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleAddr + pImgExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleAddr + pImgExportDirectory->AddressOfNameOrdinals);

	for (int i = 0; i < pImgExportDirectory->NumberOfFunctions; i++)
	{
		PBYTE pczFunctionName = (PBYTE)((PBYTE)pModuleAddr + pdwAddressOfNames[i]);
		if (djb2A(pczFunctionName) == dwProcHash)
		{
			return (PBYTE)pModuleAddr + pdwAddressOfFunctions[pwAddressOfNameOrdinales[i]];
		}
	}

	return nullptr;
}