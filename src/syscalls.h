#pragma once

#include "ntdll.h"


#define		UP		32
#define		DOWN	32

#define HGATESP(x)	HellsGate(funcList->x.ssn, funcList->x.syscallAddr)
#define HGATES(x)	HellsGate(funcList.x.ssn, funcList.x.syscallAddr)

typedef struct _SYSCALL {
	void* syscallAddr;
	short ssn;
} SYSCALL, * PSYSCALL;

typedef struct _FUNCTION_LIST {
	SYSCALL NtProtectVirtualMemory;
	SYSCALL NtWaitForSingleObject;
	SYSCALL NtCreateThreadEx;
	SYSCALL NtQueueApcThread;
	SYSCALL NtResumeThread;
	SYSCALL NtTerminateThread;
	SYSCALL NtClose;
	SYSCALL NtGetContextThread;
	SYSCALL NtSetContextThread;

} FUNCTION_LIST, * PFUNCTION_LIST;

extern "C" void			HellsGate(short ssn, void* jmpAddr);
extern "C" NTSTATUS		HellDescent(...);

bool InitSyscallList(PFUNCTION_LIST funcList);