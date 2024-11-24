#pragma once

unsigned long djb2W(wchar_t* str);
unsigned long djb2A(unsigned char* str);

constexpr unsigned long cdjb2W(const wchar_t* str)
{
	unsigned long dwHash = 0x1337;
	wchar_t c = 0;

	while ((c = *str++)) {
		if (c >= L'a' && c <= L'z') {
			c -= (L'a' - L'A');
		}
		dwHash = ((dwHash << 5) + dwHash) + c;
	}
	return dwHash;
}

constexpr unsigned long cdjb2A(const char* str)
{
	unsigned long dwHash = 0x1337;
	unsigned char c = 0;

	while ((c = *str++)) {
		if (c >= 'a' && c <= 'z') {
			c -= ('a' - 'A');
		}
		dwHash = ((dwHash << 5) + dwHash) + c;
	}
	return dwHash;
}

constexpr unsigned long HASH_KERNEL32 = cdjb2W(L"kernel32.dll");
constexpr unsigned long HASH_NTDLL = cdjb2W(L"ntdll.dll");
constexpr unsigned long HASH_CHAKRA = cdjb2W(L"chakra.dll");

constexpr unsigned long HASH_NTPROTECTVIRTUALMEMORY = cdjb2A("NtProtectVirtualMemory");
constexpr unsigned long HASH_NTWAITFORSINGLEOBJECT = cdjb2A("NtWaitForSingleObject");
constexpr unsigned long HASH_NTCREATETHREADEX = cdjb2A("NtCreateThreadEx");
constexpr unsigned long HASH_NTQUEUEUCAPCTHREAD = cdjb2A("NtQueueApcThread");
constexpr unsigned long HAHS_NTRESUMETHREAD = cdjb2A("NtResumeThread");
constexpr unsigned long HASH_NTCLOSE = cdjb2A("NtClose");
constexpr unsigned long HASH_NTTERMINATETHREAD = cdjb2A("NtTerminateThread");

constexpr unsigned long HASH_LOADLIBRARYA = cdjb2A("LoadLibraryExA");
constexpr unsigned long HASH_EXITTHREAD = cdjb2A("RtlExitUserThread");
