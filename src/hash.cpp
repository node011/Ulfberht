unsigned long djb2A(unsigned char* str)
{
	unsigned long dwHash = 0x1337;
	unsigned char c;

	while (c = *str++)
	{
		if (c >= 'a' && c <= 'z')
			c -= 'a' - 'A';

		dwHash = ((dwHash << 0x5) + dwHash) + c;
	}
	return dwHash;
}

unsigned long djb2W(wchar_t* str)
{
	unsigned long dwHash = 0x1337;
	wchar_t c;
	while (c = *str++)
	{
		if (c >= L'a' && c <= L'z')
			c -= L'a' - L'A';
		dwHash = ((dwHash << 0x5) + dwHash) + c;
	}
	return dwHash;
}

