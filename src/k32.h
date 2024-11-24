#pragma once

void* xGetModuleHandleA(unsigned long dwModuleHash);
void* xGetProcAddress(void* pModuleAddr, unsigned long dwProcHash);
