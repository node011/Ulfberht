# Ulfberht

Shellcode loader

Features :

- Indirect syscall.
- Module stomping.
- Load a stomped module using APC.
- Execute the payload with a direct jump (jmp) without creating a new thread.
- API hashing implemented using the DJB2 algorithm.
- Payload encrypted with RC4 and encoded in UUID format, implemented directly in the loader without loading rpcrt4.dll.
- No CRT is used.

How to use :

```
python3 utils.py C:\Path\To\beacon.bin 
```

Copy the output in payload.h and build the project

NB :

- If your shellcode lacks evasion features (e.g., Cobalt Strike without UDRL), it can be detected by AV/EDR
  
Credit :

- [WriteProcessMemoryAPC](https://www.x86matthew.com/view_post?id=writeprocessmemory_apc)
- [Sektor7](https://institute.sektor7.net/)
- [TartarusGate](https://github.com/trickster0/TartarusGate)
- [ReactOs](https://reactos.org/)
