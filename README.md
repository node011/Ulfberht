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

# Evasion Tips

Compiling this executable and using it directly can be risky, as it may expose potential Indicators of Compromise (IOCs), such as:

- The file was compiled within the last 5 minutes.
- The Import Address Table (IAT) is empty.

Also
  
- If you're using a beacon, avoid using an IP for C2 communication. Instead, use a redirector with a good reputation.
- Add an icon to the executable.
- Sign the executable; ideally, use a trusted signature.
- Add delay and sandbox detection.

# VirusTotal

Payload after compilation

![vanilla](https://raw.githubusercontent.com/NtDallas/Ulfberht/refs/heads/main/img/vanilla.png)

Payload after compilation with icon

![icon](https://raw.githubusercontent.com/NtDallas/Ulfberht/refs/heads/main/img/icon.png)

Payload after compilation with icon and fake sign

![icon](https://raw.githubusercontent.com/NtDallas/Ulfberht/refs/heads/main/img/icon_fake_sign.png)

# Credit 

- [WriteProcessMemoryAPC](https://www.x86matthew.com/view_post?id=writeprocessmemory_apc)
- [Sektor7](https://institute.sektor7.net/)
- [TartarusGate](https://github.com/trickster0/TartarusGate)
- [ReactOs](https://reactos.org/)
