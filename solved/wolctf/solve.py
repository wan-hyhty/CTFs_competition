from pwn import *

r = process("./challenge")

for i in range(0, 4):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"name: ", f"{i}".encode())
    r.sendlineafter(b"feed them: ", f"{i}".encode())

r.interactive()
