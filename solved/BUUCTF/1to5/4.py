from pwn import *

context.binary = exe = ELF('./4', checksec=False)
#p = remote('node4.buuoj.cn', 28764)

p = remote(exe.path)



p.interactive()