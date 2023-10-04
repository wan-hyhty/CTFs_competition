#!/usr/bin/python3
from ctypes import CDLL
from pwn import *
libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
exe = ELF('main', checksec=False)


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
    p = remote('198.199.90.158', 37775)
    libc.srand(libc.time(0))
    lim = libc.rand() % 8192
else:
    p = process(exe.path)

GDB()


for i in range(0, lim):
    libc.rand()
for i in range(0, 5):
    a = libc.rand()
    b = libc.rand()
    print(a, b)
    sla(b"= ?\n", f"{a+b}".encode())
p.recvline()
for i in range(0, 5):
    p.recvline()
    b = libc.rand()
    c = libc.rand()
    sl(f"{c-b}".encode())
for i in range(20):
    print(libc.rand())

p.interactive()
