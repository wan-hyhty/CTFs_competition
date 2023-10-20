#!/usr/bin/python3

from pwn import *
import ctypes
exe = ELF('challenge', checksec=False)
libc = ctypes.CDLL('/usr/lib/x86_64-linux-gnu/libc.so.6')
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*Elementary_Magic+191

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
        p = remote('34.126.117.161', 2000)
else:
        p = process(exe.path)

p.recvline()
libc.srand(str(p.recvline(keepends=False).decode()))
v2 = libc.rand()
sl('')
v3 = int(time.time()) 
buf = 0xDEADBEEFDEADC0DE ^ v2 ^ v3
print("rand: " + str(v2))
print("time: " + str(v3))
print("buf: " + str(buf))
GDB()
sla(b'sequence!', str(buf))
p.interactive()
