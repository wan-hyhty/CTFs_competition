#!/usr/bin/python3

from pwn import *

# exe = ELF('./server.py', checksec=False)

# context.binary = exe

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
        p = remote("tamuctf.com", 443, ssl=True, sni="md5")
else:
        p = process(exe.path)

GDB()
sla(b"> ", b"echo lmao")
p.interactive()
