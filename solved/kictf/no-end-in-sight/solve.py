#!/usr/bin/python3

from pwn import *

exe = ELF('no-end-in-sight', checksec=False)

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
        p = remote('no-end-in-sight.kitctf.de', 1337, ssl=True)
else:
        p = process(exe.path)

GDB()
# sl(b"%29$p")
# stack = p.recvline(keepends = False) - 0x371
# payload = b"a"  * 0x108 +

p.interactive()
