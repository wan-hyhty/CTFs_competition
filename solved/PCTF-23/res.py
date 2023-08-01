from itertools import chain, product
from pwn import *


def bruteforce(charset, maxlength):
    return (''.join(candidate)
            for candidate in chain.from_iterable(product(charset, repeat=i)
                                                 for i in range(1, maxlength + 1)))


def main():

    brute = 0x0

    for i in range(40619, 1073741824):
        r = process("./lucid")
        r.sendlineafter(b"Enter the pin:", p32(0x0 + i))
        if r.recvline() == b' Invalid\n':
            log.info("process " + hex(0x0 + i))
            r.close()
        else:
            log.info("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            break
    r.interactive()


if __name__ == '__main__':
    main()
