#!/usr/bin/python3

from pwn import *

exe = ELF("chal", checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(
            p,
            gdbscript="""


                c
                """,
        )
        input()


info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
    p = remote("")
else:
    # p = process("qemu-arm -g 1234 ./chal".split())
    p = process("qemu-arm ./chal".split())

str = ""
# GDB()
for i in range(0, 255):
    p.sendlineafter(b"512 chars", p8(i) + p8(i + 1) + p8(i + 2) + p8(i + 3))
    check = p.recvline().decode()
    if check == "*** Bad hex (invalid char) ***":
        str += chr(i)
p.interactive()
